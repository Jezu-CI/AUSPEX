"""Effacement d'actifs sur demande : `auspex oublier IP…` (RGPD, droit à l'effacement).

Retire une ou plusieurs adresses IP de l'état d'Auspex : fiche de l'actif
(identification, adresses MAC, noms), flux dont l'adresse est la source ou la
destination, alertes et écarts qui la citent, alertes en attente d'envoi au
SIEM, et vues recalculées (rapport d'analyse, rapprochement NetBox, tableau
de bord, carte).

Ne sont pas modifiés, par conception :
- les **exports d'audit signés** : preuves scellées, conservées selon la
  politique de l'organisation (`audit.keep`) ;
- les **sauvegardes** déjà produites ;
- les **logs Zeek reçus** des capteurs, purgés automatiquement au-delà de
  AUSPEX_LOGS_RETENTION_DAYS (30 jours par défaut) ;
- **NetBox** : le compte de service d'Auspex n'a aucun droit de suppression ;
  la commande indique l'adresse à supprimer avec un compte administrateur ;
- les **alertes déjà livrées** (SIEM, webhook, fichier de sortie) : elles
  appartiennent à l'outil qui les a reçues.

Un équipement encore actif sur le réseau réapparaît au cycle suivant : l'effacement
vaut pour un équipement retiré, ou pour corriger une donnée.
"""
from __future__ import annotations

import fcntl
import ipaddress
import json
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .state import _atomic_write, _read

# Vues recalculées à chaque cycle : les éléments qui citent l'adresse en sont
# retirés tout de suite, sans attendre le cycle suivant.
VUES = ("report.json", "netbox_report.json", "tableau/dashboard.json", "tableau/carte.json")


class OubliError(Exception):
    pass


@contextmanager
def verrou_etat(state_dir: Path, attente: float = 600.0):
    """Verrou exclusif du répertoire d'état, partagé par le cycle du service et
    les commandes qui modifient l'état (sinon un cycle en cours réécrirait ce
    qui vient d'être effacé)."""
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    with open(state_dir / ".verrou", "a+") as fh:
        debut = time.monotonic()
        while True:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() - debut > attente:
                    raise OubliError("état occupé : un cycle d'analyse ne se termine pas") from None
                time.sleep(0.5)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def adresses(valeurs: list[str]) -> set[str]:
    out = set()
    for v in valeurs:
        try:
            out.add(str(ipaddress.ip_address(v.strip())))
        except ValueError:
            raise OubliError(f"adresse IP invalide : {v!r}") from None
    return out


# Adresses écrites dans un texte : « 10.0.0.5 », « 10.0.0.5/24 », « 10.0.0.5:502 »,
# « fd00::7 ». Chaque candidat est relu par ipaddress (une heure ou une adresse
# MAC n'est pas une adresse IP) et comparé sous sa forme canonique.
_IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9]|\.[0-9])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")


def _canonique(valeur: str) -> str | None:
    try:
        return str(ipaddress.ip_address(valeur))
    except ValueError:
        return None


def _cite(valeur, ips: set[str]) -> bool:
    """Valeur scalaire qui désigne l'une des adresses, seule (« 10.0.0.5 »,
    « 10.0.0.5/24 ») ou dans un texte (message d'alerte qui cite plusieurs
    adresses d'un même équipement)."""
    if not isinstance(valeur, str):
        return False
    if _canonique(valeur.split("/")[0]) in ips:
        return True
    return any(_canonique(m) in ips for motif in (_IPV4, _IPV6) for m in motif.findall(valeur))


def _cite_directement(d: dict, ips: set[str]) -> bool:
    """Enregistrement dont un champ désigne l'adresse (src, dst, ip, address…)."""
    return any(_cite(v, ips) for v in d.values())


def _cite_quelque_part(obj, ips: set[str]) -> bool:
    """L'adresse apparaît n'importe où dans l'objet (événement d'alerte complet)."""
    if isinstance(obj, dict):
        return any(_cite(k, ips) or _cite_quelque_part(v, ips) for k, v in obj.items())
    if isinstance(obj, list):
        return any(_cite_quelque_part(v, ips) for v in obj)
    return _cite(obj, ips)


def _filtrer(obj, ips: set[str]) -> tuple[object, int]:
    """Retire d'un document JSON les enregistrements qui citent directement
    l'une des adresses, et les clés égales à l'une d'elles ; renvoie le
    document et le nombre d'éléments retirés."""
    retires = 0
    if isinstance(obj, list):
        out = []
        for e in obj:
            if isinstance(e, dict) and _cite_directement(e, ips):
                retires += 1
                continue
            if _cite(e, ips):
                retires += 1
                continue
            e, n = _filtrer(e, ips)
            retires += n
            out.append(e)
        return out, retires
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if _cite(k, ips) or (isinstance(v, dict) and _cite_directement(v, ips)):
                retires += 1
                continue
            v, n = _filtrer(v, ips)
            retires += n
            out[k] = v
        return out, retires
    return obj, 0


@dataclass
class Bilan:
    actifs: int = 0
    flux: int = 0
    alertes: int = 0
    envois: int = 0
    vues: dict[str, int] = field(default_factory=dict)
    netbox: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.actifs + self.flux + self.alertes + self.envois + sum(self.vues.values())


def oublier(state_dir: Path, ips: set[str], appliquer: bool) -> Bilan:
    """Calcule (et, si `appliquer`, écrit) l'effacement des adresses `ips`."""
    state_dir = Path(state_dir)
    ips = {_canonique(i) or i for i in ips}
    bilan = Bilan()
    ecritures: list[tuple[Path, object]] = []

    p = state_dir / "assets.json"
    actifs = _read(p, [])
    garder = [a for a in actifs if not _cite(a.get("ip"), ips)]
    bilan.actifs = len(actifs) - len(garder)
    if bilan.actifs:
        ecritures.append((p, garder))

    p = state_dir / "flows.json"
    flux = _read(p, [])
    garder = [f for f in flux if not (_cite(f.get("src"), ips) or _cite(f.get("dst"), ips))]
    bilan.flux = len(flux) - len(garder)
    if bilan.flux:
        ecritures.append((p, garder))

    p = state_dir / "alerts.json"
    alertes = _read(p, {})
    garder = {k: a for k, a in alertes.items()
              if not _cite_directement(a.get("finding") or {}, ips)}
    bilan.alertes = len(alertes) - len(garder)
    if bilan.alertes:
        ecritures.append((p, garder))

    # Alertes en attente d'envoi au SIEM (une par ligne).
    for f in sorted((state_dir / "outbox").glob("*.jsonl")):
        lignes = f.read_text(encoding="utf-8").splitlines()
        garder = []
        for ligne in lignes:
            try:
                evt = json.loads(ligne)
            except ValueError:
                garder.append(ligne)
                continue
            if _cite_quelque_part(evt, ips):   # un événement porte sur un seul écart
                continue
            garder.append(ligne)
        if len(garder) != len(lignes):
            bilan.envois += len(lignes) - len(garder)
            ecritures.append((f, "\n".join(garder) + ("\n" if garder else "")))

    for nom in VUES:
        p = state_dir / nom
        if not p.exists():
            continue
        doc, n = _filtrer(_read(p, None), ips)
        if n:
            bilan.vues[nom] = n
            ecritures.append((p, doc))

    bilan.netbox = sorted(ips)
    if appliquer:
        for chemin, contenu in ecritures:
            if isinstance(contenu, str):
                tmp = chemin.with_suffix(chemin.suffix + ".tmp")
                tmp.write_text(contenu, encoding="utf-8")
                tmp.replace(chemin)
            else:
                _atomic_write(chemin, contenu)
    return bilan
