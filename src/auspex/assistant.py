"""Assistant de première configuration : `auspex init`.

Pose quelques questions (organisation, zones et plages d'adresses, SIEM,
référentiels d'audit) et produit `auspex.yaml` à partir du modèle livré, en
gardant ses commentaires. Appelé par `deploy/install.sh` à la première
installation ; utilisable seul :

    auspex init --modele deploy/auspex.yaml.template > config/auspex.yaml
    auspex init --modele … --reponses reponses.json   # sans questions (automatisation)

Les questions et messages vont sur la sortie d'erreur, la configuration sur la
sortie standard : l'installateur la récupère sans les questions. Le résultat est
validé comme n'importe quelle configuration avant d'être rendu.
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

from .config import AUDIT_FRAMEWORKS, ConfigError, parse_config

# Types de zone proposés, dans l'ordre du menu : (classe, libellé, nom suggéré).
TYPES = [
    ("tier0", "Tier 0 : annuaire (contrôleurs de domaine, PKI)", "T0-AD"),
    ("tier1", "Tier 1 : serveurs", "T1-serveurs"),
    ("tier2", "Tier 2 : postes de travail", "T2-postes"),
    ("admin", "Administration : bastions, postes d'administration", "ADMIN"),
    ("dmz", "DMZ informatique (services exposés)", "DMZ"),
    ("purdue4", "Réseau d'entreprise vu depuis l'industriel (Purdue 4)", "ENTREPRISE"),
    ("purdue3.5", "DMZ industrielle (Purdue 3.5)", "OT-DMZ"),
    ("purdue3", "Supervision industrielle : historiens, MES (Purdue 3)", "OT-N3"),
    ("purdue2", "Conduite : IHM, SCADA (Purdue 2)", "OT-N2"),
    ("purdue1", "Contrôle : automates, contrôleurs (Purdue 1)", "OT-N1"),
    ("purdue0", "Procédé : capteurs, actionneurs (Purdue 0)", "OT-N0"),
    ("other", "Autre", "ZONE"),
]
REFERENTIELS = {
    "nis2": "NIS2", "dora": "DORA", "iec62443": "IEC 62443",
    "iso27001": "ISO 27001", "anssi": "ANSSI (hygiène, cartographie)",
}
TRANSPORTS = [("tls", "TLS, chiffré (recommandé)", 6514), ("tcp", "TCP", 514), ("udp", "UDP", 514)]
NOM_ZONE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$")
HOTE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$")


class Abandon(Exception):
    """L'utilisateur a interrompu l'assistant (Ctrl+C, fin de saisie)."""


@dataclass
class Reponses:
    organisation: str = ""
    zones: list[dict] = field(default_factory=list)   # {name, class, prefixes}
    siem: dict | None = None                           # {transport, hote, port, format}
    referentiels: list[str] = field(default_factory=list)

    @classmethod
    def depuis(cls, d: dict) -> Reponses:
        return cls(organisation=str(d.get("organisation") or ""), zones=list(d.get("zones") or []),
                   siem=d.get("siem") or None, referentiels=list(d.get("referentiels") or []))


# --- Contrôle des saisies ------------------------------------------------------

def plages(texte: str) -> list[str]:
    """« 10.0.0.0/24, 10.1.0.0/16 » → plages normalisées ; ValueError si invalide."""
    out = []
    for morceau in re.split(r"[\s,;]+", texte.strip()):
        if not morceau:
            continue
        try:
            reseau = ipaddress.ip_network(morceau, strict=False)
        except ValueError:
            raise ValueError(f"« {morceau} » n'est pas une plage d'adresses (exemple : 10.0.0.0/24)") from None
        if reseau.prefixlen == 0:
            raise ValueError("une zone ne peut pas couvrir toutes les adresses (0.0.0.0/0)")
        out.append(str(reseau))
    if not out:
        raise ValueError("au moins une plage est nécessaire (exemple : 10.0.0.0/24)")
    return out


def _chevauchements(zones: list[dict], nouvelles: list[str]) -> list[str]:
    reseaux = [ipaddress.ip_network(p) for p in nouvelles]
    conflits = []
    for z in zones:
        for p in z["prefixes"]:
            autre = ipaddress.ip_network(p)
            for r in reseaux:
                if r.version == autre.version and r.overlaps(autre):
                    conflits.append(f"{r} chevauche {autre} (zone {z['name']})")
    return conflits


# --- Questions -----------------------------------------------------------------

class Dialogue:
    def __init__(self, lire: Callable[[], str], ecrire: Callable[[str], None]):
        self._lire, self.ecrire = lire, ecrire

    def demander(self, question: str, defaut: str = "") -> str:
        self.ecrire(f"{question}{f' [{defaut}]' if defaut else ''} : ")
        ligne = self._lire()
        if ligne == "":                    # fin de saisie (Ctrl+D) : rien n'est écrit
            raise Abandon()
        return ligne.strip() or defaut

    def oui_non(self, question: str, defaut: bool) -> bool:
        while True:
            r = self.demander(f"{question} (o/n)", "o" if defaut else "n").lower()
            if r in ("o", "oui", "y", "yes"):
                return True
            if r in ("n", "non", "no"):
                return False
            self.ecrire("  Répondre o ou n.\n")

    def choix(self, question: str, options: list[str], defaut: int | None = None,
              afficher: bool = True) -> int:
        """Choix par numéro ; « ? » réaffiche la liste (utile quand elle n'est pas affichée)."""
        def liste():
            for i, o in enumerate(options, 1):
                self.ecrire(f"  {i:>2}. {o}\n")
        if afficher:
            liste()
        while True:
            r = self.demander(question, str(defaut) if defaut else "")
            if r == "?":
                liste()
            elif r.isdigit() and 1 <= int(r) <= len(options):
                return int(r) - 1
            else:
                self.ecrire(f"  Choisir un numéro entre 1 et {len(options)} (« ? » : la liste).\n")


def questionner(d: Dialogue) -> Reponses | None:
    """Pose les questions ; None si l'utilisateur préfère garder l'exemple."""
    rep = Reponses()
    d.ecrire("Chaque réponse se modifie ensuite dans config/auspex.yaml.\n"
             "Entrée seule : valeur proposée entre crochets.\n\n")
    if not d.oui_non("Décrire maintenant les zones de votre réseau ? (sinon : configuration d'exemple)", True):
        return None

    rep.organisation = d.demander("Nom de l'organisation ou du site, en tête des rapports d'audit "
                                  "(ex. Ville de Lyon, site de Villefranche)")

    d.ecrire("\nZones réseau. Une zone = un ensemble de plages d'adresses de même niveau\n"
             "de confiance (annuaire, serveurs, postes, automates…). Auspex contrôle les flux\n"
             "entre zones. Plages au format 10.0.0.0/24, séparées par des virgules.\n")
    while True:
        premiere = not rep.zones
        d.ecrire(f"\nZone n° {len(rep.zones) + 1}\n")
        t = d.choix("Type" if premiere else "Type (« ? » : la liste)",
                    [libelle for _, libelle, _ in TYPES], afficher=premiere)
        classe, libelle, suggestion = TYPES[t]
        pris = {z["name"] for z in rep.zones}
        n, base = 2, suggestion
        while suggestion in pris:
            suggestion, n = f"{base}-{n}", n + 1
        while True:
            nom = d.demander("Nom de la zone (lettres, chiffres, . _ -)", suggestion)
            if not NOM_ZONE.fullmatch(nom):
                d.ecrire("  Nom invalide : lettres, chiffres, point, tiret ou souligné, sans espace.\n")
            elif nom in pris:
                d.ecrire(f"  La zone {nom} existe déjà.\n")
            else:
                break
        while True:
            try:
                prefixes = plages(d.demander("Plages d'adresses"))
            except ValueError as exc:
                d.ecrire(f"  {exc}\n")
                continue
            conflits = _chevauchements(rep.zones, prefixes)
            if conflits:
                d.ecrire("  " + " ; ".join(conflits) + ". Une adresse appartient à une seule zone.\n")
                continue
            break
        rep.zones.append({"name": nom, "class": classe, "prefixes": prefixes})
        d.ecrire(f"  → {nom} : {', '.join(prefixes)} ({libelle.split(' :')[0]})\n")
        if not d.oui_non("Ajouter une autre zone ?", len(rep.zones) < 2):
            break

    d.ecrire("\nSIEM : Auspex peut envoyer ses alertes (flux interdits, nouveaux équipements,\n"
             "balayages) à votre SIEM en syslog. Sinon, elles restent dans NetBox et dans un fichier.\n")
    if d.oui_non("Avez-vous un SIEM qui reçoit du syslog ?", False):
        t = d.choix("Transport", [libelle for _, libelle, _ in TRANSPORTS], 1)
        transport, _, port_defaut = TRANSPORTS[t]
        while True:
            hote = d.demander("Nom ou adresse du SIEM (ex. siem.exemple.local)")
            if HOTE.fullmatch(hote) or _ip(hote):
                break
            d.ecrire("  Nom d'hôte ou adresse IP attendu.\n")
        while True:
            port = d.demander("Port", str(port_defaut))
            if port.isdigit() and 1 <= int(port) <= 65535:
                break
            d.ecrire("  Port entre 1 et 65535.\n")
        f = d.choix("Format", ["CEF (ArcSight, QRadar, Sentinel, Splunk…)", "JSON"], 1)
        rep.siem = {"transport": transport, "hote": hote, "port": int(port), "format": ("cef", "json")[f]}

    d.ecrire("\nExports d'audit signés produits chaque mois. Numéros séparés par des\n"
             "virgules, Entrée seule pour aucun (exports toujours possibles à la demande).\n")
    noms = list(REFERENTIELS)
    for i, k in enumerate(noms, 1):
        d.ecrire(f"  {i}. {REFERENTIELS[k]}\n")
    while True:
        r = d.demander("Référentiels")
        try:
            idx = [int(x) for x in re.split(r"[\s,;]+", r) if x]
            if all(1 <= i <= len(noms) for i in idx):
                rep.referentiels = list(dict.fromkeys(noms[i - 1] for i in idx))
                break
        except ValueError:
            pass
        d.ecrire(f"  Numéros entre 1 et {len(noms)}, séparés par des virgules.\n")
    return rep


def _ip(texte: str) -> bool:
    try:
        ipaddress.ip_address(texte)
        return True
    except ValueError:
        return False


# --- Production du fichier -----------------------------------------------------

def _yaml_valeur(v) -> str:
    """Valeur YAML sur une ligne : l'écriture JSON est du YAML valide, et tout texte
    y est entre guillemets, échappé (un nom ne peut pas injecter de structure)."""
    return json.dumps(v, ensure_ascii=False)


def construire(rep: Reponses, modele: str) -> str:
    """auspex.yaml : le modèle, dont les sections répondues sont remplacées."""
    texte = modele
    if rep.organisation:
        ligne = f"organisation: {_yaml_valeur(rep.organisation)}"
        texte, n = re.subn(r"^# organisation:.*$", lambda _m: ligne, texte, count=1, flags=re.M)
        if not n:
            raise ValueError("modèle : ligne « # organisation: » introuvable")
    if rep.referentiels:
        texte, n = re.subn(r"^(  referentiels: )\[\][^\n]*$", lambda m: m.group(1) + _yaml_valeur(rep.referentiels),
                           texte, count=1, flags=re.M)
        if not n:
            raise ValueError("modèle : ligne « referentiels: [] » introuvable")
    if rep.zones:
        bloc = "zones:\n  # Saisies par l'assistant d'installation (auspex init).\n" + "".join(
            f"  - {{ name: {_yaml_valeur(z['name'])}, class: {z['class']}, "
            f"prefixes: {_yaml_valeur(z['prefixes'])} }}\n" for z in rep.zones)
        texte, n = re.subn(r"^zones:\n(?:  .*\n)+", lambda _m: bloc, texte, count=1, flags=re.M)
        if not n:
            raise ValueError("modèle : section « zones: » introuvable")
    if rep.siem:
        s = rep.siem
        url = f"{s['transport']}://{s['hote']}:{s['port']}"
        ligne = f"    - {{ type: syslog, url: {_yaml_valeur(url)}, format: {s['format']} }}"
        texte, n = re.subn(r"^    # - \{ type: syslog,.*$", lambda _m: ligne, texte, count=1, flags=re.M)
        if not n:
            raise ValueError("modèle : sortie syslog d'exemple introuvable")
    return texte


def valider(texte: str) -> None:
    """La configuration produite doit être acceptée par Auspex (ConfigError sinon).
    Seules les références à des fichiers du central (règles de flux, autorités de
    certification) ne sont pas vérifiées ici : ils n'existent pas encore."""
    raw = yaml.safe_load(texte)
    try:
        parse_config(raw, base_dir=Path("/nonexistent"))
    except ConfigError as exc:
        reste = [p for p in exc.problems if "introuvable" not in p and "n'existe pas" not in p]
        if reste:
            raise ConfigError(reste) from None


def resume(rep: Reponses) -> str:
    lignes = [f"  Organisation : {rep.organisation or '(non renseignée)'}"]
    for z in rep.zones:
        lignes.append(f"  Zone {z['name']:<14} {z['class']:<10} {', '.join(z['prefixes'])}")
    s = rep.siem
    lignes.append(f"  SIEM         : {s['transport']}://{s['hote']}:{s['port']} ({s['format'].upper()})"
                  if s else "  SIEM         : aucun (alertes dans NetBox et dans un fichier)")
    lignes.append(f"  Audit        : {', '.join(REFERENTIELS[r] for r in rep.referentiels) or 'à la demande'}")
    return "\n".join(lignes)


def main(modele: Path, reponses: Path | None) -> int:
    """Pour `auspex init` : configuration sur la sortie standard, dialogue sur la sortie d'erreur."""
    texte_modele = Path(modele).read_text(encoding="utf-8")

    def ecrire(t: str) -> None:
        sys.stderr.write(t)
        sys.stderr.flush()

    if reponses:
        rep = Reponses.depuis(json.loads(Path(reponses).read_text(encoding="utf-8")))
        for f in rep.referentiels:
            if f not in AUDIT_FRAMEWORKS:
                ecrire(f"Référentiel inconnu : {f}\n")
                return 1
    else:
        d = Dialogue(sys.stdin.readline, ecrire)
        try:
            rep = questionner(d)
            if rep is not None:
                ecrire("\nRécapitulatif :\n" + resume(rep) + "\n")
                if not d.oui_non("Enregistrer cette configuration ?", True):
                    ecrire("Configuration d'exemple conservée ; relancer « ./install.sh » ou\n"
                           "modifier config/auspex.yaml.\n")
                    rep = None
        except (Abandon, KeyboardInterrupt):
            ecrire("\nAssistant interrompu : configuration d'exemple conservée.\n")
            rep = None
    if rep is None:
        sys.stdout.write(texte_modele)
        return 0
    texte = construire(rep, texte_modele)
    try:
        valider(texte)
    except ConfigError as exc:
        ecrire("Configuration refusée :\n" + "\n".join(f"  - {p}" for p in exc.problems) + "\n")
        return 1
    sys.stdout.write(texte)
    return 0
