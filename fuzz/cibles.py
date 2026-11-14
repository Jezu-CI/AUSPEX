"""Cibles de fuzzing : les analyseurs qui lisent des données venues de l'extérieur.

Chaque cible reçoit des octets quelconques et vérifie le contrat de l'analyseur :
soit il accepte, soit il refuse avec SON erreur documentée (ConfigError, MajError,
problèmes d'import…). Toute autre exception est un défaut : une donnée malveillante
ou abîmée ne doit jamais faire tomber un cycle d'analyse ni contourner un contrôle.

- manifeste      : manifeste de mise à jour du capteur (vérifié avant la signature)
- journal_zeek   : journaux envoyés par les capteurs (JSON ou TSV, en-têtes compris)
- regles_csv     : fichier des flux autorisés déposé par l'utilisateur
- champs_regle   : ports, extrémités et dates d'une règle (cellules Excel ou CSV)
- configuration  : auspex.yaml
- journal_gzip   : journaux compressés (archives de rotation, éventuellement tronquées)
- regles_xlsx    : classeur Excel des flux autorisés (cellules quelconques ou fichier abîmé)
- identification : moteur d'identification (règles réelles de rules/) sur des journaux forgés
- cle_capteur    : clé publique collée par l'utilisateur à l'enrôlement d'un capteur
- sauvegarde     : archive de sauvegarde présentée à la restauration
- reponse_netbox : réponses de l'API NetBox (rapprochement inventaire observé / déclaré)

Exécution : python fuzz/fuzz.py CIBLE [secondes] (Atheris si installé, sinon
mutations aléatoires) ; corpus de départ dans fuzz/corpus/CIBLE/.
"""
from __future__ import annotations

import gzip
import io
import json
import os
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from auspex import backup as _backup
from auspex import config as _config
from auspex import flowrules as _flowrules
from auspex import maj as _maj
from auspex import netbox as _netbox
from auspex import reception as _reception
from auspex import zeek as _zeek
from auspex.fingerprint import engine as _engine

RACINE = Path(__file__).resolve().parent.parent

ZONES = {"T0-AD", "T1-serveurs", "OT-N2"}
_TMP = Path(tempfile.mkdtemp(prefix="auspex-fuzz-"))


def _fichier(nom: str, data: bytes) -> Path:
    p = _TMP / f"{os.getpid()}-{nom}"
    p.write_bytes(data)
    return p


def manifeste(data: bytes) -> None:
    try:
        out = _maj.parse_manifest(data)
    except _maj.MajError:
        return
    assert out["format"] == _maj.FORMAT and _maj.VERSION_RE.fullmatch(out["version"])
    _maj.version_key(out["version"])           # une version acceptée doit être comparable


def journal_zeek(data: bytes) -> None:
    records = list(_zeek.read_log(_fichier("conn.log", data)))
    for rec in records:
        assert isinstance(rec, dict)
        _zeek.ts_of(rec)
    _zeek.aggregate_conn(iter(records))     # agrégation des flux, comme au cycle d'analyse


def regles_csv(data: bytes) -> None:
    res = _flowrules.import_rules(_fichier("regles.csv", data), ZONES)
    assert isinstance(res.rules, list) and isinstance(res.problems, list)


def champs_regle(data: bytes) -> None:
    texte = data.decode("utf-8", errors="replace")
    for f in (_flowrules._parse_ports, lambda v: _flowrules._parse_endpoint(v, ZONES)):
        r = f(texte)
        assert r is not None
    r = _flowrules._parse_date(texte)
    assert r is None or isinstance(r, (str, ValueError))


def configuration(data: bytes) -> None:
    try:
        _config.load_config(_fichier("auspex.yaml", data))
    except _config.ConfigError:
        return


def journal_gzip(data: bytes) -> None:
    """Premier octet : 0 = octets bruts (fichier .gz quelconque), 1 = gzip valide,
    2 = gzip tronqué (archive en cours d'écriture) ; le reste est le journal."""
    mode, corps = (data[0] % 3, data[1:]) if data else (0, b"")
    if mode == 1:
        corps = gzip.compress(corps)
    elif mode == 2:
        corps = gzip.compress(corps)
        corps = corps[:len(corps) * 2 // 3]
    records = list(_zeek.read_log(_fichier("conn.2026-11-01.log.gz", corps)))
    for rec in records:
        assert isinstance(rec, dict)
    _zeek.aggregate_conn(iter(records))


def regles_xlsx(data: bytes) -> None:
    """Premier octet pair : fichier .xlsx quelconque (abîmé, forgé) ; impair : vrai
    classeur dont les cellules viennent des données (lignes « \\n », cellules « ; »)."""
    if data and data[0] % 2:
        from openpyxl import Workbook
        wb = Workbook()
        ws = wb.active
        ws.title = "regles"
        for ligne in data[1:].decode("utf-8", errors="replace").split("\n")[:200]:
            cellules = []
            for c in ligne.split(";")[:30]:
                c = "".join(ch for ch in c if ch in "\t\n\r" or ord(ch) >= 32)   # caractères admis par Excel
                cellules.append(int(c) if c.strip().isdigit() and len(c) < 15 else c)
            ws.append(cellules)
        tampon = io.BytesIO()
        wb.save(tampon)
        data = tampon.getvalue()
    res = _flowrules.import_rules(_fichier("regles.xlsx", data), ZONES)
    assert isinstance(res.rules, list) and isinstance(res.problems, list)


_MOTEUR: dict = {}


def _regles_reelles():
    if not _MOTEUR:
        d = RACINE / "rules"
        _MOTEUR["regles"] = _engine.load_rules([d])
        _MOTEUR["oui"] = _engine.load_oui(d / "oui.yaml")
        _MOTEUR["norm"] = _engine.load_normalizer(d / "aliases.yaml")
        _MOTEUR["journaux"] = sorted({r.log for r in _MOTEUR["regles"]} | {"conn", "dhcp", "ntlm"})
    return _MOTEUR


def identification(data: bytes) -> None:
    """Premier octet : type de journal (conn, http, modbus, s7comm…) ; le reste : le journal.
    Les règles d'identification du dépôt s'appliquent à des valeurs quelconques."""
    m = _regles_reelles()
    kind = m["journaux"][data[0] % len(m["journaux"])] if data else "conn"
    moteur = _engine.FingerprintEngine(m["regles"], m["oui"], normalizer=m["norm"])
    for rec in _zeek.read_log(_fichier(f"{kind}.log", data[1:])):
        moteur.observe(kind, rec)
    for actif in moteur.inventory():
        json.dumps(actif)                       # l'inventaire doit rester enregistrable


def cle_capteur(data: bytes) -> None:
    texte = data.decode("utf-8", errors="replace")
    try:
        cle = _reception.parse_public_key(texte)
    except _reception.SensorKeyError:
        return
    assert "\n" not in cle and cle.startswith("ssh-ed25519 ")   # rien ne s'ajoute au fichier des clés
    assert _reception.fingerprint(cle).startswith("SHA256:")


def sauvegarde(data: bytes) -> None:
    """Premier octet pair : archive quelconque ; impair : vraie archive tar.gz dont
    le manifeste et un fichier viennent des données (séparés par un octet nul)."""
    if data and data[0] % 2:
        manifeste_, _, contenu = data[1:].partition(b"\0")
        tampon = io.BytesIO()
        with tarfile.open(fileobj=tampon, mode="w:gz") as tar:
            for nom, octets in (("manifest.json", manifeste_), ("state/assets.json", contenu)):
                info = tarfile.TarInfo(nom)
                info.size = len(octets)
                tar.addfile(info, io.BytesIO(octets))
        data = tampon.getvalue()
    try:
        _backup.inspect_backup(_fichier("sauvegarde.tar.gz", data))
    except _backup.BackupError:
        return


class _NetBoxForge(_netbox.NetBoxClient):
    """Client NetBox dont les réponses viennent des données : {chemin: réponse}."""

    def __init__(self, reponses):
        super().__init__("https://netbox.exemple", "jeton")
        self.reponses = reponses

    def request(self, method, path, params=None, body=None):
        assert method == "GET"
        brut = self.reponses.get(path.replace("https://netbox.exemple", "").split("?")[0]) \
            if isinstance(self.reponses, dict) else self.reponses
        return _netbox.decode_response(brut if isinstance(brut, bytes) else json.dumps(brut).encode(), method, path)


_NB: dict = {}


def _contexte_netbox():
    if not _NB:
        _NB["cfg"] = _config.parse_config({
            "version": 1,
            "zones": [{"name": "T0-AD", "class": "tier0", "prefixes": ["10.0.0.0/24"]},
                      {"name": "OT-N2", "class": "purdue2", "prefixes": ["172.16.2.0/24"]}],
            "sensors": [{"name": "capteur-ot", "zone": "OT-N2", "interface": "eth1"}],
            "netbox": {"url": "https://netbox.exemple", "token_env": "NETBOX_TOKEN"},
        }, base_dir=_TMP)
        m = _regles_reelles()
        moteur = _engine.FingerprintEngine(m["regles"], m["oui"], normalizer=m["norm"])
        for src, dst, port, service in (("10.0.0.5", "10.0.0.6", 445, "smb"),
                                        ("172.16.2.10", "172.16.2.20", 502, "modbus")):
            moteur.observe("conn", {"ts": 1793500000.0, "id.orig_h": src, "id.resp_h": dst, "id.resp_p": port,
                                    "proto": "tcp", "conn_state": "SF", "service": service})
        _NB["actifs"] = moteur.inventory()
    return _NB


def reponse_netbox(data: bytes) -> None:
    """Données : JSON {chemin de l'API: page de résultats}, ou octets quelconques (toutes les
    réponses). Contrat : la réponse est exploitée, ou refusée par NetBoxError."""
    try:
        reponses = json.loads(data)
    except (ValueError, RecursionError):
        reponses = data
    ctx = _contexte_netbox()
    client = _NetBoxForge(reponses)
    try:
        ip_objects = client.list("/api/ipam/ip-addresses/")
        declares = _netbox.fetch_declared(client)
        _netbox.check_objects(ip_objects, declares)
    except _netbox.NetBoxError:
        return
    _netbox.build_plan(ctx["cfg"], ctx["actifs"], ip_objects)
    _netbox.reconcile(ctx["cfg"], ctx["actifs"], ip_objects, declares,
                      datetime(2026, 11, 14, tzinfo=timezone.utc))


CIBLES = {f.__name__: f for f in (manifeste, journal_zeek, regles_csv, champs_regle, configuration,
                                  journal_gzip, regles_xlsx, identification, cle_capteur, sauvegarde,
                                  reponse_netbox)}
