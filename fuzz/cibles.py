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

Exécution : python fuzz/fuzz.py CIBLE [secondes] (Atheris si installé, sinon
mutations aléatoires) ; corpus de départ dans fuzz/corpus/CIBLE/.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from auspex import config as _config
from auspex import flowrules as _flowrules
from auspex import maj as _maj
from auspex import zeek as _zeek

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


CIBLES = {f.__name__: f for f in (manifeste, journal_zeek, regles_csv, champs_regle, configuration)}
