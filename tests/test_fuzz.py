"""Fuzzing : régressions des défauts trouvés, et courte passe à chaque exécution des tests.

Chaque entrée ci-dessous a fait planter un analyseur avant correction (fuzz/fuzz.py) :
une donnée abîmée ou forgée doit être refusée proprement, jamais lever une exception.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzz"))
import cibles  # noqa: E402
import fuzz as moteur  # noqa: E402

REGRESSIONS = [
    ("manifeste", b"format=auspex-maj-capteu\x80\nversion=0.2.0\n"),                      # non ASCII
    ("journal_zeek", b"#separator\n#fields\tts\n1\n"),                                     # en-tête sans valeur
    ("journal_zeek", b"#separator \\x\n#unset_field\n#empty_field\n"),                     # échappement invalide
    ("journal_zeek", b"#separator \\x00\n"),                                                # séparateur nul
    ("journal_zeek", b'{"ts":1e300,"id.orig_h":"a","id.resp_h":"b","proto":"tcp"}\n'),     # horodatage hors limites
    ("journal_zeek", b'{"ts":1,"id.orig_h":"a","id.resp_h":"b","proto":7}\n'),               # champ du mauvais type
    ("journal_zeek", b'{"ts":1,"id.orig_h":"a","id.resp_h":"b","proto":"tcp","id.resp_p":Infinity,'
                     b'"conn_state":["S0"]}\n'),
    ("journal_zeek", b'{"ts":1,"id.orig_h":"a","id.resp_h":"b","proto":"udp"}\n'
                     b'{"ts":"2026-01-01T00:00:00","id.orig_h":"a","id.resp_h":"b","proto":"udp"}\n'),  # fuseau absent
    ("regles_csv", b"id;source\n\x8f\x81\x9d;\x90\n"),                                      # octets hors cp1252
    ("regles_csv", b"id,source\x00,destination\n"),                                         # caractère nul
    ("champs_regle", b"inf"),                                                               # port infini
    ("champs_regle", b"1-inf"),
    ("configuration", b"version: 1\n\xf3\x28\n"),                                           # non UTF-8
    ("configuration", b"version: 1\naccess: texte\n"),                                       # mauvais type
    ("configuration", b"[1, 2]\n"),
]


@pytest.mark.parametrize("cible, data", REGRESSIONS)
def test_regressions(cible, data):
    cibles.CIBLES[cible](data)


@pytest.mark.parametrize("cible", sorted(cibles.CIBLES))
def test_courte_passe(cible):
    """Deux secondes de mutations par cible, graine fixe : reproductible."""
    assert moteur.sans_atheris(cible, 2, graine=1) == 0
