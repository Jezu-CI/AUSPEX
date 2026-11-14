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
    # Issue #9 : lecteurs ajoutés au fuzzing
    ("journal_gzip", b"\x00\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + b"\xff\xfe\xfd" * 8 + b"\n"),  # gzip abîmé
    ("identification", ("conn", b'{"ts":1,"id.orig_h":"10.0.0.1","id.resp_h":"10.0.0.2","proto":1}\n')),
    ("identification", ("conn", b'{"ts":1,"id.orig_h":"10.0.0.1","id.resp_h":"10.0.0.2","proto":"tcp",'
                                b'"conn_state":["SF"]}\n')),
    ("identification", ("conn", b'{"ts":1,"id.orig_h":"10.0.0.1","id.resp_h":["10.0.0.2"],"proto":"udp",'
                                b'"resp_pkts":1e400}\n')),
    ("identification", ("dhcp", b'{"ts":1,"assigned_addr":"10.0.0.3","mac":7}\n')),       # MAC non textuelle
    ("sauvegarde", b'\x01{"format": 1, "files": {ate\x00x'),                               # manifeste illisible
    ("sauvegarde", b"\x01[1]\x00x"),
    ("sauvegarde", b'\x01{"format": 1, "files": {"state/assets.json": 3}}\x00x'),
    ("sauvegarde", b"\x00\x1f\x8b\x08garbage"),                                              # archive abîmée
    ("reponse_netbox", b'{"/api/ipam/ip-addresses/": {"results": [], "next": "https://[::1/x"}}'),
    ("reponse_netbox", b'{"/api/ipam/ip-addresses/": {"results": [], '
                       b'"next": "https://netbox.exemple/api/ipam/ip-addresses/"}}'),      # pagination sans fin
    ("reponse_netbox", b'{"/api/ipam/ip-addresses/": {"results": [1]}}'),
    ("reponse_netbox", b'{"/api/ipam/ip-addresses/": {"results": [{"id": "7", "address": "10.0.0.5/24"}]}}'),
    ("reponse_netbox", b'{"/api/dcim/devices/": {"results": [{"id": 1, "platform": "Windows"}]}}'),
    ("reponse_netbox", b"<html>proxy</html>"),
    ("reponse_netbox", b"[]"),
]


@pytest.mark.parametrize("cible, data", REGRESSIONS)
def test_regressions(cible, data):
    if isinstance(data, tuple):                 # (type de journal, journal) pour l'identification
        kind, journal = data
        data = bytes([cibles._regles_reelles()["journaux"].index(kind)]) + journal
    cibles.CIBLES[cible](data)


def test_regression_classeur_abime():
    """Données compressées d'une feuille abîmées : problème d'import, pas zlib.error."""
    import io
    import zipfile
    x = (ROOT / "fuzz/corpus/regles_xlsx/fichier").read_bytes()[1:]
    info = zipfile.ZipFile(io.BytesIO(x)).getinfo("xl/worksheets/sheet1.xml")
    debut = info.header_offset + 30 + len(info.filename) + len(info.extra)
    abime = bytearray(x)
    for k in range(debut + 2, debut + 12):
        abime[k] ^= 0x5A
    cibles.regles_xlsx(b"\x00" + bytes(abime))


def test_ligne_demesuree_ignoree_sans_tout_lire(tmp_path, monkeypatch):
    """Archive piégée : une ligne sans fin n'est jamais gardée entière en mémoire."""
    import gzip
    from auspex import zeek
    monkeypatch.setattr(zeek, "MAX_LINE", 100)
    ok = b'{"ts":1,"id.orig_h":"10.0.0.1","id.resp_h":"10.0.0.2","proto":"udp"}\n'
    p = tmp_path / "conn.log.gz"
    p.write_bytes(gzip.compress(ok + b"A" * 1000 + b"\n" + ok))
    lignes = list(zeek._complete_lines(p))
    assert [ligne for _, ligne in lignes] == [ok, ok]
    assert lignes[1][0] == len(ok) + 1001          # positions exactes (reprise de lecture)
    p.write_bytes(gzip.compress(ok + b"A" * 1000))  # ligne sans fin : rien après
    assert [ligne for _, ligne in zeek._complete_lines(p)] == [ok]


@pytest.mark.parametrize("ext", ["csv", "xlsx"])
def test_fichier_de_regles_trop_long_refuse(tmp_path, monkeypatch, ext):
    from auspex import flowrules
    monkeypatch.setattr(flowrules, "MAX_ROWS", 5)
    lignes = [["id", "source", "destination", "protocole", "ports"]] + \
             [[f"r{i}", "T0-AD", "OT-N2", "tcp", "502"] for i in range(10)]
    p = tmp_path / f"regles.{ext}"
    if ext == "csv":
        p.write_text("\n".join(",".join(li) for li in lignes), encoding="utf-8")
    else:
        from openpyxl import Workbook
        wb = Workbook()
        for li in lignes:
            wb.active.append(li)
        wb.save(p)
    res = flowrules.import_rules(p, {"T0-AD", "OT-N2"})
    assert res.rules == [] and "plus de 5 lignes" in res.problems[0].message


def test_netbox_pagination_sans_fin_refusee():
    from auspex.netbox import NetBoxError
    page = {"results": [], "next": "https://netbox.exemple/api/ipam/ip-addresses/?offset=0"}
    client = cibles._NetBoxForge({"/api/ipam/ip-addresses/": page})
    with pytest.raises(NetBoxError, match="pagination sans fin"):
        client.list("/api/ipam/ip-addresses/")


def test_netbox_objets_de_forme_inattendue_refuses():
    from auspex.netbox import NetBoxError, check_objects
    check_objects([{"id": 1, "address": "10.0.0.5/24", "tags": [{"slug": "auspex"}]}],
                  [{"id": 2, "name": "dc01", "status": {"value": "active"}, "platform": {"name": "Windows"}}])
    with pytest.raises(NetBoxError, match="adresse IP"):
        check_objects([{"id": True, "address": "10.0.0.5/24"}], [])
    with pytest.raises(NetBoxError, match="équipement"):
        check_objects([], [{"id": 2, "primary_ip4": {"address": 5}}])


@pytest.mark.parametrize("cible", sorted(cibles.CIBLES))
def test_courte_passe(cible):
    """Deux secondes de mutations par cible, graine fixe : reproductible."""
    assert moteur.sans_atheris(cible, 2, graine=1) == 0
