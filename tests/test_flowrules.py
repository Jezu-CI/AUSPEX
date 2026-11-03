from datetime import date, datetime

from openpyxl import Workbook

from auspex.flowrules import (
    RuleStore, diff_rules, export_rules_csv, import_rules,
)

ZONES = {"T0-AD", "T1-serveurs", "T2-postes", "ADMIN-bastion", "OT-N2"}

GOOD_CSV = """id,source,destination,protocole,port,description,proprietaire,expire_le
C-001,T1-serveurs,T0-AD,tcp,88,Kerberos,Equipe AD,
C-002,T2-postes,T1-serveurs,tcp,443,Applications web,Equipe infra,
C-014,ADMIN-bastion,OT-N2,tcp,22,Maintenance automate,Prestataire X,15/12/2026
C-020,10.2.5.0/24,any,udp,53;123,DNS et NTP,,
"""


def test_import_csv_ok(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text(GOOD_CSV, encoding="utf-8")
    res = import_rules(p, ZONES)
    assert res.ok, [str(x) for x in res.problems]
    assert len(res.rules) == 4
    assert res.rules[2].expire_le == "2026-12-15"
    assert res.rules[3]._ports.matches(123) and not res.rules[3]._ports.matches(80)


def test_import_csv_semicolon_and_french_headers(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text("ID;Source;Destination;Protocole;Port;Propriétaire;Expire le\n"
                 "A1;T2-postes;T1-serveurs;tcp;8000-8100;Moi;2026-11-30\n", encoding="cp1252")
    res = import_rules(p, ZONES)
    assert res.ok, [str(x) for x in res.problems]
    assert res.rules[0].proprietaire == "Moi"
    assert res.rules[0]._ports.matches(8050)


def test_import_reports_every_problem_with_line(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text(
        "id,source,destination,protocole,port,expire_le\n"
        "X1,Zone-Inconnue,T0-AD,tcp,88,\n"
        "X2,T1-serveurs,T0-AD,sctp,99999,\n"
        "X1,T1-serveurs,T0-AD,tcp,88,31/02/2026\n"
        "X4,,T0-AD,tcp,88,\n", encoding="utf-8")
    res = import_rules(p, ZONES)
    msgs = [str(x) for x in res.problems]
    assert any("ligne 2" in m and "Zone-Inconnue" in m for m in msgs)
    assert any("ligne 3" in m and "sctp" in m for m in msgs)
    assert any("ligne 3" in m and "99999" in m for m in msgs)
    assert any("ligne 4" in m and "déjà utilisé" in m for m in msgs)
    assert any("ligne 4" in m and "31/02/2026" in m for m in msgs)
    assert any("ligne 5" in m and "source" in m for m in msgs)


def test_import_missing_columns(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text("id,source\nA,B\n", encoding="utf-8")
    res = import_rules(p, ZONES)
    assert not res.ok and "colonnes obligatoires" in str(res.problems[0])


def test_import_xlsx_with_real_dates_and_numbers(tmp_path):
    wb = Workbook()
    ws = wb.active
    ws.title = "regles"
    ws.append(["id", "source", "destination", "protocole", "port", "description", "propriétaire", "expire_le"])
    ws.append(["C-1", "T2-postes", "T1-serveurs", "TCP", 443, "web", "infra", None])
    ws.append(["C-2", "ADMIN-bastion", "OT-N2", "tcp", 22, "maint", "presta", datetime(2026, 12, 15)])
    p = tmp_path / "r.xlsx"
    wb.save(p)
    res = import_rules(p, ZONES)
    assert res.ok, [str(x) for x in res.problems]
    assert res.rules[0].protocole == "tcp" and res.rules[0].port == "443"
    assert res.rules[1].expire_le == "2026-12-15"


def test_diff_and_store_roundtrip(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text(GOOD_CSV, encoding="utf-8")
    first = import_rules(p, ZONES).rules
    store = RuleStore(tmp_path / "state")
    assert store.load(ZONES) == []
    store.save(first, source="r.csv")
    loaded = store.load(ZONES)
    assert [r.id for r in loaded] == sorted(r.id for r in first)

    # Réimport identique : aucun changement (idempotence)
    assert diff_rules(loaded, import_rules(p, ZONES).rules).is_empty

    p.write_text(GOOD_CSV.replace("C-002,T2-postes,T1-serveurs,tcp,443", "C-002,T2-postes,T1-serveurs,tcp,8443")
                 .replace("C-020,10.2.5.0/24,any,udp,53;123,DNS et NTP,,\n", "")
                 + "C-030,T2-postes,T1-serveurs,tcp,25,SMTP,,\n", encoding="utf-8")
    d = diff_rules(loaded, import_rules(p, ZONES).rules)
    assert [r.id for r in d.added] == ["C-030"]
    assert [new.id for _, new in d.modified] == ["C-002"]
    assert [r.id for r in d.removed] == ["C-020"]


def test_export_reimport(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text(GOOD_CSV, encoding="utf-8")
    rules = import_rules(p, ZONES).rules
    out = tmp_path / "export.csv"
    export_rules_csv(rules, out)
    assert diff_rules(rules, import_rules(out, ZONES).rules).is_empty


def test_expired():
    from auspex.flowrules import FlowRule
    r = FlowRule("x", "any", "any", "tcp", "22", expire_le="2026-10-15")
    assert r.expired(date(2026, 10, 16)) and not r.expired(date(2026, 10, 15))


def test_header_only_file_is_valid_and_empty(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text("id,source,destination,protocole,port,description,proprietaire,expire_le\n")
    res = import_rules(p, ZONES)
    assert res.ok and res.rules == []


def test_truly_empty_file_and_bad_header_refused(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text("")
    assert "fichier vide" in str(import_rules(p, ZONES).problems[0])
    p.write_text("identifiant,de,vers\n")
    assert "colonnes obligatoires" in str(import_rules(p, ZONES).problems[0])
