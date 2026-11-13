from auspex.compliance import evaluate
from auspex.flowrules import FlowRule, compile_rule
from auspex.zeek import aggregate_conn, read_log
from auspex.zones import ZoneMap
from conftest import conn


def rule(rid, src, dst, proto, port, expire=""):
    r = FlowRule(rid, src, dst, proto, port, expire_le=expire)
    assert not compile_rule(r, {"T0-AD", "T1-serveurs", "T2-postes", "ADMIN-bastion", "OT-DMZ", "OT-N2"})
    return r


def run(config, records, rules, now=None, tmp_path=None):
    flows = list(aggregate_conn(iter(records)).values())
    return evaluate(flows, rules, ZoneMap(config.zones), config.alerts, now=now)


def types(report):
    return sorted(f.type for f in report.findings)


def test_declared_flow_is_covered(config, day):
    recs = [conn(day(0), "10.2.1.5", "10.1.0.10", 443)]
    rep = run(config, recs, [rule("C1", "T2-postes", "T1-serveurs", "tcp", "443")])
    assert rep.findings == [] and rep.flows_covered == 1


def test_temporary_ssh_becomes_persistent(config, day):
    """Le cas d'usage : un SSH ouvert pour un dépannage, jamais refermé."""
    first = [conn(day(0), "10.9.0.4", "10.1.0.10", 22)]
    rep1 = run(config, first, [])
    assert types(rep1) == ["nouveau_flux_non_declare"]
    assert rep1.findings[0].service == "SSH"

    later = first + [conn(day(5), "10.9.0.4", "10.1.0.10", 22)]
    rep2 = run(config, later, [])
    persistent = [f for f in rep2.findings if f.type == "flux_non_declare_persistant"]
    assert len(persistent) == 1
    assert "5 jours" in persistent[0].message
    # Même identifiant : l'alerte est mise à jour dans le SIEM, pas dupliquée.
    assert persistent[0].id == rep1.findings[0].id
    assert persistent[0].severity == "high"  # medium escaladé


def test_expired_rule_still_used(config, day):
    recs = [conn(day(20), "10.9.0.4", "172.16.2.10", 22)]
    r = rule("C-014", "ADMIN-bastion", "OT-N2", "tcp", "22", expire="2026-10-15")
    rep = run(config, recs, [r], now=day(20))
    exp = [f for f in rep.findings if f.type == "regle_expiree_utilisee"]
    assert len(exp) == 1 and exp[0].rule_ids == ["C-014"]
    assert exp[0].severity == "critical"  # SSH vers l'OT
    # Avant expiration : couvert
    rep_ok = run(config, recs, [r], now=day(5))
    assert not [f for f in rep_ok.findings if f.type == "regle_expiree_utilisee"]


def test_unused_rule_only_after_long_window(config, day):
    rules = [rule("C1", "T2-postes", "T1-serveurs", "tcp", "443"),
             rule("C9", "T2-postes", "T1-serveurs", "tcp", "25")]
    short = [conn(day(0), "10.2.1.5", "10.1.0.10", 443), conn(day(10), "10.2.1.5", "10.1.0.10", 443)]
    assert "regle_jamais_utilisee" not in types(run(config, short, rules))
    long = short + [conn(day(40), "10.2.1.5", "10.1.0.10", 443)]
    rep = run(config, long, rules)
    unused = [f for f in rep.findings if f.type == "regle_jamais_utilisee"]
    assert [f.rule_ids for f in unused] == [["C9"]]


def test_admin_from_lower_tier_flagged_even_if_declared(config, day):
    recs = [conn(day(0), "10.2.1.5", "10.0.0.5", 3389)]
    rep = run(config, recs, [rule("BAD", "T2-postes", "T0-AD", "tcp", "3389")])
    adm = [f for f in rep.findings if f.type == "flux_admin_inter_tiers"]
    assert len(adm) == 1 and adm[0].severity == "critical" and adm[0].service == "RDP"
    # La règle existe : pas d'écart « non déclaré » en plus
    assert "nouveau_flux_non_declare" not in types(rep)


def test_smb_and_rpc_to_dc_are_not_admin(config, day):
    """Régression : GPO et SYSVOL passent par SMB/RPC depuis tous les postes."""
    recs = [conn(day(0), "10.2.1.5", "10.0.0.5", 445), conn(day(0), "10.2.1.5", "10.0.0.5", 135)]
    rules = [rule("AD", "T2-postes", "T0-AD", "tcp", "445;135")]
    assert run(config, recs, rules).findings == []


def test_admin_from_more_sensitive_tier_ok(config, day):
    recs = [conn(day(0), "10.0.0.5", "10.1.0.10", 3389)]
    rep = run(config, recs, [rule("OK", "T0-AD", "T1-serveurs", "tcp", "3389")])
    assert rep.findings == []


def test_it_to_ot_direct(config, day):
    recs = [conn(day(0), "10.1.0.10", "172.16.2.10", 502)]
    rep = run(config, recs, [])
    assert "flux_it_vers_ot_direct" in types(rep)
    # Via la DMZ industrielle : pas de violation d'architecture
    recs2 = [conn(day(0), "172.16.35.5", "172.16.2.10", 502)]
    assert "flux_it_vers_ot_direct" not in types(run(config, recs2, []))


def test_rejected_attempts_are_not_flows(config, day):
    recs = [conn(day(0), "10.2.1.5", "10.0.0.5", 445, state="REJ"),
            conn(day(0), "10.2.1.5", "10.0.0.5", 445, state="S0")]
    rep = run(config, recs, [])
    assert rep.findings == []


def test_intra_zone_ignored_by_default(config, day):
    recs = [conn(day(0), "10.2.1.5", "10.2.1.6", 445)]
    assert run(config, recs, []).findings == []
    config.alerts.check_intra_zone = True
    assert types(run(config, recs, [])) == ["nouveau_flux_non_declare"]


def test_unknown_zone_is_high(config, day):
    recs = [conn(day(0), "192.168.50.3", "10.1.0.10", 443)]
    rep = run(config, recs, [])
    assert rep.findings[0].src_zone == "(inconnue)" and rep.findings[0].severity == "high"


def test_cidr_and_any_rules(config, day):
    recs = [conn(day(0), "10.2.5.7", "10.1.0.10", 53, proto="udp")]
    assert run(config, recs, [rule("D", "10.2.5.0/24", "any", "udp", "53;123")]).findings == []
    assert run(config, recs, [rule("D", "10.2.6.0/24", "any", "udp", "53")]).findings != []


def test_zeek_tsv_format(tmp_path):
    p = tmp_path / "conn.log"
    p.write_text(
        "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tconn_state\torig_bytes\tresp_bytes\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tstring\tcount\tcount\n"
        "1790841600.0\tC1\t10.2.1.5\t51000\t10.1.0.10\t22\ttcp\tssh\tSF\t10\t-\n", encoding="utf-8")
    recs = list(read_log(p))
    assert recs[0]["id.resp_p"] == "22" and "resp_bytes" not in recs[0]
    flows = aggregate_conn(iter(recs))
    f = next(iter(flows.values()))
    assert f.port == 22 and f.count == 1 and f.bytes == 10 and f.services == {"ssh"}


def test_zeek_json_gz(tmp_path, day):
    import gzip
    import json
    p = tmp_path / "conn.12:00:00-13:00:00.log.gz"
    with gzip.open(p, "wt") as fh:
        fh.write(json.dumps(conn(day(0), "10.2.1.5", "10.1.0.10", 22)) + "\n")
    assert len(list(read_log(p))) == 1
