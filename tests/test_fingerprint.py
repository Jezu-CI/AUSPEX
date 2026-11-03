from pathlib import Path

import pytest

from auspex.fingerprint import FingerprintEngine, load_rules
from auspex.fingerprint.engine import RuleError, load_normalizer, load_oui
from conftest import T0, conn

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


@pytest.fixture(scope="module")
def engine_factory():
    rules = load_rules([RULES_DIR])
    oui = load_oui(RULES_DIR / "oui.yaml")
    norm = load_normalizer(RULES_DIR / "aliases.yaml")
    return lambda: FingerprintEngine(rules, oui, normalizer=norm)


def ident(engine, ip):
    return next(a for a in engine.inventory() if a["ip"] == ip)["identification"]


def test_shipped_rules_load():
    rules = load_rules([RULES_DIR])
    assert len(rules) > 30
    assert len({r.id for r in rules}) == len(rules)


def test_domain_controller_from_concordant_signals(engine_factory):
    e = engine_factory()
    for port in (88, 389, 3268, 445, 135, 53):
        e.observe("conn", conn(T0, "10.2.1.5", "10.0.0.5", port,
                               proto="udp" if port == 53 else "tcp",
                               service="dns" if port == 53 else None))
    i = ident(e, "10.0.0.5")
    assert i["os_family"]["value"] == "Windows"
    assert i["os_family"]["confidence"] > 0.9  # cinq indices concordants
    roles = [r["value"] for r in i["role"]]
    assert roles[0] == "Contrôleur de domaine (Kerberos)"
    assert "Serveur DNS" in roles and "Annuaire LDAP" in roles


def test_one_rule_votes_once_regardless_of_volume(engine_factory):
    e1, e2 = engine_factory(), engine_factory()
    e1.observe("conn", conn(T0, "10.2.1.5", "10.0.0.5", 445))
    for _ in range(500):
        e2.observe("conn", conn(T0, "10.2.1.5", "10.0.0.5", 445))
    assert ident(e1, "10.0.0.5")["os_family"] == ident(e2, "10.0.0.5")["os_family"]


def test_unanswered_connection_says_nothing_about_target(engine_factory):
    e = engine_factory()
    e.observe("conn", conn(T0, "10.2.1.5", "10.0.0.9", 3389, state="S0"))
    assert all(a["ip"] != "10.0.0.9" for a in e.inventory())


def test_conflicting_signals_lower_confidence(engine_factory):
    clean, mixed = engine_factory(), engine_factory()
    for e in (clean, mixed):
        e.observe("ssh", {"ts": T0.timestamp(), "id.orig_h": "10.2.1.5", "id.resp_h": "10.1.0.20",
                          "server": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"})
    mixed.observe("conn", conn(T0, "10.2.1.5", "10.1.0.20", 3389))
    c, m = ident(clean, "10.1.0.20")["os_family"], ident(mixed, "10.1.0.20")["os_family"]
    assert c["value"] == m["value"] == "Linux"
    assert m["confidence"] < c["confidence"]
    assert m["alternatives"][0]["value"] == "Windows"
    assert ident(clean, "10.1.0.20")["os_version"]["value"] == "Ubuntu"


def test_user_agent_targets_client(engine_factory):
    e = engine_factory()
    e.observe("http", {"ts": T0.timestamp(), "id.orig_h": "10.2.3.4", "id.resp_h": "10.1.0.80",
                       "user_agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8)"})
    i = ident(e, "10.2.3.4")
    assert i["os_version"]["value"] == "Android 14"
    assert i["device_type"]["value"] == "Mobile ou tablette"


def test_dhcp_hostname_mac_and_oui(engine_factory):
    e = engine_factory()
    e.observe("dhcp", {"ts": T0.timestamp(), "client_addr": "10.2.9.9", "assigned_addr": "10.2.9.9",
                       "server_addr": "10.0.0.5", "mac": "00:15:5D:01:02:03", "host_name": "PC-COMPTA-07"})
    inv = {a["ip"]: a for a in e.inventory()}
    assert inv["10.2.9.9"]["hostnames"] == ["pc-compta-07"]
    assert inv["10.2.9.9"]["macs"] == ["00:15:5d:01:02:03"]
    assert inv["10.2.9.9"]["identification"]["device_type"]["value"] == "Machine virtuelle"
    assert inv["10.0.0.5"]["identification"]["role"][0]["value"] == "Serveur DHCP"


def test_ot_plc_and_master_roles(engine_factory):
    e = engine_factory()
    e.observe("conn", conn(T0, "172.16.2.50", "172.16.2.10", 102, service="s7comm"))
    plc, hmi = ident(e, "172.16.2.10"), ident(e, "172.16.2.50")
    assert plc["vendor"]["value"] == "Siemens"
    assert plc["device_type"]["value"] == "Automate"
    assert hmi["role"][0]["value"].startswith("Client S7")


def test_cip_identity_fields_are_copied(engine_factory):
    e = engine_factory()
    e.observe("cip_identity", {"ts": T0.timestamp(), "id.orig_h": "172.16.2.50", "id.resp_h": "172.16.2.20",
                               "socket_address": "172.16.2.20", "vendor_name": "Rockwell Automation/Allen-Bradley",
                               "product_name": "1756-L83E/B", "revision": "33.11",
                               "device_type_name": "Programmable Logic Controller"})
    i = ident(e, "172.16.2.20")
    assert i["model"]["value"] == "1756-L83E/B"
    assert i["firmware"]["value"] == "33.11"
    assert i["vendor"] == {"value": "Rockwell Automation", "confidence": 0.9,
                           "evidence": ["ot-cip-identity"], "alternatives": []}
    assert i["device_type"]["value"] == "Automate"


def test_aliases_make_concordant_signals_agree(engine_factory):
    """MAC Rockwell + identité CIP Allen-Bradley : un seul fabricant, confiance renforcée."""
    e = engine_factory()
    e.observe("conn", {"ts": T0.timestamp(), "id.orig_h": "172.16.2.50", "id.resp_h": "172.16.2.20",
                       "id.resp_p": 44818, "proto": "tcp", "conn_state": "SF",
                       "resp_l2_addr": "00:00:bc:44:55:66"})
    e.observe("cip_identity", {"ts": T0.timestamp(), "socket_address": "172.16.2.20",
                               "vendor_name": "Rockwell Automation/Allen-Bradley",
                               "product_name": "1769-L33ER", "device_type_name": "Programmable Logic Controller"})
    i = ident(e, "172.16.2.20")
    assert i["vendor"]["value"] == "Rockwell Automation"
    assert i["vendor"]["confidence"] == 0.95  # 1 - (1-0.9)(1-0.5)
    assert i["vendor"]["alternatives"] == []
    # « Équipement industriel » (générique) ne concurrence pas « Automate »
    assert i["device_type"] == {"value": "Automate", "confidence": 0.9,
                                "evidence": ["ot-cip-identity"], "alternatives": []}


def test_generic_value_used_when_nothing_better(engine_factory):
    e = engine_factory()
    e.observe("conn", conn(T0, "172.16.2.50", "172.16.2.30", 20000))
    assert ident(e, "172.16.2.30")["device_type"]["value"] == "Équipement industriel"


def test_aliases_file_validated(tmp_path):
    (tmp_path / "a.yaml").write_text("aliases:\n  couleur: {a: b}\n", encoding="utf-8")
    with pytest.raises(RuleError, match="attributs inconnus"):
        load_normalizer(tmp_path / "a.yaml")


def test_public_ips_not_inventoried(engine_factory):
    e = engine_factory()
    e.observe("conn", conn(T0, "10.2.1.5", "8.8.8.8", 53, proto="udp", service="dns"))
    assert [a["ip"] for a in e.inventory()] == ["10.2.1.5"]


def test_bad_rule_rejected(tmp_path):
    (tmp_path / "bad.yaml").write_text(
        "rules:\n  - {id: x, log: conn, set: {colour: red}, weight: 0.5}\n", encoding="utf-8")
    with pytest.raises(RuleError, match="attributs inconnus"):
        load_rules([tmp_path])
    (tmp_path / "bad.yaml").write_text(
        "rules:\n  - {id: x, log: conn, set: {role: a}, weight: 2}\n", encoding="utf-8")
    with pytest.raises(RuleError, match="weight"):
        load_rules([tmp_path])


def test_router_mac_not_attributed_to_remote_hosts(engine_factory):
    """Derrière un routeur, tous les hôtes distants ont la MAC du routeur."""
    e = engine_factory()
    router = "00:1b:1b:ee:ee:ee"  # préfixe Siemens : le piège serait de le propager
    for ip in ("10.1.0.10", "10.1.0.11", "10.1.0.12"):
        rec = conn(T0, "10.2.1.5", ip, 443)
        rec["resp_l2_addr"] = router
        e.observe("conn", rec)
    inv = {a["ip"]: a for a in e.inventory()}
    for ip in ("10.1.0.10", "10.1.0.11", "10.1.0.12"):
        assert inv[ip]["macs"] == []
        assert "vendor" not in inv[ip]["identification"]
    assert router in e.gateway_macs


def test_mac_of_unanswered_target_ignored(engine_factory):
    e = engine_factory()
    rec = conn(T0, "10.2.1.5", "10.1.0.250", 445, state="REJ")
    rec["resp_l2_addr"] = "00:15:5d:ff:ff:01"
    e.observe("conn", rec)
    assert "10.1.0.250" not in {a["ip"] for a in e.inventory()}


def test_direct_l2_mac_attributed(engine_factory):
    e = engine_factory()
    rec = conn(T0, "172.16.2.50", "172.16.2.10", 102)
    rec["resp_l2_addr"] = "00:1b:1b:10:20:30"
    e.observe("conn", rec)
    assert ident(e, "172.16.2.10")["vendor"]["value"] == "Siemens"


# --- J2–J3 : enseignements des captures réelles (4SICS 2015) -------------------------

def roles(engine, ip):
    return [r["value"] for r in ident(engine, ip).get("role", [])]


def test_scanner_is_not_a_master(engine_factory):
    """Un balayage ouvre des connexions sur 20000, 502, 102 sans échange applicatif :
    pas de faux « maître DNP3 », mais un rôle de balayage qui l'explique."""
    e = engine_factory()
    for host in range(1, 60):
        for port in (20000, 502, 102, 22, 80):
            e.observe("conn", conn(T0, "10.9.9.9", f"10.1.0.{host}", port, state="REJ", ob=0, rb=0))
    e.observe("conn", conn(T0, "10.9.9.9", "10.1.0.200", 20000, state="SF", ob=0, rb=0))   # port ouvert, rien échangé
    r = roles(e, "10.9.9.9")
    assert any("Balayage de ports" in x for x in r)
    assert not any("DNP3" in x for x in r)


def test_scan_needs_many_targets(engine_factory):
    e = engine_factory()
    for host in range(1, 20):           # 19 tentatives refusées : un poste mal configuré, pas un balayage
        e.observe("conn", conn(T0, "10.2.1.5", f"10.1.0.{host}", 445, state="REJ", ob=0, rb=0))
    e.observe("conn", conn(T0, "10.2.1.5", "10.1.0.250", 80))
    assert not any("Balayage" in x for x in roles(e, "10.2.1.5"))


def test_real_master_keeps_its_role(engine_factory):
    e = engine_factory()
    e.observe("conn", conn(T0, "10.2.1.5", "172.16.2.50", 20000, ob=40, rb=120))
    assert "Maître DNP3 (SCADA probable)" in roles(e, "10.2.1.5")


def test_embedded_device_banners_and_certificates(engine_factory):
    e = engine_factory()
    e.observe("ssh", {"id.orig_h": "10.9.9.9", "id.resp_h": "172.16.2.60", "server": "SSH-2.0-moxa_1.0",
                      "client": "SSH-2.0-Nmap-SSH2-Hostkey"})
    e.observe("ssl", {"id.orig_h": "10.9.9.9", "id.resp_h": "172.16.2.75",
                      "subject": "CN=EagleSDV,O=Hirschmann Automation and Control GmbH,C=DE"})
    e.observe("snmp", {"id.orig_h": "10.9.9.9", "id.resp_h": "172.16.2.30",
                       "display_string": "Siemens, SIMATIC S7, CPU-1200, 6ES7 212-1BD30-0XB0 SZVA3YU6014773  , 1, V.1.0.1"})
    assert ident(e, "172.16.2.60")["vendor"]["value"] == "Moxa"
    assert ident(e, "172.16.2.75")["model"]["value"] == "EagleSDV"
    s7 = ident(e, "172.16.2.30")
    assert s7["model"]["value"] == "SIMATIC S7 CPU-1200 (6ES7 212-1BD30-0XB0)"
    assert s7["firmware"]["value"] == "V1.0.1" and s7["vendor"]["value"] == "Siemens"
    assert "Outil de balayage (Nmap)" in roles(e, "10.9.9.9")


def test_rule_numeric_and_aggregate_validation(tmp_path):
    bad = tmp_path / "r.yaml"
    for body in ("match: { resp_bytes: { min: beaucoup } }",
                 "count_distinct: [id.resp_h]\n    min_count: 1",
                 "min_count: 10"):
        bad.write_text(f"rules:\n  - id: x\n    log: conn\n    set: {{ role: r }}\n    weight: 0.5\n    {body}\n")
        with pytest.raises(RuleError):
            load_rules([bad])


def test_inventory_filter():
    from auspex.fingerprint.engine import inventoriable
    assert inventoriable("10.1.2.3") and not inventoriable("8.8.8.8")
    assert inventoriable("141.82.10.5", declared=True)          # adresses publiques d'une zone déclarée
    for ip in ("172.16.255.255", "255.255.255.255", "224.0.0.251", "127.0.0.1", "169.254.1.1"):
        assert not inventoriable(ip, declared=True), ip


def test_broadcast_without_reply_is_not_an_asset(engine_factory):
    e = engine_factory()
    rec = conn(T0, "192.168.0.24", "192.168.0.255", 47808, proto="udp", state="S0", ob=20, rb=0)
    rec.update(service="bacnet", resp_pkts=0)
    e.observe("conn", rec)
    assert all(a["ip"] != "192.168.0.255" for a in e.inventory())


def test_s7_engineering_station_and_bacnet_identity(engine_factory):
    e = engine_factory()
    base = {"id.orig_h": "192.168.1.10", "id.resp_h": "192.168.1.40", "rosctr_name": "User-Data"}
    e.observe("s7comm", {**base, "function_name": "Request: Block Functions"})
    assert "Station d'ingénierie (programmation S7)" in roles(e, "192.168.1.10")
    assert ident(e, "192.168.1.40")["vendor"]["value"] == "Siemens"
    e.observe("bacnet_discovery", {"id.orig_h": "172.16.36.205", "id.resp_h": "172.16.255.255",
                                   "source_h": "172.16.36.205", "pdu_service": "i-am", "vendor": "Tridium Inc."})
    e.observe("bacnet_property", {"id.orig_h": "172.16.36.1", "id.resp_h": "172.16.36.205",
                                  "source_h": "172.16.36.205", "property": "model-name", "value": "NiagaraAX Station"})
    t = ident(e, "172.16.36.205")
    assert t["vendor"]["value"].startswith("Tridium") and t["model"]["value"] == "NiagaraAX Station"
