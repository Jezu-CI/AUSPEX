"""Alerte « balayage du réseau » (issue #2) : détection, seuil, fenêtre, gravité,
exceptions, cycle de vie dans le SIEM, configuration, persistance, audit."""
import json
from datetime import timedelta

import pytest

from auspex.compliance import evaluate
from auspex.config import ConfigError, parse_config
from auspex.outputs import normalize, to_cef
from auspex.state import AlertStore, FlowStore
from auspex.zeek import aggregate_conn
from auspex.zones import ZoneMap
from conftest import BASE_CONFIG, conn

SCANNER = "10.2.1.66"   # poste de la zone T2-postes


def scan(ts, src=SCANNER, n=120, net="10.1.0", state="REJ", first_port=1):
    """n tentatives vers n cibles (adresse, port) distinctes, sur 10 machines."""
    return [conn(ts + timedelta(seconds=i), src, f"{net}.{10 + i % 10}", first_port + i // 10, state=state)
            for i in range(n)]


def cfg_with(tmp_path, **scan_cfg):
    raw = json.loads(json.dumps(BASE_CONFIG))
    raw["alerts"]["scan"] = scan_cfg
    return parse_config(raw, base_dir=tmp_path)


def run(config, records, now):
    flows = list(aggregate_conn(iter(records)).values())
    return evaluate(flows, [], ZoneMap(config.zones), config.alerts, now=now)


def scans(report):
    return [f for f in report.findings if f.type == "balayage_reseau"]


def test_scan_detected(config, day):
    rep = run(config, scan(day(0)), now=day(0, 1))
    [f] = scans(rep)
    assert f.src == SCANNER and f.src_zone == "T2-postes" and f.dst_zone == "T1-serveurs"
    assert f.severity == "high" and f.count == 120 and f.proto == "tcp"
    assert f.title == "Balayage du réseau"
    assert "120 cibles" in f.message and "10 machine(s)" in f.message and "en 24 h" in f.message
    assert "ports les plus visés : 1, 2, 3, 4, 5" in f.message
    assert any("§3.2" in r for r in f.references) and any("SR 6.2" in r for r in f.references)


def test_unanswered_s0_counts_too(config, day):
    rep = run(config, scan(day(0), n=60) + scan(day(0), n=60, state="S0", first_port=100), now=day(0, 1))
    assert scans(rep)[0].count == 120


def test_below_threshold(config, day):
    """99 cibles : un poste mal configuré, pas un balayage (même seuil que l'identification)."""
    assert scans(run(config, scan(day(0), n=99), now=day(0, 1))) == []


@pytest.mark.parametrize("state", ["SH", "OTH", "RSTOS0", "S1"])
def test_other_states_ignored(config, day, state):
    """Captures asymétriques : ces états ne prouvent pas un balayage."""
    assert scans(run(config, scan(day(0), state=state), now=day(0, 1))) == []


def test_reached_targets_not_counted(config, day):
    """Une cible finalement jointe (SF) n'est pas une cible refusée."""
    recs = scan(day(0), n=100) + [conn(day(0, 1), SCANNER, "10.1.0.10", 1)]  # port 1 de .10 joint
    assert scans(run(config, recs, now=day(0, 2))) == []


def test_window(config, day):
    recs = scan(day(0))
    assert scans(run(config, recs, now=day(0, 23)))      # dans les 24 h
    assert scans(run(config, recs, now=day(1, 1))) == []  # balayage terminé depuis plus de 24 h


def test_window_configurable(tmp_path, day):
    c = cfg_with(tmp_path, window_hours=2)
    assert scans(run(c, scan(day(0)), now=day(0, 1)))
    assert scans(run(c, scan(day(0)), now=day(0, 3))) == []


@pytest.mark.parametrize("net, zone", [("172.16.2", "OT-N2"), ("10.0.0", "T0-AD")])
def test_sensitive_targets_critical(config, day, net, zone):
    [f] = scans(run(config, scan(day(0), net=net), now=day(0, 1)))
    assert f.severity == "critical" and f.dst_zone == zone and "cibles sensibles" in f.message


def test_severity_configurable(tmp_path, day):
    c = cfg_with(tmp_path, severity="medium")
    assert scans(run(c, scan(day(0)), now=day(0, 1)))[0].severity == "medium"
    assert scans(run(c, scan(day(0), net="172.16.2"), now=day(0, 1)))[0].severity == "high"


def test_threshold_configurable(tmp_path, day):
    c = cfg_with(tmp_path, min_targets=20)
    assert scans(run(c, scan(day(0), n=20), now=day(0, 1)))


def test_allowed_scanner(tmp_path, day):
    c = cfg_with(tmp_path, allowed=["10.2.1.66", "10.9.0.0/24"])
    recs = scan(day(0)) + scan(day(0), src="10.9.0.7") + scan(day(0), src="10.2.1.67")
    assert [f.src for f in scans(run(c, recs, now=day(0, 1)))] == ["10.2.1.67"]


def test_disabled(tmp_path, day):
    assert scans(run(cfg_with(tmp_path, enabled=False), scan(day(0)), now=day(0, 1))) == []


def test_one_alert_per_scanner(config, day):
    recs = scan(day(0)) + scan(day(0), src="10.2.1.67", net="10.1.1")
    found = scans(run(config, recs, now=day(0, 1)))
    assert sorted(f.src for f in found) == [SCANNER, "10.2.1.67"]
    assert len({f.id for f in found}) == 2


def test_siem_lifecycle(config, day, tmp_path):
    """Une seule ouverture pendant le balayage, pas de rafale, résolution quand il cesse."""
    store = AlertStore(tmp_path / "state")
    first = scan(day(0))
    ev1 = store.reconcile(run(config, first, now=day(0, 1)).findings, day(0, 1))
    assert [(e["event"], e["type"]) for e in ev1] == [("open", "balayage_reseau")]
    # Le balayage continue, plus de cibles : même alerte, aucun nouvel événement
    more = first + scan(day(0, 2), n=300, first_port=50)
    assert store.reconcile(run(config, more, now=day(0, 3)).findings, day(0, 3)) == []
    # Il atteint l'atelier : la gravité monte, une mise à jour
    ot = more + scan(day(0, 4), net="172.16.2")
    ev3 = store.reconcile(run(config, ot, now=day(0, 5)).findings, day(0, 5))
    assert [(e["event"], e["severity"]) for e in ev3] == [("update", "critical")]
    assert ev3[0]["id"] == ev1[0]["id"]
    # Plus aucune tentative depuis 24 h : résolue
    ev4 = store.reconcile(run(config, ot, now=day(2)).findings, day(2))
    assert [(e["event"], e["id"]) for e in ev4] == [("resolve", ev1[0]["id"])]


def test_siem_event_formats(config, day):
    [f] = scans(run(config, scan(day(0)), now=day(0, 1)))
    ev = normalize({"event": "open", **f.to_dict()}, now=day(0, 1))
    assert ev["type"] == "balayage_reseau" and ev["severity_id"] == 4
    assert ev["src_endpoint"] == {"ip": SCANNER, "zone": "T2-postes"}
    assert ev["dst_endpoint"]["ip"] is None and ev["count"] == 120
    cef = to_cef(ev)
    assert cef.startswith("CEF:0|auspex|auspex|") and "|balayage_reseau|Balayage du réseau|8|" in cef
    assert f"src={SCANNER}" in cef and "cnt=120" in cef and " dst=" not in cef


def test_flow_store_keeps_unanswered(tmp_path, day):
    store = FlowStore(tmp_path)
    flows = aggregate_conn(iter(scan(day(0), n=3) + [conn(day(0), SCANNER, "10.1.0.10", 1, state="SH")]))
    store.save(flows)
    loaded = store.load()
    f = loaded[(SCANNER, "10.1.0.10", "tcp", 1)]
    assert f.attempts_rejected == 2 and f.attempts_unanswered == 1
    FlowStore.merge(loaded, aggregate_conn(iter(scan(day(1), n=1))))
    assert loaded[(SCANNER, "10.1.0.10", "tcp", 1)].attempts_unanswered == 2


def test_flow_store_reads_old_state(tmp_path, day):
    """État enregistré par une version antérieure (sans attempts_unanswered)."""
    old = [{"src": SCANNER, "dst": "10.1.0.10", "proto": "tcp", "port": 1, "first_seen": day(0).isoformat(),
            "last_seen": day(0).isoformat(), "count": 0, "bytes": 0, "attempts_rejected": 4, "services": []}]
    (tmp_path / "flows.json").write_text(json.dumps(old))
    assert FlowStore(tmp_path).load()[(SCANNER, "10.1.0.10", "tcp", 1)].attempts_unanswered == 0


@pytest.mark.parametrize("scan_cfg, error", [
    ({"min_targets": 1}, "alerts.scan.min_targets"),
    ({"min_targets": "100"}, "alerts.scan.min_targets"),
    ({"window_hours": 0}, "alerts.scan.window_hours"),
    ({"severity": "grave"}, "alerts.scan.severity"),
    ({"enabled": "oui"}, "alerts.scan.enabled"),
    ({"allowed": ["10.2.1.300"]}, "alerts.scan.allowed[0]"),
    ({"allowed": "10.2.1.66"}, "alerts.scan.allowed"),
    ({"seuil": 3}, "clé(s) inconnue(s) seuil"),
])
def test_config_errors(tmp_path, scan_cfg, error):
    with pytest.raises(ConfigError) as e:
        cfg_with(tmp_path, **scan_cfg)
    assert error in str(e.value)


def test_config_defaults(config):
    s = config.alerts.scan
    assert (s.enabled, s.min_targets, s.window_hours, s.severity, s.allowed) == (True, 100, 24, "high", ())


def test_identification_rule_and_alert_share_threshold():
    """Rôle d'identification « Balayage de ports » et alerte : même seuil par défaut."""
    import yaml
    from pathlib import Path
    rules = yaml.safe_load((Path(__file__).resolve().parent.parent / "rules" / "it.yaml").read_text(encoding="utf-8"))
    rules = rules["rules"] if isinstance(rules, dict) else rules
    port_scan = next(r for r in rules if r["id"] == "it-port-scan")
    from auspex.config import ScanConfig
    assert port_scan["min_count"] == ScanConfig().min_targets
    assert set(port_scan["match"]["conn_state"]["one_of"]) == {"REJ", "S0"}


@pytest.mark.parametrize("fw, ref", [("nis2", "§3.2"), ("iec62443", "SR 6.2"), ("iso27001", "A.8.16")])
def test_audit_surveillance_controls(fw, ref):
    """Sans balayage ouvert : preuve de surveillance (comme avant) ; avec : écart rapporté."""
    from auspex.audit import FRAMEWORKS, _evaluate
    ctx = {"netbox": True, "rules": True, "observed": True}
    ctl = lambda findings: next(c for c in _evaluate(FRAMEWORKS[fw], findings, ctx) if c["ref"] == ref)
    assert ctl([])["statut"] == "preuve"
    closed = {"id": "A", "type": "balayage_reseau", "severity": "high", "open_at_end": False,
              "opened_in_period": True, "opened_at": "2026-10-01T08:00:00+00:00",
              "resolved_at": "2026-10-02T08:00:00+00:00"}
    c = ctl([closed])
    assert c["statut"] == "preuve" and c["resolus_periode"] == 1
    c = ctl([{**closed, "open_at_end": True, "resolved_at": None}])
    assert c["statut"] == "ecarts" and c["ouverts_fin_par_gravite"]["high"] == 1


def test_dates_and_attempts(config, day):
    """Début borné à la fenêtre ; « count » = tentatives, le nombre de cibles est dans le message."""
    old_target = [conn(day(0), SCANNER, "10.1.0.250", 445, state="S0"),
                  conn(day(5), SCANNER, "10.1.0.250", 445, state="S0")]
    recs = old_target + scan(day(5, 1), n=99) + scan(day(5, 2), n=99)   # 99 cibles tentées 2 fois
    [f] = scans(run(config, recs, now=day(5, 3)))
    assert f.first_seen == day(4, 3).isoformat() and f.last_seen.startswith(day(5, 2).isoformat()[:13])
    assert f.count == 100 and "100 cibles" in f.message
    from auspex.compliance import count_label
    assert count_label(f.type, f.count) == "100 cible(s)"
    assert count_label("nouveau_flux_non_declare", 3) == "3 connexion(s)"
