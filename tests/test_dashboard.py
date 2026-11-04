"""Instantané du tableau de bord, sur le scénario de démonstration."""

import importlib.util
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from auspex.cli import main
from auspex.config import load_config
from auspex.dashboard import SEVERITY_ORDER, build_snapshot, snapshot_path

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo"


@pytest.fixture
def site(tmp_path, monkeypatch):
    work = tmp_path / "site"
    shutil.copytree(DEMO, work, ignore=shutil.ignore_patterns("state", "logs"))
    spec = importlib.util.spec_from_file_location("gen", work / "generate_logs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    gen.generate(work / "logs", days=7)
    monkeypatch.chdir(work)
    assert main(["apply"]) == 0
    assert main(["daemon", "--logs", "logs", "--once"]) == 0
    return work


def snap(site):
    return json.loads(snapshot_path(load_config(site / "auspex.yaml").state_dir).read_text())


def test_written_by_each_cycle(site):
    s = snap(site)
    assert s["version"] == 1 and s["service"]["ok"] is True and s["service"]["records"] == 587  # dont 120 tentatives du balayage
    assert s["service"]["interval"] and s["service"]["finished"]
    # Seul le répertoire « tableau » est destiné à NetBox
    assert snapshot_path(load_config(site / "auspex.yaml").state_dir).parent.name == "tableau"


def test_findings_match_open_alerts(site):
    s = snap(site)
    assert s["findings_total"] == len(s["findings"]) > 0
    assert sum(s["findings_by_severity"].values()) == s["findings_total"]
    assert list(s["findings_by_severity"]) == list(SEVERITY_ORDER)
    rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    ranks = [rank[f["severity"]] for f in s["findings"]]
    assert ranks == sorted(ranks)                        # plus grave d'abord
    f = s["findings"][0]
    for key in ("id", "title", "severity", "scope", "opened_at", "src_zone", "dst_zone", "references"):
        assert key in f
    titles = set(s["findings_by_type"])
    assert "Flux non déclaré persistant" in titles or "Nouveau flux non déclaré" in titles


def test_inventory_summary(site):
    inv = snap(site)["inventory"]
    assert inv["total"] > 0 and sum(inv["by_zone"].values()) == inv["total"]
    assert sum(inv["by_type"].values()) == inv["total"] == sum(inv["by_os"].values())
    assert 0 <= inv["unidentified"] <= inv["total"]
    assert len(inv["new"]) <= 10


def test_zone_matrix(site):
    z = snap(site)["zones"]
    assert z["zones"] and set(z["classes"]) == set(z["zones"])
    assert z["pairs"] and all(p["src"] != p["dst"] for p in z["pairs"])
    assert all(p["src"] in z["zones"] and p["dst"] in z["zones"] for p in z["pairs"])
    assert any(p["findings"] for p in z["pairs"])        # le scénario contient des écarts entre zones


def test_new_and_silent_assets(site):
    cfg = load_config(site / "auspex.yaml")
    later = datetime.now(timezone.utc) + timedelta(days=30)
    s = build_snapshot(cfg, now=later)
    assert s["inventory"]["new_24h"] == 0 and s["inventory"]["silent_7d"] == s["inventory"]["total"]


def test_snapshot_failure_never_stops_the_service(site, capsys, monkeypatch):
    import auspex.dashboard as dash

    def boom(*a, **k):
        raise RuntimeError("disque plein")
    monkeypatch.setattr(dash, "write_snapshot", boom)
    capsys.readouterr()
    assert main(["daemon", "--logs", "logs", "--once"]) == 0
    out = capsys.readouterr().out
    assert "tableau_de_bord_erreur" in out and '"ok": true' in out


def test_no_secrets_nor_full_state(site):
    """L'instantané ne recopie ni les flux complets ni les votes d'identification."""
    raw = snapshot_path(load_config(site / "auspex.yaml").state_dir).read_text()
    assert "votes" not in raw and "evidence" not in raw and "token" not in raw.lower()



# --- Carte -----------------------------------------------------------------------------

def carte(site):
    from auspex.dashboard import map_path
    return json.loads(map_path(load_config(site / "auspex.yaml").state_dir).read_text())


def test_map_written_with_snapshot(site):
    m = carte(site)
    assert m["version"] == 1 and m["nodes"] and m["edges"] and m["zones"]
    ids = {n["id"] for n in m["nodes"]}
    assert all(e["src"] in ids and e["dst"] in ids for e in m["edges"])   # aucun lien orphelin
    names = {z["name"] for z in m["zones"]}
    assert all(n["zone"] in names for n in m["nodes"])


def test_map_zone_order_it_then_ot(site):
    classes = [z["class"] for z in carte(site)["zones"]]
    from auspex.dashboard import ZONE_ORDER
    ranks = [ZONE_ORDER.index(c) for c in classes if c in ZONE_ORDER]
    assert ranks == sorted(ranks)
    ot = [z["ot"] for z in carte(site)["zones"] if z["name"]]
    assert ot == sorted(ot)                               # IT d'abord, OT ensuite


def test_map_findings_on_edges_and_nodes(site):
    m = carte(site)
    flagged = [e for e in m["edges"] if e["findings"]]
    assert flagged and all(e == m["edges"][i] for i, e in enumerate(flagged))   # liens en écart en tête
    assert any(n["findings"] for n in m["nodes"])
    assert any(e["inter_zone"] for e in m["edges"])
    assert all(len(e["ports"]) <= 6 for e in m["edges"])


def test_map_caps(site, monkeypatch):
    import auspex.dashboard as d
    monkeypatch.setattr(d, "MAX_MAP_NODES", 3)
    m = d.build_map(load_config(site / "auspex.yaml"))
    assert len(m["nodes"]) == 3 and m["truncated"]["nodes"] > 0
    ids = {n["id"] for n in m["nodes"]}
    assert all(e["src"] in ids and e["dst"] in ids for e in m["edges"])


def test_map_inventory_findings_not_haloed(site):
    """Un écart d'inventaire (actif absent de la CMDB) ne compte pas comme un écart de flux."""
    from auspex import dashboard as d
    cfg = load_config(site / "auspex.yaml")
    m0 = d.build_map(cfg)
    ip = next(n["id"] for n in m0["nodes"] if n["findings"] == 0)
    extra = [{"id": "x", "type": "actif_inconnu", "title": "Actif observé, absent de la CMDB", "severity": "low",
              "src": ip, "scope": "inventaire"}]
    m = d.build_map(cfg, findings=d._findings(cfg.state_dir) + extra)
    node = next(n for n in m["nodes"] if n["id"] == ip)
    assert node["findings"] == 0 and node["inventory_findings"] == ["Actif observé, absent de la CMDB"]
    assert m["edges"] == m0["edges"]  # les flux ne changent pas
