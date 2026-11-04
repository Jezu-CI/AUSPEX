"""Service en continu (auspex daemon) et vérification de santé."""

import importlib.util
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from auspex.cli import main
from auspex.config import ConfigError, parse_config
from fake_netbox import FakeNetBox

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo"


@pytest.fixture
def nb():
    fake = FakeNetBox()
    yield fake
    fake.close()


@pytest.fixture
def site(tmp_path, monkeypatch):
    work = tmp_path / "site"
    shutil.copytree(DEMO, work, ignore=shutil.ignore_patterns("state", "logs"))
    spec = importlib.util.spec_from_file_location("gen", work / "generate_logs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    gen.generate(work / "logs", days=7)
    monkeypatch.chdir(work)
    return work


def events(capsys):
    return [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.startswith("{")]


def test_daemon_once_without_netbox(site, capsys):
    assert main(["apply"]) == 0
    capsys.readouterr()
    assert main(["daemon", "--logs", "logs", "--once"]) == 0
    ev = events(capsys)
    cycle = next(e for e in ev if e["event"] == "cycle")
    # 587 enregistrements, dont les 120 tentatives du balayage de la démonstration
    assert cycle["ok"] and cycle["analyse"]["records"] == 587 and "netbox" not in cycle
    assert [e["event"] for e in ev] == ["démarrage", "cycle", "arrêt"]
    assert main(["health"]) == 0


def test_daemon_with_netbox(site, nb, capsys, monkeypatch):
    cfg = yaml.safe_load((site / "auspex.yaml").read_text())
    cfg["netbox"] = {"url": nb.url, "token_env": "NB_TOKEN"}
    (site / "auspex.yaml").write_text(yaml.safe_dump(cfg, allow_unicode=True))
    monkeypatch.setenv("NB_TOKEN", "secret")

    # NetBox pas encore préparé : le cycle échoue proprement, le service le signale
    assert main(["daemon", "--logs", "logs", "--once"]) == 1
    cycle = next(e for e in events(capsys) if e["event"] == "cycle")
    assert not cycle["ok"] and "auspex apply" in cycle["error"]
    assert main(["health"]) == 1

    assert main(["apply"]) == 0
    capsys.readouterr()
    assert main(["daemon", "--logs", "logs", "--once"]) == 0
    cycle = next(e for e in events(capsys) if e["event"] == "cycle")
    assert cycle["ok"] and cycle["netbox"]["created"] > 0
    assert nb.ip("10.2.1.11")["custom_fields"]["auspex_type"] == "Machine virtuelle"
    assert main(["health"]) == 0

    # Cycle suivant sans nouveaux logs : rien à lire, rien à écrire
    capsys.readouterr()
    assert main(["daemon", "--logs", "logs", "--once"]) == 0
    cycle = next(e for e in events(capsys) if e["event"] == "cycle")
    assert cycle["analyse"]["records"] == 0
    assert cycle["netbox"]["created"] == 0 and cycle["netbox"]["updated"] == 0


def test_invalid_config_mid_run_keeps_previous(site, capsys, monkeypatch):
    """Une erreur dans auspex.yaml en cours de route n'arrête pas le service."""
    assert main(["apply"]) == 0
    import auspex.cli as cli
    real = cli.load_config
    calls = {"n": 0}

    def flaky(path):
        calls["n"] += 1
        if calls["n"] == 2:  # 1er appel : démarrage ; 2e : début du cycle
            raise ConfigError(["zones[0].class : 'tier9' inconnue"])
        return real(path)

    monkeypatch.setattr(cli, "load_config", flaky)
    capsys.readouterr()
    assert main(["daemon", "--logs", "logs", "--once"]) == 0
    ev = events(capsys)
    assert any(e["event"] == "configuration_invalide" for e in ev)
    assert next(e for e in ev if e["event"] == "cycle")["ok"]


def test_health_detects_stale_heartbeat(site, capsys):
    assert main(["apply"]) == 0
    assert main(["daemon", "--logs", "logs", "--once", "--interval", "60"]) == 0
    hb = site / "state" / "heartbeat.json"
    st = json.loads(hb.read_text())
    st["finished"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    hb.write_text(json.dumps(st))
    capsys.readouterr()
    assert main(["health"]) == 1
    assert "bloqué" in capsys.readouterr().out


def test_missing_logs_dir_is_reported(site, capsys):
    assert main(["daemon", "--logs", "absent", "--once"]) == 1
    cycle = next(e for e in events(capsys) if e["event"] == "cycle")
    assert "absent" in cycle["error"]


def test_http_internal_netbox_requires_explicit_flag(tmp_path):
    base = {"version": 1, "zones": [{"name": "Z", "class": "tier1", "prefixes": ["10.0.0.0/8"]}]}
    with pytest.raises(ConfigError, match="allow_http_internal"):
        parse_config({**base, "netbox": {"url": "http://netbox:8080"}}, tmp_path)
    c = parse_config({**base, "netbox": {"url": "http://netbox:8080", "allow_http_internal": True}}, tmp_path)
    assert c.netbox.url == "http://netbox:8080"
    # Le drapeau ne vaut que pour un nom de service Docker, jamais pour un nom de domaine
    with pytest.raises(ConfigError, match="HTTPS obligatoire"):
        parse_config({**base, "netbox": {"url": "http://netbox.client.fr", "allow_http_internal": True}}, tmp_path)


def test_daemon_apply_suspends_analysis_until_conformant(site, nb, capsys, monkeypatch):
    """Régression CI : jeton NetBox absent → aucune analyse, aucune alerte.

    Sans ce garde-fou, le service analysait les logs sans les règles de flux et
    ouvrait des dizaines d'alertes à tort.
    """
    cfg = yaml.safe_load((site / "auspex.yaml").read_text())
    cfg["netbox"] = {"url": nb.url, "token_env": "NB_TOKEN"}
    (site / "auspex.yaml").write_text(yaml.safe_dump(cfg, allow_unicode=True))
    monkeypatch.delenv("NB_TOKEN", raising=False)

    assert main(["daemon", "--apply", "--logs", "logs", "--once"]) == 1
    cycle = next(e for e in events(capsys) if e["event"] == "cycle")
    assert not cycle["ok"] and "analyse suspendue" in cycle["error"] and "NB_TOKEN" in cycle["error"]
    assert "analyse" not in cycle
    assert not (site / "state" / "flows.json").exists()
    assert not (site / "state" / "siem.jsonl").exists()  # aucune alerte émise
    assert not (site / "state" / "flow_rules.json").exists()  # rien d'appliqué partiellement
    capsys.readouterr()
    assert main(["health"]) == 1
    assert "analyse suspendue" in capsys.readouterr().out

    # Le jeton arrive : le cycle suivant applique, analyse et synchronise
    monkeypatch.setenv("NB_TOKEN", "secret")
    assert main(["daemon", "--apply", "--logs", "logs", "--once"]) == 0
    cycle = next(e for e in events(capsys) if e["event"] == "cycle")
    assert cycle["ok"] and any(a.startswith("Règles de flux") for a in cycle["apply"])
    assert any(a.startswith("NetBox") for a in cycle["apply"])
    # Avec les règles importées, seuls les vrais écarts sont signalés (7, pas 40)
    assert cycle["analyse"]["findings"] == 7
    assert nb.ip("10.2.1.11")["custom_fields"]["auspex_type"] == "Machine virtuelle"

    # Une règle ajoutée au fichier est importée au cycle suivant, sans intervention
    with open(site / "regles-flux.csv", "a") as fh:
        fh.write("C-050,ADMIN-bastion,10.1.0.80,tcp,22,Administration serveur web,Equipe infra,\n")
    assert main(["daemon", "--apply", "--logs", "logs", "--once"]) == 0
    cycle = next(e for e in events(capsys) if e["event"] == "cycle")
    assert cycle["apply"] == ["Règles de flux : 1 ajoutée(s), 0 modifiée(s), 0 supprimée(s)"]
    assert cycle["analyse"]["events"]["resolve"] == 1  # le SSH persistant est désormais déclaré


def test_health_since_requires_a_new_cycle(site, capsys):
    """Après une mise à jour, le dernier cycle de l'ancienne version ne compte pas."""
    assert main(["apply"]) == 0
    assert main(["daemon", "--logs", "logs", "--once"]) == 0
    capsys.readouterr()
    future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    assert main(["health", "--since", future]) == 1
    assert "aucun cycle commencé depuis" in capsys.readouterr().out
    assert main(["health", "--since", past]) == 0
