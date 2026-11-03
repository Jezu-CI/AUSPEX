"""Test de bout en bout de la CLI sur le scénario de démonstration."""

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from auspex.cli import main

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo"


@pytest.fixture
def demo(tmp_path, monkeypatch):
    work = tmp_path / "demo"
    shutil.copytree(DEMO, work, ignore=shutil.ignore_patterns("state", "logs"))
    spec = importlib.util.spec_from_file_location("gen", work / "generate_logs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    gen.generate(work / "logs", days=7)
    monkeypatch.chdir(work)
    return work


def cli(*args, capsys=None):
    code = main(list(args))
    out = capsys.readouterr().out if capsys else ""
    return code, out


def findings(capsys):
    code, out = cli("findings", "--json", capsys=capsys)
    return {(f["type"], f["src"], f["dst"], f["port"]): f for f in json.loads(out)}


def test_full_scenario(demo, capsys):
    assert cli("validate", capsys=capsys)[0] == 0

    code, out = cli("rules", "import", capsys=capsys)
    assert code == 0 and "Simulation uniquement" in out
    assert not (demo / "state" / "flow_rules.json").exists()
    assert cli("rules", "import", "--apply", capsys=capsys)[0] == 0

    code, out = cli("analyze", "--logs", "logs", "--now", "logs", capsys=capsys)
    assert code == 0, out
    f = findings(capsys)

    # Le SSH de dépannage oublié : persistant, du bastion vers le serveur web
    ssh = f[("flux_non_declare_persistant", "10.9.0.4", "10.1.0.80", 22)]
    assert ssh["severity"] == "high" and "6 jours" in ssh["message"]
    # RDP d'un poste vers le contrôleur de domaine : violation du modèle en tiers
    assert f[("flux_admin_inter_tiers", "10.2.1.13", "10.0.0.5", 3389)]["severity"] == "critical"
    # Serveur applicatif qui interroge l'automate en direct
    assert ("flux_it_vers_ot_direct", "10.1.0.30", "172.16.2.10", 502) in f
    # Accès prestataire couvert par une règle expirée
    exp = f[("regle_expiree_utilisee", "10.9.0.7", "172.16.2.10", 22)]
    assert exp["rule_ids"] == ["C-031"]
    # Aucun faux positif sur le trafic AD normal (SMB, RPC, Kerberos...)
    assert not [k for k in f if k[0] == "flux_admin_inter_tiers" and k[3] in (445, 135)]
    # La supervision depuis la DMZ OT est déclarée : pas d'écart
    assert not [k for k in f if k[1] == "172.16.35.5"]

    # Les alertes sont parties vers la sortie « SIEM » (fichier ici)
    sent = [json.loads(l) for l in (demo / "state" / "siem.jsonl").read_text().splitlines()]
    assert {e["activity"] for e in sent} == {"open"}
    assert len(sent) == len(f)

    # Inventaire identifié
    code, out = cli("assets", "--json", capsys=capsys)
    inv = {a["ip"]: a["identification"] for a in json.loads(out)}
    assert inv["10.0.0.5"]["os_family"]["value"] == "Windows"
    assert inv["10.0.0.5"]["role"][0]["value"].startswith("Contrôleur de domaine")
    assert inv["10.1.0.80"]["os_version"]["value"] == "Ubuntu"
    assert inv["10.2.1.11"]["device_type"]["value"] == "Machine virtuelle"
    assert inv["172.16.2.10"]["vendor"]["value"] == "Siemens"
    assert inv["172.16.2.20"]["model"]["value"].startswith("1769-L33ER")
    assert inv["172.16.2.20"]["vendor"]["value"] == "Rockwell Automation"
    assert inv["172.16.2.20"]["vendor"]["confidence"] >= 0.9
    assert inv["172.16.2.10"]["device_type"]["value"] == "Automate"
    assert inv["172.16.2.10"]["device_type"]["confidence"] >= 0.8
    assert "10.1.0.250" not in inv  # cible d'un scan sans réponse

    # Deuxième passage sur les mêmes logs : aucune nouvelle alerte (pas de bruit)
    code, out = cli("analyze", "--logs", "logs", "--now", "logs", "--json", capsys=capsys)
    assert json.loads(out)["events"] == {"open": 0, "update": 0, "resolve": 0}

    # On déclare le SSH de dépannage : l'alerte se résout au passage suivant
    rules = (demo / "regles-flux.csv").read_text()
    (demo / "regles-flux.csv").write_text(
        rules + "C-050,ADMIN-bastion,10.1.0.80,tcp,22,Administration serveur web,Equipe infra,\n")
    assert cli("rules", "import", "--apply", capsys=capsys)[0] == 0
    code, out = cli("analyze", "--logs", "logs", "--now", "logs", "--json", capsys=capsys)
    assert json.loads(out)["events"]["resolve"] == 1
    assert ("flux_non_declare_persistant", "10.9.0.4", "10.1.0.80", 22) not in findings(capsys)


def test_invalid_rules_file_blocks_import(demo, capsys):
    (demo / "regles-flux.csv").write_text("id,source,destination,protocole,port\nX,Nulle-part,T0-AD,tcp,88\n")
    code, out = cli("rules", "import", "--apply", capsys=capsys)
    assert code == 1 and "Nulle-part" in out
    assert not (demo / "state" / "flow_rules.json").exists()


def test_invalid_config_exit_code(demo, capsys):
    (demo / "auspex.yaml").write_text("version: 9\n")
    assert main(["validate"]) == 1
    assert "version" in capsys.readouterr().err


def test_alerts_test_command(demo, capsys):
    code, out = cli("alerts", "test", capsys=capsys)
    assert code == 0 and "OK" in out
    sent = json.loads((demo / "state" / "siem.jsonl").read_text().splitlines()[-1])
    assert sent["id"] == "AUSPEX-TEST"
