"""Tests d'intégration sur des logs produits par le VRAI Zeek.

Exécutés en CI après lecture de tools/pcapgen.py par l'image capteur.
Ignorés en local si AUSPEX_ZEEK_LOGS n'est pas défini.

Les noms de champs des parsers industriels (ICSNPP) ont été confirmés ainsi.
"""

import json
import os
from pathlib import Path

import pytest
import yaml

from auspex.cli import _rule_data, main
from auspex.config import load_config
from auspex.state import AssetStore
from auspex.zeek import read_log

LOGS = os.environ.get("AUSPEX_ZEEK_LOGS")
pytestmark = pytest.mark.skipif(not LOGS, reason="AUSPEX_ZEEK_LOGS non défini (logs Zeek réels)")

CONFIG = {
    "version": 1,
    "state_dir": "state",
    "zones": [
        {"name": "T0-AD", "class": "tier0", "prefixes": ["10.0.0.0/24"]},
        {"name": "T1-serveurs", "class": "tier1", "prefixes": ["10.1.0.0/16"]},
        {"name": "T2-postes", "class": "tier2", "prefixes": ["10.2.0.0/16"]},
        {"name": "ADMIN-bastion", "class": "admin", "prefixes": ["10.9.0.0/24"]},
        {"name": "OT-DMZ", "class": "purdue3.5", "prefixes": ["172.16.35.0/24"]},
        {"name": "OT-N2", "class": "purdue2", "prefixes": ["172.16.2.0/24"]},
    ],
}


@pytest.fixture(scope="module")
def analysis(tmp_path_factory):
    work = tmp_path_factory.mktemp("integration")
    (work / "auspex.yaml").write_text(yaml.safe_dump(CONFIG), encoding="utf-8")
    cfg = str(work / "auspex.yaml")
    assert main(["-c", cfg, "analyze", "--logs", str(Path(LOGS).resolve()), "--now", "logs", "--no-send"]) == 0
    state = work / "state"
    report = json.loads((state / "report.json").read_text())
    _, _, norm = _rule_data(load_config(cfg))
    inv = {ip: a.to_dict(norm) for ip, a in AssetStore(state).load().items()}
    return {"inv": inv, "report": report}


def logs_of(kind):
    p = Path(LOGS) / f"{kind}.log"
    return list(read_log(p)) if p.exists() else []


# --- Ce que Zeek doit produire -----------------------------------------------

def test_zeek_produced_core_logs():
    for kind in ("conn", "dhcp", "dns", "http", "ssh"):
        assert logs_of(kind), f"{kind}.log absent ou vide"


def test_conn_log_has_mac_addresses():
    recs = [r for r in logs_of("conn") if r.get("resp_l2_addr")]
    assert recs, "mac-logging inactif : orig_l2_addr / resp_l2_addr absents"


# --- Identification ----------------------------------------------------------

def test_ubuntu_server_from_ssh_banner(analysis):
    i = analysis["inv"]["10.1.0.80"]["identification"]
    assert i["os_family"]["value"] == "Linux"
    assert i["os_version"]["value"] == "Ubuntu"


def test_windows_workstation_from_http(analysis):
    a = analysis["inv"]["10.2.1.11"]
    assert a["identification"]["os_family"]["value"] == "Windows"
    assert a["identification"]["os_version"]["value"].startswith("Windows 10/11")


def test_dhcp_hostname_mac_and_vm(analysis):
    a = analysis["inv"]["10.2.1.11"]
    assert "pc-compta-01" in a["hostnames"]
    assert "00:15:5d:0a:11:01" in a["macs"]
    assert a["identification"]["device_type"]["value"] == "Machine virtuelle"


def test_domain_controller(analysis):
    roles = [r["value"] for r in analysis["inv"]["10.0.0.5"]["identification"]["role"]]
    assert "Contrôleur de domaine (Kerberos)" in roles
    assert "Serveur DNS" in roles
    assert "Serveur DHCP" in roles


def test_refused_connection_not_inventoried(analysis):
    assert "10.1.0.250" not in analysis["inv"]


def test_modbus_roles(analysis):
    plc = [r["value"] for r in analysis["inv"]["172.16.2.10"]["identification"]["role"]]
    scada = [r["value"] for r in analysis["inv"]["172.16.35.5"]["identification"]["role"]]
    assert any(v.startswith("Esclave Modbus") for v in plc)
    assert any(v.startswith("Maître Modbus") for v in scada)


def test_siemens_vendor_from_mac(analysis):
    assert analysis["inv"]["172.16.2.10"]["identification"]["vendor"]["value"] == "Siemens"


def test_rockwell_vendor_from_mac(analysis):
    assert analysis["inv"]["172.16.2.20"]["identification"]["vendor"]["value"] == "Rockwell Automation"


# --- Parsers industriels ICSNPP (champs confirmés sur Zeek réel) -------------

def test_s7comm_service_detected(analysis):
    services = {r.get("service") for r in logs_of("conn") if r.get("id.resp_p") == 102}
    assert any(s and "s7comm" in s for s in services), services
    i = analysis["inv"]["172.16.2.10"]["identification"]
    assert i["device_type"]["value"] == "Automate"
    assert "ot-s7-service" in i["vendor"]["evidence"]


def test_cip_identity(analysis):
    ident = logs_of("cip_identity")
    assert ident and ident[0]["socket_address"] == "172.16.2.20"
    i = analysis["inv"]["172.16.2.20"]["identification"]
    assert i["model"]["value"] == "1769-L33ER/A LOGIX5333ER"
    assert i["firmware"]["value"] == "32.11"
    assert i["device_type"]["value"] == "Automate"
    assert i["vendor"]["value"] == "Rockwell Automation" and i["vendor"]["confidence"] >= 0.9


# --- Conformité ---------------------------------------------------------------

def test_compliance_findings(analysis):
    findings = analysis["report"]["findings_detail"]
    keys = {(f["type"], f["src"], f["dst"], f["port"]) for f in findings}
    assert ("flux_admin_inter_tiers", "10.2.1.13", "10.0.0.5", 3389) in keys
    assert ("flux_it_vers_ot_direct", "10.1.0.30", "172.16.2.10", 502) in keys
