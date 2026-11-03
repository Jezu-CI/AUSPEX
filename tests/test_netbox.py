"""Synchronisation NetBox, testée contre un faux NetBox local."""

import importlib.util
import json
import shutil
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
def site(tmp_path, monkeypatch, nb):
    """Démo analysée + configuration pointant vers le faux NetBox."""
    work = tmp_path / "site"
    shutil.copytree(DEMO, work, ignore=shutil.ignore_patterns("state", "logs"))
    spec = importlib.util.spec_from_file_location("gen", work / "generate_logs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    gen.generate(work / "logs", days=7)
    cfg = yaml.safe_load((work / "auspex.yaml").read_text())
    cfg["netbox"] = {"url": nb.url, "token_env": "NB_TOKEN", "silent_after_days": 3}
    (work / "auspex.yaml").write_text(yaml.safe_dump(cfg, allow_unicode=True))
    monkeypatch.chdir(work)
    monkeypatch.setenv("NB_TOKEN", "secret")
    assert main(["rules", "import", "--apply"]) == 0
    assert main(["analyze", "--logs", "logs", "--now", "logs"]) == 0
    return work


def declare_site(nb):
    """Ce qu'un humain a saisi dans NetBox avant Auspex."""
    complete = {"auspex_proprietaire": "Equipe AD", "auspex_niveau_protection": "élevé",
                "auspex_fonction_metier": "Authentification", "auspex_criticite": "critique"}
    dc = nb.add("/api/dcim/devices/", {
        "name": "DC01", "description": "Contrôleur de domaine", "status": {"value": "active"},
        "platform": {"name": "Windows Server 2022"}, "primary_ip4": {"address": "10.0.0.5/24"},
        "custom_fields": complete})
    files = nb.add("/api/dcim/devices/", {
        "name": "FILES01", "description": "", "status": {"value": "active"}, "custom_fields": {}})
    ghost = nb.add("/api/dcim/devices/", {
        "name": "OLD-APP", "description": "Ancienne appli", "status": {"value": "active"},
        "primary_ip4": {"address": "10.1.0.99/16"}, "custom_fields": complete})
    web = nb.add("/api/virtualization/virtual-machines/", {
        "name": "WEB01", "description": "Intranet", "status": {"value": "active"},
        "platform": {"name": "Windows Server 2019"}, "custom_fields": complete})
    # IP du serveur de fichiers rattachée à une interface, avec une saisie humaine à préserver
    nb.add("/api/ipam/ip-addresses/", {
        "address": "10.1.0.20/16", "description": "Saisi à la main", "status": {"value": "active"},
        "assigned_object_type": "dcim.interface", "assigned_object": {"id": 1, "device": {"id": files["id"]}},
        "tags": [{"slug": "prod", "name": "prod"}], "custom_fields": {"ticket": "CHG-42"}})
    nb.add("/api/ipam/ip-addresses/", {
        "address": "10.1.0.80/16", "status": {"value": "active"},
        "assigned_object_type": "virtualization.vminterface",
        "assigned_object": {"id": 2, "virtual_machine": {"id": web["id"]}}, "tags": [], "custom_fields": {}})
    # Champ saisi à la main sur une IP : il doit survivre aux synchronisations
    nb.add("/api/extras/custom-fields/", {"name": "ticket", "object_types": ["ipam.ipaddress"]})
    return dc, files, ghost, web


def test_setup_is_idempotent(site, nb, capsys):
    assert main(["netbox", "setup"]) == 0
    assert "Simulation" in capsys.readouterr().out
    assert nb.data["/api/extras/custom-fields/"] == []  # simulation : rien d'écrit
    assert main(["netbox", "setup", "--apply"]) == 0
    names = {cf["name"] for cf in nb.data["/api/extras/custom-fields/"]}
    assert {"auspex_os", "auspex_last_seen", "auspex_criticite"} <= names
    os_cf = next(cf for cf in nb.data["/api/extras/custom-fields/"] if cf["name"] == "auspex_os")
    assert os_cf["ui_editable"] == "no" and os_cf["object_types"] == ["ipam.ipaddress"]
    crit = next(cf for cf in nb.data["/api/extras/custom-fields/"] if cf["name"] == "auspex_criticite")
    assert set(crit["object_types"]) == {"dcim.device", "virtualization.virtualmachine"}
    capsys.readouterr()
    assert main(["netbox", "setup"]) == 0
    assert "Rien à faire" in capsys.readouterr().out


def test_sync_refuses_without_setup(site, nb, capsys):
    assert main(["netbox", "sync"]) == 4
    assert "auspex apply" in capsys.readouterr().err


def test_full_sync(site, nb, capsys):
    assert main(["netbox", "setup", "--apply"]) == 0
    dc, files, ghost, web = declare_site(nb)

    # Simulation : rien n'est écrit
    before = json.dumps(nb.data, sort_keys=True)
    assert main(["netbox", "sync", "--now", "logs"]) == 0
    out = capsys.readouterr().out
    assert "Simulation uniquement" in out and "à créer" in out
    assert json.dumps(nb.data, sort_keys=True) == before

    assert main(["netbox", "sync", "--apply", "--now", "logs"]) == 0
    ips = {o["address"].split("/")[0]: o for o in nb.data["/api/ipam/ip-addresses/"]}

    # Les adresses observées inconnues sont créées, marquées, non rattachées
    new = ips["10.2.1.11"]
    assert new["address"] == "10.2.1.11/16"  # longueur du préfixe de la zone
    assert new["description"] == "Observé par Auspex" and "assigned_object" not in new
    assert new["custom_fields"]["auspex_os"].startswith("Windows")
    assert new["custom_fields"]["auspex_type"] == "Machine virtuelle"
    assert new["custom_fields"]["auspex_hostnames"] == "pc-compta-01"
    assert ips["172.16.2.20"]["custom_fields"]["auspex_model"].startswith("1769-L33ER")

    # Une IP saisie à la main est enrichie sans rien perdre
    f = ips["10.1.0.20"]
    assert f["description"] == "Saisi à la main"
    assert f["custom_fields"]["ticket"] == "CHG-42"
    assert {t["slug"] for t in f["tags"]} == {"prod", "auspex"}
    assert f["custom_fields"]["auspex_os"]

    report = json.loads((site / "state" / "netbox_report.json").read_text())
    found = {(x["type"], x["message"].split(" ")[0]) for x in report["findings"]}
    types = {x["type"] for x in report["findings"]}
    # Actifs observés non déclarés : un poste, un automate...
    assert ("actif_inconnu", "10.2.1.11") in found and ("actif_inconnu", "172.16.2.20") in found
    # ... mais pas ceux qui sont rattachés à un équipement ou une VM
    assert ("actif_inconnu", "10.0.0.5") not in found and ("actif_inconnu", "10.1.0.80") not in found
    assert ("actif_inconnu", "10.1.0.20") not in found
    # Équipement déclaré jamais vu dans une zone écoutée
    assert ("actif_silencieux", "OLD-APP") in found
    # La VM déclarée Windows est vue Ubuntu
    div = [x for x in report["findings"] if x["type"] == "identification_divergente"]
    assert len(div) == 1 and "WEB01" in div[0]["message"] and "Linux" in div[0]["message"]
    # DC01 : Windows déclaré et observé, pas de divergence ; fiche complète
    assert not [x for x in report["findings"] if "DC01" in x["message"]]
    # FILES01 : fiche incomplète au regard de NIS2 / DORA
    fiche = [x for x in report["findings"] if x["type"] == "fiche_incomplete"]
    assert len(fiche) == 1 and "FILES01" in fiche[0]["message"]
    assert "niveau de protection" in fiche[0]["message"] and "criticité" in fiche[0]["message"]
    assert types == {"actif_inconnu", "actif_silencieux", "identification_divergente", "fiche_incomplete"}

    # Les alertes de flux de l'analyse restent ouvertes (périmètres séparés)
    capsys.readouterr()
    assert main(["findings", "--json"]) == 0
    open_types = {f["type"] for f in json.loads(capsys.readouterr().out)}
    assert "flux_non_declare_persistant" in open_types and "actif_inconnu" in open_types

    # Deuxième synchronisation : rien à écrire, aucune nouvelle alerte
    capsys.readouterr()
    patches = sum(1 for m, _ in nb.requests if m in ("POST", "PATCH"))
    assert main(["netbox", "sync", "--apply", "--now", "logs"]) == 0
    out = capsys.readouterr().out
    assert "0 à créer, 0 à enrichir" in out and "0 ouverte(s)" in out
    assert sum(1 for m, _ in nb.requests if m in ("POST", "PATCH")) == patches


def test_missing_token(site, nb, monkeypatch, capsys):
    monkeypatch.delenv("NB_TOKEN")
    assert main(["netbox", "setup"]) == 4
    assert "NB_TOKEN" in capsys.readouterr().err


def test_wrong_token(site, nb, monkeypatch, capsys):
    monkeypatch.setenv("NB_TOKEN", "mauvais")
    assert main(["netbox", "setup"]) == 4
    assert "403" in capsys.readouterr().err


def test_netbox_config_rules(tmp_path):
    base = {"version": 1, "zones": [{"name": "Z", "class": "tier1", "prefixes": ["10.0.0.0/8"]}]}
    with pytest.raises(ConfigError, match="HTTPS obligatoire"):
        parse_config({**base, "netbox": {"url": "http://netbox.client.local"}}, tmp_path)
    with pytest.raises(ConfigError, match="token_env"):
        parse_config({**base, "netbox": {"url": "https://nb", "token": "x"}}, tmp_path)
    c = parse_config({**base, "netbox": {"url": "http://127.0.0.1:8000/"}}, tmp_path)
    assert c.netbox.url == "http://127.0.0.1:8000" and c.netbox.token_env == "NETBOX_TOKEN"


def test_v2_token_uses_bearer():
    from auspex.netbox import NetBoxClient
    assert NetBoxClient("https://nb", "nbt_abc.def")._auth() == "Bearer nbt_abc.def"
    assert NetBoxClient("https://nb", "0123abcd")._auth() == "Token 0123abcd"
