"""Synchronisation contre un VRAI NetBox (démarré par la CI).

Ignoré si AUSPEX_NETBOX_URL n'est pas défini. Le jeton ADMINISTRATEUR est lu
dans NETBOX_TOKEN : il sert à la mise en place et à déclarer le site. La
synchronisation, elle, tourne avec le seul jeton du compte de service
Librarian, dont les interdictions sont vérifiées une à une.
"""

import importlib.util
import json
import os
import secrets
import shutil
from pathlib import Path

import pytest
import yaml

from auspex.cli import main
from auspex.netbox import LIBRARIAN, OBSERVED_DESCRIPTION, NetBoxClient, NetBoxError

URL = os.environ.get("AUSPEX_NETBOX_URL")
LIB_TOKEN = secrets.token_hex(20)
pytestmark = pytest.mark.skipif(not URL, reason="AUSPEX_NETBOX_URL non défini (NetBox réel)")
DEMO = Path(__file__).resolve().parents[2] / "examples" / "demo"


@pytest.fixture(scope="module")
def client():
    return NetBoxClient(URL, os.environ["NETBOX_TOKEN"])


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    work = tmp_path_factory.mktemp("nbreal") / "site"
    shutil.copytree(DEMO, work, ignore=shutil.ignore_patterns("state", "logs"))
    spec = importlib.util.spec_from_file_location("gen", work / "generate_logs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    gen.generate(work / "logs", days=7)
    cfg = yaml.safe_load((work / "auspex.yaml").read_text())
    cfg["netbox"] = {"url": URL, "token_env": "NETBOX_TOKEN", "silent_after_days": 3}
    (work / "auspex.yaml").write_text(yaml.safe_dump(cfg, allow_unicode=True))
    c = str(work / "auspex.yaml")
    assert main(["-c", c, "rules", "import", "--apply"]) == 0
    assert main(["-c", c, "analyze", "--logs", str(work / "logs"), "--now", "logs", "--no-send"]) == 0
    return work, c


def post(client, path, body):
    return client.request("POST", path, body=body)


def declare(client):
    """Déclare un petit site via l'API officielle, comme le ferait un humain."""
    s = post(client, "/api/dcim/sites/", {"name": "Site CI", "slug": "site-ci"})
    m = post(client, "/api/dcim/manufacturers/", {"name": "Générique", "slug": "generique"})
    dt = post(client, "/api/dcim/device-types/", {"manufacturer": m["id"], "model": "Serveur", "slug": "serveur"})
    role = post(client, "/api/dcim/device-roles/", {"name": "Serveur", "slug": "serveur", "color": "2196f3"})
    win = post(client, "/api/dcim/platforms/", {"name": "Windows Server 2022", "slug": "windows-server-2022"})
    win19 = post(client, "/api/dcim/platforms/", {"name": "Windows Server 2019", "slug": "windows-server-2019"})
    complete = {"auspex_proprietaire": "Equipe AD", "auspex_niveau_protection": "élevé",
                "auspex_fonction_metier": "Authentification", "auspex_criticite": "critique"}

    def device(name, ip, platform=None, description="", cf=None):
        d = post(client, "/api/dcim/devices/", {
            "name": name, "device_type": dt["id"], "role": role["id"], "site": s["id"], "status": "active",
            "description": description, "custom_fields": cf or {},
            **({"platform": platform["id"]} if platform else {})})
        itf = post(client, "/api/dcim/interfaces/", {"device": d["id"], "name": "eth0", "type": "1000base-t"})
        a = post(client, "/api/ipam/ip-addresses/", {
            "address": ip, "status": "active", "description": "Saisi à la main",
            "assigned_object_type": "dcim.interface", "assigned_object_id": itf["id"]})
        client.request("PATCH", f"/api/dcim/devices/{d['id']}/", body={"primary_ip4": a["id"]})
        return d

    device("DC01", "10.0.0.5/24", win, "Contrôleur de domaine", complete)
    device("FILES01", "10.1.0.20/16")
    device("OLD-APP", "10.1.0.99/16", None, "Ancienne application", complete)
    vm = post(client, "/api/virtualization/virtual-machines/", {
        "name": "WEB01", "site": s["id"], "status": "active", "platform": win19["id"],
        "description": "Intranet", "custom_fields": complete})
    vitf = post(client, "/api/virtualization/interfaces/", {"virtual_machine": vm["id"], "name": "eth0"})
    post(client, "/api/ipam/ip-addresses/", {
        "address": "10.1.0.80/16", "status": "active",
        "assigned_object_type": "virtualization.vminterface", "assigned_object_id": vitf["id"]})


def test_sync_against_real_netbox(client, site, capsys, monkeypatch):
    work, cfg = site
    major, minor = client.version()
    print(f"NetBox {major}.{minor}")
    monkeypatch.setenv("LIBRARIAN_TOKEN", LIB_TOKEN)
    rc = main(["-c", cfg, "netbox", "setup", "--apply"])
    assert rc == 0, capsys.readouterr()
    assert "droits restreints vérifiés" in capsys.readouterr().out
    assert main(["-c", cfg, "netbox", "setup"]) == 0  # idempotent
    assert "Rien à faire" in capsys.readouterr().out
    declare(client)

    monkeypatch.setenv("NETBOX_TOKEN", LIB_TOKEN)  # à partir d'ici : Librarian uniquement
    assert main(["-c", cfg, "netbox", "sync", "--apply", "--now", "logs", "--no-send"]) == 0
    ips = {o["address"].split("/")[0]: o for o in client.list("/api/ipam/ip-addresses/")}

    new = ips["10.2.1.11"]
    assert new["description"] == "Observé par Auspex" and new["assigned_object"] is None
    assert new["custom_fields"]["auspex_type"] == "Machine virtuelle"
    assert new["custom_fields"]["auspex_os"].startswith("Windows")
    assert "auspex" in {t["slug"] for t in new["tags"]}
    assert ips["172.16.2.20"]["custom_fields"]["auspex_model"].startswith("1769-L33ER")

    files = ips["10.1.0.20"]
    assert files["description"] == "Saisi à la main"            # saisie humaine intacte
    assert files["assigned_object"] is not None                  # rattachement intact
    assert files["custom_fields"]["auspex_os"]                   # enrichie par Auspex

    report = json.loads((work / "state" / "netbox_report.json").read_text())
    msgs = [(f["type"], f["message"]) for f in report["findings"]]
    assert any(t == "actif_inconnu" and m.startswith("10.2.1.11 ") for t, m in msgs)
    assert not any(t == "actif_inconnu" and m.startswith(("10.0.0.5 ", "10.1.0.80 ", "10.1.0.20 ")) for t, m in msgs)
    assert any(t == "actif_silencieux" and "OLD-APP" in m for t, m in msgs)
    assert any(t == "identification_divergente" and "WEB01" in m for t, m in msgs)
    assert any(t == "fiche_incomplete" and "FILES01" in m for t, m in msgs)
    assert not any("DC01" in m for _, m in msgs)

    # Idempotence sur le vrai NetBox
    capsys.readouterr()
    assert main(["-c", cfg, "netbox", "sync", "--apply", "--now", "logs", "--no-send"]) == 0
    assert "0 à créer, 0 à enrichir" in capsys.readouterr().out


def forbidden(call) -> bool:
    try:
        call()
    except NetBoxError as exc:
        return "HTTP 403" in str(exc)
    return False


def test_librarian_least_privilege(client, site):
    """Chaque interdiction de Librarian est vérifiée sur le vrai NetBox."""
    lib = NetBoxClient(URL, LIB_TOKEN)
    ip_id = next(o["id"] for o in client.list("/api/ipam/ip-addresses/")
                 if o["address"].startswith("10.2.1.11/"))
    dc = next(d for d in client.list("/api/dcim/devices/") if d["name"] == "DC01")

    # Interdit : supprimer, toucher aux équipements, administrer, créer des champs
    assert forbidden(lambda: lib.request("DELETE", f"/api/ipam/ip-addresses/{ip_id}/"))
    assert forbidden(lambda: lib.request("PATCH", f"/api/dcim/devices/{dc['id']}/", body={"description": "x"}))
    assert forbidden(lambda: lib.request("POST", "/api/dcim/sites/", body={"name": "Pirate", "slug": "pirate"}))
    assert forbidden(lambda: lib.request("POST", "/api/extras/custom-fields/", body={
        "name": "pirate", "type": "text", "object_types": ["ipam.ipaddress"]}))
    assert forbidden(lambda: lib.request("GET", "/api/users/users/"))
    # NetBox laisse chaque utilisateur lister SES jetons : Librarian ne doit
    # voir que les siens, sans leur clé, et ne rien pouvoir faire pour autrui.
    librarian_id = client.list("/api/users/users/", {"username": LIBRARIAN})[0]["id"]
    admin_id = client.list("/api/users/users/", {"username": "admin"})[0]["id"]
    own = lib.list("/api/users/tokens/")
    assert own and all(t["user"]["id"] == librarian_id for t in own), "Librarian voit des jetons d'autrui"
    assert all(t.get("key") in (None, "") or "*" in str(t.get("key")) for t in own), "clé de jeton exposée"
    assert all(client.token not in json.dumps(t) for t in own)
    assert forbidden(lambda: lib.request("POST", "/api/users/tokens/", body={"user": admin_id}))
    # Interdit : créer une adresse qui ne porte pas la marque d'Auspex
    assert forbidden(lambda: lib.request("POST", "/api/ipam/ip-addresses/", body={
        "address": "10.250.0.1/32", "status": "active", "description": "pirate"}))
    # Permis : créer une adresse marquée, enrichir une adresse
    made = lib.request("POST", "/api/ipam/ip-addresses/", body={
        "address": "10.250.0.2/32", "status": "active", "description": OBSERVED_DESCRIPTION})
    lib.request("PATCH", f"/api/ipam/ip-addresses/{made['id']}/", body={"custom_fields": {"auspex_os": "Test"}})
    client.request("DELETE", f"/api/ipam/ip-addresses/{made['id']}/")  # nettoyage par l'administrateur


def test_changes_are_attributed_to_librarian(client, site):
    """L'historique NetBox montre qui a écrit : utile pour l'audit."""
    changes = None
    for path in ("/api/core/object-changes/", "/api/extras/object-changes/"):
        try:
            changes = client.list(path, {"user_name": LIBRARIAN})
            break
        except NetBoxError:
            continue
    assert changes, "aucune modification attribuée à Librarian dans l'historique NetBox"
    assert {c["user_name"] for c in changes} == {LIBRARIAN}
    assert any(c["changed_object_type"] == "ipam.ipaddress" for c in changes)
