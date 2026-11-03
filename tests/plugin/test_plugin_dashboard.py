"""Plugin NetBox : widgets du tableau de bord et page des écarts."""

import json
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("django")

import django_harness  # noqa: E402,F401  (configure Django)
from django.contrib.auth import get_user_model  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.test import Client, RequestFactory  # noqa: E402
from extras.dashboard.widgets import REGISTRY  # noqa: E402  (doublure)
from netbox.plugins.utils import SETTINGS  # noqa: E402  (doublure)

from netbox_auspex import widgets  # noqa: E402
from netbox_auspex.dashboard import _snapshot  # noqa: E402


def finding(i, severity, scope="flux", **kw):
    return {"id": f"f{i}", "type": "flux_non_declare_persistant", "title": "Flux non déclaré persistant",
            "severity": severity, "message": f"SSH ouvert {i}", "src": "10.2.0.5", "dst": "10.0.0.10",
            "src_zone": "T2-postes", "dst_zone": "T0-AD", "proto": "tcp", "port": 22, "service": "ssh",
            "opened_at": f"2026-10-0{1 + i % 9}T08:00:00+00:00", "last_seen": "2026-10-31T08:00:00+00:00",
            "references": ["NIS2 art. 21"], "scope": scope, **kw}


def snapshot(now=None, **over):
    now = now or datetime.now(timezone.utc)
    findings = ([finding(i, "critical") for i in range(3)] + [finding(i, "medium") for i in range(3, 13)]
                + [finding(20, "low", scope="inventaire", src=None, dst=None, src_zone=None, dst_zone=None,
                           message="Actif observé, absent de la CMDB")])
    data = {
        "version": 1, "generated_at": now.isoformat(timespec="seconds"),
        "service": {"ok": True, "error": None, "finished": now.isoformat(), "interval": 300, "records": 467,
                    "delivery_errors": 0, "outbox_pending": 2, "netbox_sync": True},
        "findings_total": len(findings),
        "findings_by_severity": {"critical": 3, "high": 0, "medium": 10, "low": 1, "info": 0},
        "findings_by_type": {"Flux non déclaré persistant": 13, "Actif observé, absent de la CMDB": 1},
        "findings": findings,
        "inventory": {"total": 40, "new_24h": 2, "silent_7d": 3, "unidentified": 5,
                      "by_zone": {"T0-AD": 10, "OT-N2": 30}, "by_type": {"automate": 12, "serveur": 20, "non identifié": 8},
                      "by_os": {"Windows": 20, "non identifié": 20},
                      "new": [{"ip": "172.16.2.50", "zone": "OT-N2", "hostname": "plc-50", "device_type": "automate",
                               "os_family": None, "first_seen": now.isoformat()}]},
        "zones": {"zones": ["T0-AD", "T2-postes", "OT-N2"], "classes": {"T0-AD": "tier0", "T2-postes": "tier2",
                                                                       "OT-N2": "purdue2"},
                  "pairs": [{"src": "T2-postes", "dst": "T0-AD", "flows": 4, "findings": 3},
                            {"src": "T0-AD", "dst": "OT-N2", "flows": 2, "findings": 0}]},
        "rules": {"total": 11, "expired": 1, "expiring_7d": 2},
    }
    data.update(over)
    return data


@pytest.fixture(scope="module", autouse=True)
def database():
    call_command("migrate", verbosity=0)


@pytest.fixture
def snap_file(tmp_path):
    path = tmp_path / "dashboard.json"
    old = SETTINGS["netbox_auspex"]["dashboard_path"]
    SETTINGS["netbox_auspex"]["dashboard_path"] = str(path)
    _snapshot.stamp = _snapshot.data = None

    def write(data):
        path.write_text(json.dumps(data))
        _snapshot.stamp = None  # relecture forcée (deux écritures dans la même milliseconde)
        return path
    yield write
    SETTINGS["netbox_auspex"]["dashboard_path"] = old
    _snapshot.stamp = _snapshot.data = None
    get_user_model().objects.all().delete()


def request_for(user):
    r = RequestFactory().get("/")
    r.user = user
    return r


@pytest.fixture
def admin():
    return get_user_model().objects.create_superuser("chef", password="x")


def test_widgets_registered():
    for name in ("FindingsWidget", "ServiceWidget", "InventoryWidget", "ZoneMatrixWidget"):
        assert f"netbox_auspex.{name}" in REGISTRY
        assert REGISTRY[f"netbox_auspex.{name}"].default_title.startswith("Auspex — ")


def test_findings_widget(snap_file, admin):
    snap_file(snapshot())
    html = widgets.FindingsWidget(config={"max_items": 5}).render(request_for(admin))
    assert "critique : 3" in html and "moyenne : 10" in html
    assert html.count("<tr>") == 5 and "(9 de plus)" in html
    assert "10.2.0.5 (T2-postes) → 10.0.0.10 (T0-AD)" in html and "tcp/22 ssh" in html
    html = widgets.FindingsWidget(config={"severity_min": "critical"}).render(request_for(admin))
    assert html.count("<tr>") == 3
    html = widgets.FindingsWidget(config={"scope": "inventaire"}).render(request_for(admin))
    assert html.count("<tr>") == 1 and "absent de la CMDB" in html


def test_service_widget(snap_file, admin):
    snap_file(snapshot())
    html = widgets.ServiceWidget().render(request_for(admin))
    assert "en service" in html and "467" in html and "1 expirée(s)" in html and "2 expire(nt)" in html
    snap_file(snapshot(service={"ok": False, "error": "NetBox injoignable", "interval": 300}))
    html = widgets.ServiceWidget().render(request_for(admin))
    assert "en erreur" in html and "NetBox injoignable" in html
    # Attribution exigée par NOTICE (AGPL v3, article 7 b), même sans données
    assert "Basé sur Auspex, projet conçu par Yann Mathon" in html
    assert 'href="https://github.com/Jezu-CI/AUSPEX"' in html


def test_inventory_widget(snap_file, admin):
    snap_file(snapshot())
    html = widgets.InventoryWidget().render(request_for(admin))
    assert ">40<" in html and "automate" in html and "plc-50" in html
    html = widgets.InventoryWidget(config={"breakdown": "by_os"}).render(request_for(admin))
    assert "Windows" in html and "automate" in html.split("Derniers apparus")[1]  # liste des nouveaux


def test_zone_matrix_widget(snap_file, admin):
    snap_file(snapshot())
    html = widgets.ZoneMatrixWidget().render(request_for(admin))
    assert 'id="auspex-zone-matrix"' in html and "bg-red-lt" in html and "4 flux, 3 écart(s)" in html


def test_stale_and_missing_data(snap_file, admin):
    html = widgets.ServiceWidget().render(request_for(admin))
    assert "Aucune donnée du service Auspex" in html
    snap_file(snapshot(now=datetime.now(timezone.utc) - timedelta(hours=2)))
    html = widgets.ServiceWidget().render(request_for(admin))
    assert "ne les met plus à jour" in html


def test_permission_required(snap_file):
    snap_file(snapshot())
    nobody = get_user_model().objects.create_user("sans-droit", password="x")
    html = widgets.FindingsWidget().render(request_for(nobody))
    assert "Lecture de l'inventaire nécessaire" in html and "10.2.0.5" not in html


def test_html_injection_escaped(snap_file, admin):
    snap_file(snapshot(findings=[
        finding(1, "critical", src="<img src=x onerror=alert(1)>"),                       # affiché : le chemin
        finding(2, "high", src=None, dst=None, message="<script>alert(1)</script>"),    # affiché : le message
    ]))
    html = widgets.FindingsWidget().render(request_for(admin))
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html and "&lt;img" in html
    page = sso_client(admin).get("/plugins/auspex/ecarts/").content.decode()
    assert "<script>alert" not in page and "<img src=x" not in page and "&lt;script&gt;" in page


def sso_client(user):
    c = Client()
    c.force_login(user, backend="social_core.backends.fake.FakeSSO")  # pas de MFA Auspex à passer
    return c


def test_findings_page_and_filters(snap_file, admin):
    snap_file(snapshot())
    c = sso_client(admin)
    r = c.get("/plugins/auspex/ecarts/")
    assert r.status_code == 200 and r.content.decode().count("<tr>") == 1 + 14
    assert "Basé sur Auspex, projet conçu par Yann Mathon" in r.content.decode()
    r = c.get("/plugins/auspex/ecarts/?gravite=critical")
    assert r.content.decode().count("<tr>") == 1 + 3
    r = c.get("/plugins/auspex/ecarts/?type=inventaire")
    assert r.content.decode().count("<tr>") == 1 + 1
    r = c.get("/plugins/auspex/ecarts/?zone=T0-AD&q=SSH ouvert 12")
    assert r.content.decode().count("<tr>") == 1 + 1


def test_findings_page_permissions(snap_file):
    snap_file(snapshot())
    nobody = get_user_model().objects.create_user("sans-droit2", password="x")
    assert sso_client(nobody).get("/plugins/auspex/ecarts/").status_code == 403
    r = Client().get("/plugins/auspex/ecarts/")
    assert r.status_code == 302 and "/login/" in r["Location"]


# --- Carte interactive -------------------------------------------------------------------------

def map_data():
    return {"version": 1, "generated_at": "2026-10-31T08:00:00+00:00",
            "zones": [{"name": "T2-postes", "class": "tier2", "ot": False, "assets": 1},
                      {"name": "T0-AD", "class": "tier0", "ot": False, "assets": 1}],
            "nodes": [{"id": "10.2.0.5", "zone": "T2-postes", "hostname": "<img src=x onerror=alert(1)>",
                       "findings": 1},
                      {"id": "10.0.0.10", "zone": "T0-AD", "hostname": "dc-01", "findings": 1}],
            "edges": [{"src": "10.2.0.5", "dst": "10.0.0.10", "count": 4, "ports": ["tcp/22 ssh"],
                       "findings": ["Flux non déclaré persistant"], "inter_zone": True}],
            "truncated": {"nodes": False, "edges": False}}


@pytest.fixture
def map_file(snap_file):
    from netbox_auspex.dashboard import _map
    path = snap_file(snapshot()).parent / "carte.json"
    _map.stamp = _map.data = None

    def write(data):
        path.write_text(json.dumps(data))
        _map.stamp = None
        return path
    yield write
    _map.stamp = _map.data = None


def test_map_page(map_file, admin):
    page = sso_client(admin).get("/plugins/auspex/carte/")
    assert page.status_code == 200
    html = page.content.decode()
    assert 'data-src="/plugins/auspex/carte/donnees/"' in html
    assert "netbox_auspex/carte.js" in html and "netbox_auspex/carte.css" in html
    assert 'id="auspex-map-issues"' in html


def test_map_data(map_file, admin):
    c = sso_client(admin)
    r = c.get("/plugins/auspex/carte/donnees/")
    assert r.status_code == 404 and "pas encore produite" in r.json()["detail"]
    map_file(map_data())
    r = c.get("/plugins/auspex/carte/donnees/")
    assert r.status_code == 200 and r["Content-Type"].startswith("application/json")
    data = r.json()
    assert [n["id"] for n in data["nodes"]] == ["10.2.0.5", "10.0.0.10"] and data["edges"][0]["count"] == 4
    # Le nom d'hôte est une donnée observée sur le réseau : transmis tel quel en JSON,
    # jamais interprété (la carte l'affiche par textContent).
    assert data["nodes"][0]["hostname"] == "<img src=x onerror=alert(1)>"


def test_map_permissions(map_file):
    map_file(map_data())
    nobody = get_user_model().objects.create_user("sans-droit3", password="x")
    c = sso_client(nobody)
    assert c.get("/plugins/auspex/carte/").status_code == 403
    r = c.get("/plugins/auspex/carte/donnees/")
    assert r.status_code == 403 and "10.2.0.5" not in r.content.decode()
    anon = Client()
    r = anon.get("/plugins/auspex/carte/")
    assert r.status_code == 302 and "/login/" in r["Location"]
    r = anon.get("/plugins/auspex/carte/donnees/")
    assert r.status_code in (302, 403) and "10.2.0.5" not in r.content.decode()


def test_map_menu():
    from netbox_auspex.navigation import menu_items
    links = [item.link for item in menu_items]
    assert "plugins:netbox_auspex:map" in links
