"""Plugin NetBox : page « Exports d'audit » et téléchargement."""

import json

import pytest

pytest.importorskip("django")

import django_harness  # noqa: E402,F401  (configure Django)
from django.contrib.auth import get_user_model  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.test import Client  # noqa: E402
from netbox.plugins.utils import SETTINGS  # noqa: E402  (doublure)

from netbox_auspex.audits import _index  # noqa: E402

NAME = "auspex-audit-nis2-20261101T0800Z.zip"
FP = "C7AB:4CB4:1C32:6597:9BA2:380F:18E6:D4D2"


@pytest.fixture(scope="module", autouse=True)
def database():
    call_command("migrate", verbosity=0)


@pytest.fixture
def audits_dir(tmp_path):
    old = SETTINGS["netbox_auspex"]["dashboard_path"]
    SETTINGS["netbox_auspex"]["dashboard_path"] = str(tmp_path / "dashboard.json")
    folder = tmp_path / "audits"
    folder.mkdir()
    (folder / NAME).write_bytes(b"PK\x05\x06" + b"\0" * 18)          # archive (vide) listée
    (folder / "auspex-audit-dora-20261101T0800Z.zip").write_bytes(b"non listee")
    (tmp_path / "secret.txt").write_text("hors du répertoire des exports")
    index = {"version": 1, "cle": FP, "exports": [{
        "fichier": NAME, "referentiel": "nis2", "titre": "NIS2", "genere_le": "2026-11-01T08:00:00+00:00",
        "periode": {"debut": "2026-10-02T08:00:00+00:00", "fin": "2026-11-01T08:00:00+00:00"},
        "synthese": {"§6.8": "ecarts", "§6.7": "ecarts", "§12.4": "non_evalue", "§3.2": "preuve"},
        "automatique": True, "taille": 22, "sha256": "ab" * 32}]}
    (folder / "index.json").write_text(json.dumps(index))
    _index.stamp = _index.data = None
    yield folder
    SETTINGS["netbox_auspex"]["dashboard_path"] = old
    _index.stamp = _index.data = None
    get_user_model().objects.all().delete()


def sso_client(user):
    c = Client()
    c.force_login(user, backend="social_core.backends.fake.FakeSSO")
    return c


@pytest.fixture
def admin():
    return get_user_model().objects.create_superuser("auditeur", password="x")


def test_page_lists_exports(audits_dir, admin):
    r = sso_client(admin).get("/plugins/auspex/audits/")
    html = r.content.decode()
    assert r.status_code == 200 and 'id="auspex-audits"' in html
    assert FP in html and "NIS2" in html and "2026-11-01 08:00" in html and "automatique" in html
    assert "2 avec écarts" in html and "1 non évalué" in html and "1 preuve" in html
    assert f"/plugins/auspex/audits/{NAME}" in html
    assert "dora" not in html                                       # présente sur disque, absente de l'index


def test_download(audits_dir, admin):
    import logging
    records = []
    handler = logging.Handler()
    handler.emit = records.append
    logger = logging.getLogger("netbox_auspex")       # ne remonte pas à la racine : écouté directement
    logger.addHandler(handler)
    try:
        r = sso_client(admin).get(f"/plugins/auspex/audits/{NAME}")
    finally:
        logger.removeHandler(handler)
    assert r.status_code == 200 and r["Content-Type"] == "application/zip"
    assert f'filename="{NAME}"' in r["Content-Disposition"] and "attachment" in r["Content-Disposition"]
    assert b"".join(r.streaming_content).startswith(b"PK")
    events = [json.loads(rec.getMessage()) for rec in records]
    assert {"event": "auspex_audit_download", "user": "auditeur", "file": NAME}.items() <= events[-1].items()


@pytest.mark.parametrize("name", ["auspex-audit-dora-20261101T0800Z.zip",   # non listée
                                  "..%2Fsecret.txt", "index.json", "secret.txt"])
def test_download_refused(audits_dir, admin, name):
    assert sso_client(admin).get(f"/plugins/auspex/audits/{name}").status_code == 404


def test_listed_but_outside_folder(audits_dir, admin):
    """Index altéré qui pointe hors du répertoire : refusé (nom non conforme)."""
    index = json.loads((audits_dir / "index.json").read_text())
    index["exports"][0]["fichier"] = "../secret.txt"
    (audits_dir / "index.json").write_text(json.dumps(index))
    _index.stamp = None
    c = sso_client(admin)
    assert c.get("/plugins/auspex/audits/..%2Fsecret.txt").status_code == 404
    assert "secret" not in c.get("/plugins/auspex/audits/").content.decode()


def test_permissions(audits_dir):
    nobody = get_user_model().objects.create_user("sans-droit-audit", password="x")
    c = sso_client(nobody)
    assert c.get("/plugins/auspex/audits/").status_code == 403
    assert c.get(f"/plugins/auspex/audits/{NAME}").status_code == 403
    r = Client().get(f"/plugins/auspex/audits/{NAME}")
    assert r.status_code == 302 and "/login/" in r["Location"]


def test_no_exports_yet(audits_dir, admin):
    (audits_dir / "index.json").unlink()
    _index.stamp = _index.data = None
    html = sso_client(admin).get("/plugins/auspex/audits/").content.decode()
    assert "Aucun export pour l'instant" in html


def test_menu():
    from netbox_auspex.navigation import menu_items
    assert "plugins:netbox_auspex:audits" in [i.link for i in menu_items]
