"""Plugin NetBox : connexion par carte à puce (certificat transmis par le front HTTPS)."""

import copy
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import pytest
import yaml

pytest.importorskip("django")

import django_harness  # noqa: E402,F401  (configure Django)
from django.contrib.auth import BACKEND_SESSION_KEY, get_user_model  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.test import Client  # noqa: E402
from netbox.plugins.utils import SETTINGS  # noqa: E402  (doublure)

from netbox_auspex import middleware  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from test_carte import make_ca, make_user_cert, pem  # noqa: E402

CARTE = "/plugins/auspex/carte-a-puce/"
SECRET = "a1" * 32
PAGE = "/ipam/ip-addresses/"


@pytest.fixture(scope="module", autouse=True)
def database():
    call_command("migrate", verbosity=0)


@pytest.fixture
def pki(tmp_path, monkeypatch):
    ca = make_ca()
    (tmp_path / "ac.pem").write_bytes(pem(ca[1]))
    from conftest import BASE_CONFIG
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "secours", "mfa": "totp"},
                   "carte": {"adresse": "https://auspex.ville.fr:8443", "autorites": "ac.pem",
                             "identifiant": "upn_court"}}
    path = tmp_path / f"auspex-{time.monotonic_ns()}.yaml"
    path.write_text(yaml.safe_dump(raw, allow_unicode=True))
    old = SETTINGS["netbox_auspex"]["config_path"]
    SETTINGS["netbox_auspex"]["config_path"] = str(path)
    middleware._cache.policy = None
    monkeypatch.setenv("AUSPEX_PROXY_SECRET", SECRET)
    yield ca
    SETTINGS["netbox_auspex"]["config_path"] = old
    middleware._cache.policy = None
    get_user_model().objects.all().delete()


def headers(cert, secret=SECRET, verif="SUCCESS"):
    h = {"HTTP_X_AUSPEX_CARTE": quote(pem(cert).decode(), safe=""), "HTTP_X_AUSPEX_CARTE_VERIF": verif}
    if secret is not None:
        h["HTTP_X_AUSPEX_PROXY"] = secret
    return h


def test_card_login_no_mfa(pki):
    user = get_user_model().objects.create_user("JDupont")          # casse différente de l'UPN
    c = Client()
    r = c.get(CARTE + "?next=" + PAGE, **headers(make_user_cert(pki)))
    assert r.status_code == 302 and r["Location"] == PAGE
    assert c.session["_auth_user_id"] == str(user.pk)
    assert c.session[BACKEND_SESSION_KEY] == "netbox_auspex.carte.CarteBackend"
    assert c.get(PAGE).status_code == 200                              # pas de double authentification demandée


@pytest.mark.parametrize("change, reason", [
    ({"secret": None}, "hors du front"),
    ({"secret": "b2" * 32}, "hors du front"),
    ({"verif": "FAILED:certificate revoked"}, "non vérifié"),
    ({"verif": "NONE"}, "non vérifié"),
])
def test_refused_outside_front_or_unverified(pki, change, reason):
    get_user_model().objects.create_user("jdupont")
    r = Client().get(CARTE, **headers(make_user_cert(pki), **change))
    assert r.status_code == 403 and reason in r.content.decode().lower()


def test_refusals(pki):
    User = get_user_model()
    User.objects.create_user("jdupont")
    c = Client()
    other_ca = make_ca("AC pirate")
    r = c.get(CARTE, **headers(make_user_cert(other_ca)))
    assert r.status_code == 403 and "émetteur" in r.content.decode().lower()
    r = c.get(CARTE, **headers(make_user_cert(pki, upn="inconnu@ville.local")))
    assert r.status_code == 403 and "aucun compte" in r.content.decode().lower()
    for admin in ("admin@ville.local", "secours@ville.local"):
        User.objects.create_user(admin.split("@")[0])
        r = c.get(CARTE, **headers(make_user_cert(pki, upn=admin)))
        assert r.status_code == 403 and "administration local" in r.content.decode().lower()
    inactive = User.objects.create_user("ancien")
    inactive.is_active = False
    inactive.save()
    r = c.get(CARTE, **headers(make_user_cert(pki, upn="ancien@ville.local")))
    assert r.status_code == 403 and "désactivé" in r.content.decode().lower()
    r = c.get(CARTE, **headers(make_user_cert(pki, days=(-400, -1))))
    assert r.status_code == 403 and "validité" in r.content.decode().lower()
    assert "_auth_user_id" not in c.session


def test_open_redirect_refused(pki):
    get_user_model().objects.create_user("jdupont")
    for target in ("https://evil.example/", "//evil.example/x", "javascript:alert(1)"):
        r = Client().get(CARTE + "?next=" + quote(target, safe=""), **headers(make_user_cert(pki)))
        assert r.status_code == 302 and r["Location"] == "/"


def test_ambiguous_accounts_refused(pki):
    User = get_user_model()
    User.objects.create_user("jdupont")
    User.objects.create_user("JDUPONT")
    r = Client().get(CARTE, **headers(make_user_cert(pki)))
    assert r.status_code == 403 and "plusieurs comptes" in r.content.decode().lower()


def test_not_configured_is_404(tmp_path, monkeypatch):
    from conftest import BASE_CONFIG
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "secours", "mfa": "totp"}}
    path = tmp_path / "sans-carte.yaml"
    path.write_text(yaml.safe_dump(raw))
    old = SETTINGS["netbox_auspex"]["config_path"]
    SETTINGS["netbox_auspex"]["config_path"] = str(path)
    middleware._cache.policy = None
    try:
        assert Client().get(CARTE).status_code == 404
    finally:
        SETTINGS["netbox_auspex"]["config_path"] = old
        middleware._cache.policy = None


def test_card_button_address_published_in_settings():
    """Relevé en CI : NetBox ne recopie pas AUSPEX_CARTE_URL de configuration.py dans ses
    réglages ; le plugin la publie au démarrage depuis sa configuration (carte_url)."""
    from django.conf import settings
    assert settings.AUSPEX_CARTE_URL == "https://auspex.test:8443/plugins/auspex/carte-a-puce/"
