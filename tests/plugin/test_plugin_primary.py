"""Plugin NetBox : avec une méthode principale (LDAPS), comptes locaux réservés au brise-glace."""

import copy
import time

import pytest
import yaml

pytest.importorskip("django")

import django_harness  # noqa: E402,F401  (configure Django)
from django.contrib.auth import get_user_model  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.test import Client  # noqa: E402
from netbox.plugins.utils import SETTINGS  # noqa: E402  (doublure)

from netbox_auspex import middleware  # noqa: E402

PAGE = "/ipam/ip-addresses/"
MFA = "/plugins/auspex/mfa/"


@pytest.fixture(scope="module", autouse=True)
def database():
    call_command("migrate", verbosity=0)


@pytest.fixture(autouse=True)
def ldaps_config(tmp_path):
    from conftest import BASE_CONFIG
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"primary": "ldaps", "break_glass": {"user": "secours", "mfa": "totp"},
                   "ldaps": {"server": "ldaps://dc01.ville.local", "user_search_base": "OU=U,DC=ville,DC=local"}}
    path = tmp_path / f"auspex-{time.monotonic_ns()}.yaml"
    path.write_text(yaml.safe_dump(raw, allow_unicode=True))
    old = SETTINGS["netbox_auspex"]["config_path"]
    SETTINGS["netbox_auspex"]["config_path"] = str(path)
    middleware._cache.policy = None
    yield
    SETTINGS["netbox_auspex"]["config_path"] = old
    middleware._cache.policy = None
    get_user_model().objects.all().delete()


def local(name):
    get_user_model().objects.create_user(name, password="mot-de-passe")
    c = Client()
    assert c.login(username=name, password="mot-de-passe")
    return c


def test_forgotten_local_account_refused():
    c = local("ancien-compte")
    r = c.get(PAGE)
    assert r.status_code == 403 and b'id="local-refused"' in r.content
    assert "_auth_user_id" not in c.session          # session fermée
    assert c.get(PAGE).status_code == 200             # anonyme désormais (NetBox demandera la connexion)
    c = local("autre")
    r = c.get("/api/ipam/ip-addresses/")
    assert r.status_code == 403 and "compte de secours" in r.json()["detail"]


@pytest.mark.parametrize("name", ["secours", "admin"])
def test_break_glass_and_local_admin_still_allowed(name):
    r = local(name).get(PAGE)
    assert r.status_code == 302 and r["Location"].startswith(MFA)   # accepté, puis MFA


def test_directory_session_goes_to_mfa():
    user = get_user_model().objects.create_user("agent")
    c = Client()
    c.force_login(user, backend="netbox.authentication.LDAPBackend")
    r = c.get(PAGE)
    assert r.status_code == 302 and r["Location"].startswith(MFA)   # LDAPS : MFA exigée


def test_without_primary_local_accounts_work(tmp_path):
    from conftest import BASE_CONFIG
    path = tmp_path / "local.yaml"
    path.write_text(yaml.safe_dump(copy.deepcopy(BASE_CONFIG)))
    SETTINGS["netbox_auspex"]["config_path"] = str(path)
    middleware._cache.policy = None
    r = local("user1").get(PAGE)
    assert r.status_code == 302 and r["Location"].startswith(MFA)
