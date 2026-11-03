"""Plugin NetBox : étapes Auspex de la connexion SSO (OIDC)."""

import copy
import time

import pytest
import yaml

pytest.importorskip("django")

import django_harness  # noqa: E402,F401  (configure Django)
from django.contrib.auth import get_user_model  # noqa: E402
from django.contrib.auth.models import Group  # noqa: E402
from django.core.management import call_command  # noqa: E402
from netbox.plugins.utils import SETTINGS  # noqa: E402  (doublure)
from social_core.exceptions import AuthForbidden  # noqa: E402

from netbox_auspex import middleware, pipeline  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def database():
    call_command("migrate", verbosity=0)


def configure(tmp_path, **oidc):
    from conftest import BASE_CONFIG
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"primary": "oidc", "break_glass": {"user": "secours", "mfa": "totp"},
                   "oidc": {"issuer": "https://idp.ville.local/realms/r", "client_id": "netbox", **oidc}}
    path = tmp_path / f"auspex-{time.monotonic_ns()}.yaml"
    path.write_text(yaml.safe_dump(raw, allow_unicode=True))
    SETTINGS["netbox_auspex"]["config_path"] = str(path)
    middleware._cache.policy = None


@pytest.fixture(autouse=True)
def restore():
    old = SETTINGS["netbox_auspex"]["config_path"]
    yield
    SETTINGS["netbox_auspex"]["config_path"] = old
    middleware._cache.policy = None
    get_user_model().objects.all().delete()
    Group.objects.all().delete()


class Backend:
    def __init__(self, claims):
        self.id_token = claims


def test_require_group(tmp_path):
    configure(tmp_path, require_group="auspex-utilisateurs")
    pipeline.require_group(Backend({"groups": ["autre", "auspex-utilisateurs"]}), {"username": "a"}, {})
    pipeline.require_group(Backend({}), {}, {"groups": ["/auspex-utilisateurs"]})  # chemin Keycloak
    with pytest.raises(AuthForbidden):
        pipeline.require_group(Backend({"groups": ["autre"]}), {"username": "b"}, {})
    with pytest.raises(AuthForbidden):
        pipeline.require_group(Backend({}), {"username": "c"}, {})


def test_custom_claim(tmp_path):
    configure(tmp_path, require_group="g1", groups_claim="roles")
    pipeline.require_group(Backend({"roles": "g1"}), {}, {})
    with pytest.raises(AuthForbidden):
        pipeline.require_group(Backend({"groups": ["g1"]}), {}, {})


def test_no_config_no_sso(tmp_path):
    SETTINGS["netbox_auspex"]["config_path"] = str(tmp_path / "absent.yaml")
    middleware._cache.policy = None
    with pytest.raises(AuthForbidden):
        pipeline.require_group(Backend({"groups": ["x"]}), {}, {})


def test_sync_groups_and_superuser(tmp_path):
    configure(tmp_path, superuser_group="auspex-admins")
    user = get_user_model().objects.create_user("oidc1")
    user.groups.add(Group.objects.create(name="ancien"))
    pipeline.sync_groups(Backend({"groups": ["/auspex-utilisateurs", "auspex-admins"]}), user=user, response={})
    user.refresh_from_db()
    assert sorted(user.groups.values_list("name", flat=True)) == ["auspex-admins", "auspex-utilisateurs"]
    assert user.is_superuser
    pipeline.sync_groups(Backend({"groups": ["auspex-utilisateurs"]}), user=user, response={})
    user.refresh_from_db()
    assert not user.is_superuser                          # retiré du groupe : plus administrateur
    assert list(user.groups.values_list("name", flat=True)) == ["auspex-utilisateurs"]


def test_no_superuser_group_means_never_superuser(tmp_path):
    configure(tmp_path)
    user = get_user_model().objects.create_user("oidc2", is_superuser=True)
    pipeline.sync_groups(Backend({"groups": ["admins"]}), user=user, response={})
    user.refresh_from_db()
    assert not user.is_superuser



def test_saml_groups_from_assertion_attributes(tmp_path):
    """SAML : les groupes viennent des attributs de l'assertion."""
    configure(tmp_path, require_group="auspex-utilisateurs")
    response = {"idp_name": "idp", "attributes": {"groups": ["auspex-utilisateurs", "autre"]}}
    pipeline.require_group(object(), {"username": "s1"}, response)
    with pytest.raises(AuthForbidden):
        pipeline.require_group(object(), {"username": "s2"}, {"idp_name": "idp", "attributes": {"groups": ["autre"]}})


def test_saml_login_link_gets_idp_name():
    from django.test import Client
    r = Client().get("/oauth/login/saml/?next=/ipam/")
    assert r.status_code == 302 and "idp=idp" in r["Location"] and "next=%2Fipam%2F" in r["Location"]



def test_sso_refusal_page_without_details():
    from django.test import Client
    r = Client().get("/oauth/complete/refus/")
    assert r.status_code == 403 and b'id="sso-refused"' in r.content
    assert b"AuthForbidden" not in r.content and b"Traceback" not in r.content


def test_other_exceptions_untouched():
    from django.test import Client
    with pytest.raises(ValueError):
        Client().get("/autre-erreur/")


@pytest.mark.parametrize("mode", ["ip_refused", "sso_refused", "local_refused"])
def test_refusal_pages(mode):
    """Pages de refus : mises en forme, sans le pied de page de la MFA."""
    from django.template.loader import render_to_string
    html = render_to_string("netbox_auspex/mfa.html", {"mode": mode})
    assert "Téléphone perdu" not in html and "<h1>" in html
    if mode == "ip_refused":
        assert "depuis cette adresse" in html     # repéré par les preuves CI et par l'utilisateur
