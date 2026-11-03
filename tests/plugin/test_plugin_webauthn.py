"""Plugin NetBox : double authentification par clé de sécurité (WebAuthn)."""

import copy
import json
import re
import sys
import time
from pathlib import Path

import pytest
import yaml

pytest.importorskip("django")

import django_harness  # noqa: E402,F401  (configure Django)
from django.contrib.auth import get_user_model  # noqa: E402
from django.core.cache import cache  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.test import Client  # noqa: E402
from netbox.plugins.utils import SETTINGS  # noqa: E402  (doublure)

from auspex import webauthn as wa  # noqa: E402
from netbox_auspex import middleware  # noqa: E402
from netbox_auspex.mfa import SESSION_OK, _access, available_methods  # noqa: E402
from netbox_auspex.models import TOTPDevice, WebAuthnKey  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from test_webauthn import ORIGIN, RP, Authenticator  # noqa: E402  (clé simulée)

MFA = "/plugins/auspex/mfa/"
SETUP = "/plugins/auspex/mfa/setup/"
KEYS = "/plugins/auspex/mfa/cles/"
PAGE = "/ipam/ip-addresses/"
BLOCK = {"methods": ["webauthn", "totp"], "webauthn": {"domaine": RP, "adresse": ORIGIN}}


@pytest.fixture(scope="module", autouse=True)
def database():
    call_command("migrate", verbosity=0)


def write_config(tmp_path, mfa_block, break_glass_mfa="totp"):
    from conftest import BASE_CONFIG
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "secours", "mfa": break_glass_mfa}, "mfa": mfa_block}
    path = tmp_path / f"auspex-{time.monotonic_ns()}.yaml"
    path.write_text(yaml.safe_dump(raw, allow_unicode=True))
    SETTINGS["netbox_auspex"]["config_path"] = str(path)
    middleware._cache.policy = None


@pytest.fixture(autouse=True)
def setup_env(tmp_path):
    old = SETTINGS["netbox_auspex"]["config_path"]
    write_config(tmp_path, BLOCK)
    cache.clear()
    yield tmp_path
    SETTINGS["netbox_auspex"]["config_path"] = old
    middleware._cache.policy = None
    WebAuthnKey.objects.all().delete()
    TOTPDevice.objects.all().delete()
    get_user_model().objects.all().delete()


def make_user(name="agent"):
    return get_user_model().objects.create_user(name, email=f"{name}@ville.fr", password="mot-de-passe")


def logged_in(name="agent"):
    c = Client()
    assert c.login(username=name, password="mot-de-passe")
    return c


def options(html: str) -> dict:
    m = re.search(r'<script id="webauthn-options" type="application/json">(.*?)</script>', html, re.S)
    assert m, "options WebAuthn absentes de la page"
    return json.loads(m.group(1))


def challenge(html: str) -> bytes:
    return wa.b64url_decode(options(html)["challenge"])


def credential(response: dict, cred_id: bytes) -> str:
    return json.dumps({"id": wa.b64url(cred_id), "type": "public-key", "response": response})


def enroll(c, key: Authenticator, name="clé bleue"):
    page = c.get(SETUP + "?method=webauthn&next=" + PAGE).content.decode()
    r = c.post(SETUP, {"next": PAGE, "nom": name, "credential": credential(key.create(challenge(page)), key.cred_id)})
    return r


def test_choice_offers_security_key_first():
    make_user()
    html = logged_in().get(SETUP).content.decode()
    assert html.index('id="choose-webauthn"') < html.index('id="choose-totp"')


def test_enroll_then_login():
    user = make_user()
    c = logged_in()
    key = Authenticator(-7)
    r = enroll(c, key)
    html = r.content.decode()
    assert r.status_code == 200 and 'id="recovery-codes"' in html and 'id="add-backup-key"' in html
    device = TOTPDevice.objects.get(user=user)
    stored = WebAuthnKey.objects.get(user=user)
    assert device.method == "webauthn" and stored.name == "clé bleue" and stored.public_key == wa.b64url(key.cose)
    assert c.session[SESSION_OK] == user.pk

    c2 = logged_in()
    page = c2.get(MFA + "?next=" + PAGE).content.decode()
    opts = options(page)
    assert opts["allowCredentials"][0]["id"] == wa.b64url(key.cred_id) and opts["rpId"] == RP
    r = c2.post(MFA, {"next": PAGE, "credential": credential(key.get(challenge(page)), key.cred_id)})
    assert r.status_code == 302 and r["Location"] == PAGE
    stored.refresh_from_db()
    assert stored.sign_count == 1 and stored.last_used is not None
    assert c2.get(PAGE).status_code == 200


def test_replay_wrong_key_and_lock():
    make_user()
    key = Authenticator()
    enroll(logged_in(), key)
    c = logged_in()
    page = c.get(MFA).content.decode()
    good = credential(key.get(challenge(page)), key.cred_id)
    assert c.post(MFA, {"credential": good}).status_code == 302
    # Rejeu de la même réponse dans une nouvelle session : défi différent
    c2 = logged_in()
    c2.get(MFA)
    r = c2.post(MFA, {"credential": good})
    assert r.status_code == 403 and "Clé refusée" in r.content.decode()
    # Une autre clé, même présentée avec l'identifiant de la bonne
    thief = Authenticator()
    for _ in range(4):
        page = c2.get(MFA).content.decode()
        assert c2.post(MFA, {"credential": credential(thief.get(challenge(page)), key.cred_id)}).status_code == 403
    page = c2.get(MFA).content.decode()
    r = c2.post(MFA, {"credential": credential(key.get(challenge(page)), key.cred_id)})
    assert r.status_code == 429                    # verrouillé après 5 échecs, même avec la bonne clé


def test_recovery_code_on_key_page():
    make_user()
    r = enroll(logged_in(), Authenticator())
    block = re.search(r'id="recovery-codes">(.*?)</ul>', r.content.decode(), re.S).group(1)
    code = re.findall(r"<li>([^<]+)</li>", block)[0]
    c = logged_in()
    assert 'id="webauthn-get"' in c.get(MFA).content.decode()
    assert c.post(MFA, {"code": code, "next": PAGE}).status_code == 302


def test_manage_keys():
    user = make_user()
    c = logged_in()
    first = Authenticator()
    enroll(c, first)
    html = c.get(KEYS).content.decode()
    assert "clé bleue" in html and "retirer" not in html          # dernière clé : non retirable
    backup = Authenticator(-257)
    r = c.post(KEYS, {"action": "ajouter", "nom": "clé de secours",
                      "credential": credential(backup.create(challenge(html)), backup.cred_id)})
    assert r.status_code == 302 and WebAuthnKey.objects.filter(user=user).count() == 2
    html = c.get(KEYS).content.decode()
    # La même clé ne s'inscrit pas deux fois
    r = c.post(KEYS, {"action": "ajouter", "credential": credential(backup.create(challenge(html)), backup.cred_id)})
    assert r.status_code == 403 and "déjà inscrite" in r.content.decode()
    k1 = WebAuthnKey.objects.get(user=user, name="clé bleue")
    assert c.post(KEYS, {"action": "retirer", "cle": k1.pk}).status_code == 302
    k2 = WebAuthnKey.objects.get(user=user)
    r = c.post(KEYS, {"action": "retirer", "cle": k2.pk})
    assert r.status_code == 403 and "dernière clé" in r.content.decode()
    # La clé de secours permet de se connecter
    c2 = logged_in()
    page = c2.get(MFA).content.decode()
    assert c2.post(MFA, {"credential": credential(backup.get(challenge(page)), backup.cred_id)}).status_code == 302


def test_keys_page_requires_completed_mfa():
    make_user()
    enroll(logged_in(), Authenticator())
    c = logged_in()                                   # mot de passe seul
    r = c.get(KEYS)
    assert r.status_code == 302 and r["Location"].startswith(MFA)
    assert Client().get(KEYS).status_code == 302


def test_another_users_key_refused():
    make_user("alice")
    make_user("bob")
    alice_key = Authenticator()
    enroll(logged_in("alice"), alice_key)
    enroll(logged_in("bob"), Authenticator())
    c = logged_in("bob")
    page = c.get(MFA).content.decode()
    r = c.post(MFA, {"credential": credential(alice_key.get(challenge(page)), alice_key.cred_id)})
    assert r.status_code == 403


def test_break_glass_with_security_key(setup_env):
    write_config(setup_env, BLOCK, break_glass_mfa="webauthn")
    secours = make_user("secours")
    assert available_methods(secours, _access()) == ["webauthn"]


def test_webauthn_removed_from_config(setup_env):
    make_user()
    enroll(logged_in(), Authenticator())
    write_config(setup_env, {"methods": ["totp"]})
    html = logged_in().get(MFA).content.decode()
    assert "plus configurées" in html and 'id="webauthn-get"' not in html


def test_reset_revokes_security_keys():
    from io import StringIO
    user = make_user()
    lost = Authenticator()
    enroll(logged_in(), lost)
    out = StringIO()
    call_command("auspex_mfa", "reset", "agent", stdout=out)
    assert "1 clé(s) de sécurité révoquée(s)" in out.getvalue()
    assert not WebAuthnKey.objects.filter(user=user).exists()
    # La clé perdue ne sert plus : nouvelle inscription obligatoire
    c = logged_in()
    r = c.get(MFA)
    assert r.status_code == 302 and r["Location"].startswith(SETUP)
