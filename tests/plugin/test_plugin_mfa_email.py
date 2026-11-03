"""Plugin NetBox : double authentification par code envoyé par e-mail."""

import copy
import html
import re
import time

import pytest
import yaml

pytest.importorskip("django")

import django_harness  # noqa: E402,F401  (configure Django)
from django.contrib.auth import get_user_model  # noqa: E402
from django.core import mail  # noqa: E402
from django.core.cache import cache  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.test import Client  # noqa: E402
from netbox.plugins.utils import SETTINGS  # noqa: E402  (doublure)

from auspex import mfa as core  # noqa: E402
from netbox_auspex import middleware  # noqa: E402
from netbox_auspex.mfa import SESSION_SECRET, available_methods  # noqa: E402
from netbox_auspex.models import TOTPDevice  # noqa: E402

MFA = "/plugins/auspex/mfa/"
SETUP = "/plugins/auspex/mfa/setup/"
PAGE = "/ipam/ip-addresses/"
T0 = 1_800_000_000.0
EMAIL_BLOCK = {"methods": ["totp", "email"],
               "email": {"smtp_server": "smtp.ville.fr", "from": "auspex@ville.fr"}}


@pytest.fixture(scope="module", autouse=True)
def database():
    call_command("migrate", verbosity=0)


def write_config(tmp_path, mfa_block):
    from conftest import BASE_CONFIG
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "secours", "mfa": "totp"}, "mfa": mfa_block}
    path = tmp_path / f"auspex-{time.monotonic_ns()}.yaml"
    path.write_text(yaml.safe_dump(raw, allow_unicode=True))
    SETTINGS["netbox_auspex"]["config_path"] = str(path)
    middleware._cache.policy = None  # relecture forcée


@pytest.fixture(autouse=True)
def setup_env(tmp_path, monkeypatch):
    state = {"now": T0}
    monkeypatch.setattr(time, "time", lambda: state["now"])
    old = SETTINGS["netbox_auspex"]["config_path"]
    write_config(tmp_path, EMAIL_BLOCK)
    cache.clear()
    mail.outbox = []
    yield state
    SETTINGS["netbox_auspex"]["config_path"] = old
    middleware._cache.policy = None
    TOTPDevice.objects.all().delete()
    get_user_model().objects.all().delete()


@pytest.fixture
def clock(setup_env):
    return setup_env


def make_user(name="agent", email="jean.dupont@ville.fr"):
    return get_user_model().objects.create_user(name, email=email, password="mot-de-passe")


def logged_in(name="agent"):
    c = Client()
    assert c.login(username=name, password="mot-de-passe")
    return c


def last_code():
    return re.search(r"\b(\d{8})\b", mail.outbox[-1].body).group(1)


def enroll_by_email(clock):
    c = logged_in()
    r = c.get(SETUP + "?method=email")
    assert r.status_code == 200 and len(mail.outbox) == 1
    r = c.post(SETUP, {"code": last_code(), "next": PAGE})
    assert r.status_code == 200 and b"recovery-codes" in r.content
    return c, re.findall(r"<li>([a-z0-9]{5}-[a-z0-9]{5})</li>", r.content.decode())


# --- Choix de la méthode ------------------------------------------------------------------

def test_choice_offered(clock):
    make_user()
    r = logged_in().get(SETUP)
    assert r.status_code == 200 and b'id="choose-totp"' in r.content and b'id="choose-email"' in r.content
    assert b"j***@ville.fr" in r.content and b"jean.dupont" not in r.content
    assert not mail.outbox  # rien n'est envoyé tant que l'e-mail n'est pas choisi


def test_methods_per_user(tmp_path, clock):
    from netbox_auspex.mfa import _access
    access = _access()
    assert available_methods(make_user(), access) == ["totp", "email"]
    assert available_methods(make_user("sans-adresse", email=""), access) == ["totp"]
    assert available_methods(make_user("secours", email="s@ville.fr"), access) == ["totp"]  # brise-glace
    assert available_methods(make_user("admin", email="a@ville.fr"), access) == ["totp"]    # admin local
    write_config(tmp_path, {"methods": ["email"], "email": EMAIL_BLOCK["email"]})
    assert available_methods(get_user_model().objects.get(username="agent"), _access()) == ["email"]
    assert available_methods(get_user_model().objects.get(username="sans-adresse"), _access()) == ["totp"]
    assert available_methods(get_user_model().objects.get(username="agent"), None) == ["totp"]  # verrouillage


def test_break_glass_never_offered_email(clock):
    make_user("secours", email="s@ville.fr")
    c = logged_in("secours")
    r = c.get(SETUP + "?method=email")
    assert b'id="qr"' in r.content and not mail.outbox  # TOTP imposé


def test_email_disabled_means_totp_only(tmp_path, clock):
    write_config(tmp_path, {"methods": ["totp"]})
    make_user()
    r = logged_in().get(SETUP + "?method=email")
    assert b'id="qr"' in r.content and not mail.outbox


# --- Inscription et connexion par e-mail ------------------------------------------------------

def test_enroll_and_login_by_email(clock):
    make_user()
    enroll_by_email(clock)
    d = TOTPDevice.objects.get()
    assert d.method == "email" and d.secret == ""
    msg = mail.outbox[0]
    assert msg.to == ["jean.dupont@ville.fr"] and msg.from_email == "auspex@ville.fr"
    assert "10 minutes" in msg.body and "équipe sécurité" in msg.body
    clock["now"] += 61                   # un envoi par minute au plus
    c = logged_in()
    r = c.get(MFA)
    assert r.status_code == 200 and len(mail.outbox) == 2      # code envoyé à l'arrivée sur la page
    c.get(MFA)
    assert len(mail.outbox) == 2                               # pas de nouvel envoi à chaque affichage
    r = c.post(MFA, {"code": last_code(), "next": PAGE})
    assert r.status_code == 302 and r["Location"] == PAGE
    assert c.get(PAGE).status_code == 200


def test_email_code_single_use_and_expiry(clock):
    make_user()
    enroll_by_email(clock)
    clock["now"] += 61
    c = logged_in()
    c.get(MFA)
    code = last_code()
    assert c.post(MFA, {"code": code}).status_code == 302
    other = logged_in()
    clock["now"] += 61
    other.get(MFA)                       # nouveau code envoyé
    assert other.post(MFA, {"code": code}).status_code == 403  # l'ancien ne sert plus
    clock["now"] += 61
    third = logged_in()
    third.post(MFA, {"action": "resend"})
    late = last_code()
    clock["now"] += core.EMAIL_TTL + 1
    assert third.post(MFA, {"code": late}).status_code == 403  # expiré


def test_code_from_other_user_refused(clock):
    make_user()
    make_user("autre", email="autre@ville.fr")
    enroll_by_email(clock)
    c = logged_in("autre")
    c.get(SETUP + "?method=email")
    code_autre = last_code()
    clock["now"] += 61
    c1 = logged_in()
    c1.get(MFA)
    assert c1.post(MFA, {"code": code_autre}).status_code == 403


def test_code_burned_after_five_wrong_tries(clock):
    make_user()
    enroll_by_email(clock)
    clock["now"] += 61
    c = logged_in()
    c.get(MFA)
    good = last_code()
    for _ in range(5):
        c.post(MFA, {"code": "00000000"})
    clock["now"] += 300                  # fin du verrouillage
    assert c.post(MFA, {"code": good}).status_code == 403  # code grillé, même juste


def test_resend_rate_limit(clock):
    """Pas d'inondation de la boîte : 1 envoi par minute, 5 par heure, par utilisateur."""
    make_user()
    c = logged_in()
    c.get(SETUP + "?method=email")
    r = c.post(SETUP, {"action": "resend"})
    assert len(mail.outbox) == 1 and "nouvel envoi possible" in r.content.decode()
    other = logged_in()                  # nouvelle session : même limite
    other.post(SETUP + "?method=email", {"action": "resend"})
    assert len(mail.outbox) == 1
    for _ in range(10):
        clock["now"] += 61
        c.post(SETUP, {"action": "resend"})
    assert len(mail.outbox) == 5


def test_recovery_code_works_with_email_method(clock):
    make_user()
    _, codes = enroll_by_email(clock)
    clock["now"] += 61
    c = logged_in()
    assert c.post(MFA, {"code": codes[0]}).status_code == 302


def test_email_removed_from_config_leaves_recovery_codes(tmp_path, clock):
    make_user()
    _, codes = enroll_by_email(clock)
    write_config(tmp_path, {"methods": ["totp"]})
    clock["now"] += 61
    c = logged_in()
    r = c.get(MFA)
    assert "plus disponible" in r.content.decode() and len(mail.outbox) == 1  # aucun envoi
    assert c.post(MFA, {"code": codes[1]}).status_code == 302


def test_smtp_failure(clock, monkeypatch):
    make_user()
    import netbox_auspex.mfa as plugin_mfa

    def boom(*a, **k):
        raise ConnectionRefusedError("smtp en panne")
    monkeypatch.setattr(plugin_mfa, "_deliver", boom)
    r = logged_in().get(SETUP + "?method=email")
    assert "Envoi de l'e-mail impossible" in html.unescape(r.content.decode())  # apostrophe échappée par Django
    assert not cache.get(f"auspex_mfa_mail_code:{get_user_model().objects.get().pk}")


def test_switch_method_during_enrollment(clock):
    make_user()
    c = logged_in()
    c.get(SETUP + "?method=email")
    r = c.get("/plugins/auspex/mfa/setup/choisir/")
    assert r.status_code == 302
    r = c.get(SETUP + "?method=totp")
    assert b'id="qr"' in r.content and c.session[SESSION_SECRET]


def test_smtp_backend_verifies_certificates():
    import ssl
    from netbox_auspex.mfa import VerifiedSMTPBackend
    ctx = VerifiedSMTPBackend(host="x").ssl_context
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
