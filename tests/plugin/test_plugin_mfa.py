"""Plugin NetBox : double authentification, avec un vrai Django."""

import io
import re
import time

import pytest

pytest.importorskip("django")

import django_harness  # noqa: E402,F401  (configure Django)
from django.contrib.auth import get_user_model  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.test import Client  # noqa: E402

from auspex import mfa as core  # noqa: E402
from netbox_auspex.mfa import SESSION_SECRET  # noqa: E402
from netbox_auspex.models import TOTPDevice  # noqa: E402

MFA = "/plugins/auspex/mfa/"
SETUP = "/plugins/auspex/mfa/setup/"
PAGE = "/ipam/ip-addresses/"
API = "/api/ipam/ip-addresses/"
T0 = 1_800_000_000.0


@pytest.fixture(scope="module", autouse=True)
def database():
    call_command("migrate", verbosity=0)


@pytest.fixture(autouse=True)
def clean():
    yield
    TOTPDevice.objects.all().delete()
    get_user_model().objects.all().delete()


@pytest.fixture
def clock(monkeypatch):
    """Horloge contrôlée : codes TOTP déterministes."""
    state = {"now": T0}
    monkeypatch.setattr(time, "time", lambda: state["now"])
    return state


@pytest.fixture
def user():
    return get_user_model().objects.create_user("user1", password="mot-de-passe")


def logged_in(username="user1"):
    c = Client()
    assert c.login(username=username, password="mot-de-passe")  # backend local : MFA exigée
    return c


def enroll(clock):
    c = logged_in()
    c.get(SETUP)
    secret = c.session[SESSION_SECRET]
    r = c.post(SETUP, {"code": core.totp(secret, clock["now"]), "next": PAGE})
    assert r.status_code == 200, r.content
    codes = re.findall(r"<li>([a-z0-9]{5}-[a-z0-9]{5})</li>", r.content.decode())
    return c, secret, codes


# --- La migration correspond au modèle ----------------------------------------------

def test_migration_matches_model():
    out = io.StringIO()
    try:
        call_command("makemigrations", "netbox_auspex", "--check", "--dry-run", stdout=out)
    except SystemExit as exc:  # changements non reflétés dans la migration
        pytest.fail(f"migration à régénérer : {out.getvalue()} ({exc})")


# --- Tant que la MFA n'est pas passée : rien ---------------------------------------------

def test_pending_session_is_blocked(user):
    c = logged_in()
    r = c.get(PAGE)
    assert r.status_code == 302 and r["Location"].startswith(MFA) and "next=%2Fipam" in r["Location"]
    r = c.get(API)
    assert r.status_code == 403 and "Double authentification" in r.json()["detail"]
    r = c.post(PAGE, {"x": 1})
    assert r.status_code == 302
    # Un faux en-tête de jeton ne contourne pas la MFA de la session.
    r = c.get(PAGE, HTTP_AUTHORIZATION="Token 0123456789abcdef")
    assert r.status_code == 302 and r["Location"].startswith(MFA)


def test_logout_allowed_while_pending(user):
    c = logged_in()
    assert c.get("/logout/").status_code == 302
    assert c.get(PAGE).status_code == 200  # déconnecté : anonyme, plus rien à demander


def test_anonymous_untouched():
    assert Client().get(PAGE).status_code == 200  # NetBox exige lui-même la connexion


def test_sso_session_not_asked_for_mfa(user):
    c = Client()
    c.force_login(user, backend="social_core.backends.fake.FakeSSO")
    assert c.get(PAGE).status_code == 200


# --- Inscription ----------------------------------------------------------------------

def test_first_login_goes_to_enrollment(user):
    c = logged_in()
    r = c.get(MFA + "?next=" + PAGE)
    assert r.status_code == 302 and r["Location"].startswith(SETUP)
    r = c.get(SETUP)
    assert r.status_code == 200 and b"otpauth://totp/Auspex" in r.content
    assert b'<div class="qr" id="qr"><svg' in r.content  # QR code affiché, non échappé


def test_enrollment(user, clock):
    c = logged_in()
    c.get(SETUP)
    secret = c.session[SESSION_SECRET]
    assert c.post(SETUP, {"code": "000000"}).status_code == 403
    assert not TOTPDevice.objects.exists()
    before = c.cookies["sessionid"].value
    r = c.post(SETUP, {"code": core.totp(secret, clock["now"]), "next": PAGE})
    codes = re.findall(r"<li>([a-z0-9]{5}-[a-z0-9]{5})</li>", r.content.decode())
    assert len(codes) == 10
    device = TOTPDevice.objects.get()
    assert device.secret == secret and device.last_counter == core.counter_at(clock["now"])
    assert all(code not in str(device.recovery_hashes) for code in codes)
    assert c.cookies["sessionid"].value != before        # nouvel identifiant de session
    assert c.get(PAGE).status_code == 200
    assert SESSION_SECRET not in c.session


def test_no_reenrollment_once_enrolled(user, clock):
    enroll(clock)
    c = logged_in()  # mot de passe seul (volé ?) : pas de nouvelle inscription possible
    r = c.get(SETUP)
    assert r.status_code == 302 and r["Location"].startswith(MFA)
    assert c.post(SETUP, {"code": "123456"}).status_code == 302
    assert TOTPDevice.objects.count() == 1


# --- Vérification ------------------------------------------------------------------------

def test_verify_replay_and_next_code(user, clock):
    _, secret, _ = enroll(clock)
    c = logged_in()
    r = c.post(MFA, {"code": core.totp(secret, clock["now"]), "next": PAGE})
    assert r.status_code == 403                            # code de l'inscription : rejeu
    clock["now"] += 30
    r = c.post(MFA, {"code": core.totp(secret, clock["now"]), "next": PAGE})
    assert r.status_code == 302 and r["Location"] == PAGE
    assert c.get(PAGE).status_code == 200
    other = logged_in()
    assert other.post(MFA, {"code": core.totp(secret, clock["now"])}).status_code == 403  # rejeu


def test_recovery_code_single_use(user, clock):
    _, _, codes = enroll(clock)
    c = logged_in()
    assert c.post(MFA, {"code": codes[0].upper()}).status_code == 302
    assert c.get(PAGE).status_code == 200
    assert len(TOTPDevice.objects.get().recovery_hashes) == 9
    assert logged_in().post(MFA, {"code": codes[0]}).status_code == 403


def test_lockout_and_escalation(user, clock):
    _, secret, _ = enroll(clock)
    c = logged_in()
    for _ in range(5):
        assert c.post(MFA, {"code": "000000"}).status_code == 403
    clock["now"] += 30
    good = core.totp(secret, clock["now"])
    r = c.post(MFA, {"code": good})
    assert r.status_code == 429                            # verrouillé : même le bon code est refusé
    assert c.get(PAGE).status_code == 302
    clock["now"] += 300
    assert c.post(MFA, {"code": core.totp(secret, clock["now"])}).status_code == 302
    d = TOTPDevice.objects.get()
    assert d.failures == 0 and d.locks == 0 and d.locked_until is None


def test_open_redirect_refused(user, clock):
    _, secret, _ = enroll(clock)
    c = logged_in()
    clock["now"] += 30
    r = c.post(MFA, {"code": core.totp(secret, clock["now"]), "next": "https://pirate.example/"})
    assert r.status_code == 302 and r["Location"] == "/"


def test_mfa_is_per_user(user, clock):
    """La session MFA d'un utilisateur ne vaut pas pour un autre compte."""
    c, _, _ = enroll(clock)
    get_user_model().objects.create_user("user2", password="mot-de-passe")
    assert c.login(username="user2", password="mot-de-passe")
    assert c.get(PAGE).status_code == 302


def test_csrf_enforced(user, clock):
    enroll(clock)
    c = Client(enforce_csrf_checks=True)
    assert c.login(username="user1", password="mot-de-passe")
    assert c.post(MFA, {"code": "123456"}).status_code == 403
    assert TOTPDevice.objects.get().failures == 0          # rejeté avant toute évaluation


# --- Administration -----------------------------------------------------------------------

def test_management_command(user, clock):
    enroll(clock)
    c = logged_in()
    for _ in range(5):
        c.post(MFA, {"code": "000000"})
    out = io.StringIO()
    call_command("auspex_mfa", "status", stdout=out)
    assert "user1" in out.getvalue() and "verrouillé" in out.getvalue()
    call_command("auspex_mfa", "unlock", "user1", stdout=io.StringIO())
    assert TOTPDevice.objects.get().locked_until is None
    call_command("auspex_mfa", "reset", "user1", stdout=io.StringIO())
    assert not TOTPDevice.objects.exists()
    r = logged_in().get(MFA)
    assert r.status_code == 302 and r["Location"].startswith(SETUP)  # nouvelle inscription
    from django.core.management.base import CommandError
    with pytest.raises(CommandError):
        call_command("auspex_mfa", "reset", "inconnu")
