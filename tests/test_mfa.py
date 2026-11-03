"""Double authentification TOTP (cœur, sans Django)."""

import base64

import pytest

from auspex import mfa

# Vecteurs officiels de la RFC 6238 (annexe B), SHA-1, secret ASCII
# « 12345678901234567890 ». La RFC donne 8 chiffres ; nos codes de 6 chiffres
# en sont les 6 derniers.
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()
RFC_VECTORS = [
    (59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130"),
]


@pytest.mark.parametrize("t,expected", RFC_VECTORS)
def test_rfc6238_vectors(t, expected):
    key = mfa._key(RFC_SECRET)
    assert mfa.hotp(key, t // 30, digits=8) == expected
    assert mfa.totp(RFC_SECRET, t) == expected[-6:]


def test_rfc4226_vectors():
    key = b"12345678901234567890"
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    assert [mfa.hotp(key, c) for c in range(10)] == expected


def test_secret_is_160_bits_and_accepted_with_spaces():
    s = mfa.new_secret()
    assert len(mfa._key(s)) == 20 and s != mfa.new_secret()
    assert mfa.totp(mfa.grouped(s), 1000) == mfa.totp(s, 1000)  # saisi par groupes de 4


# --- Vérification ----------------------------------------------------------------

NOW = 1_800_000_000.0


def test_verify_current_and_clock_skew():
    s = mfa.new_secret()
    c = mfa.counter_at(NOW)
    assert mfa.verify(s, mfa.totp(s, NOW), None, NOW) == c
    assert mfa.verify(s, mfa.totp(s, NOW - 30), None, NOW) == c - 1   # téléphone en retard
    assert mfa.verify(s, mfa.totp(s, NOW + 30), None, NOW) == c + 1   # en avance
    assert mfa.verify(s, mfa.totp(s, NOW - 60), None, NOW) is None    # trop ancien
    assert mfa.verify(s, mfa.totp(s, NOW + 60), None, NOW) is None


def test_replay_refused():
    s = mfa.new_secret()
    code = mfa.totp(s, NOW)
    used = mfa.verify(s, code, None, NOW)
    assert mfa.verify(s, code, used, NOW) is None             # même code, même période
    assert mfa.verify(s, code, used, NOW + 25) is None        # même code, un peu plus tard
    assert mfa.verify(s, mfa.totp(s, NOW - 30), used, NOW) is None  # code plus ancien
    assert mfa.verify(s, mfa.totp(s, NOW + 30), used, NOW + 30) == used + 1  # code suivant : oui


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", None, "12 34 5"])
def test_malformed_codes(bad):
    assert mfa.verify(mfa.new_secret(), bad, None, NOW) is None


def test_wrong_secret_or_broken_secret():
    s = mfa.new_secret()
    assert mfa.verify(mfa.new_secret(), mfa.totp(s, NOW), None, NOW) is None
    assert mfa.verify("pas du base32 !", "123456", None, NOW) is None


def test_otpauth_uri():
    uri = mfa.otpauth_uri("JBSWY3DPEHPK3PXP", "user 1")
    assert uri.startswith("otpauth://totp/Auspex%3Auser%201?")
    assert "secret=JBSWY3DPEHPK3PXP" in uri and "issuer=Auspex" in uri and "digits=6" in uri


# --- Codes de secours --------------------------------------------------------------

def test_recovery_codes_single_use():
    codes, hashes = mfa.new_recovery_codes()
    assert len(codes) == len(set(codes)) == 10
    assert all(c not in "".join(hashes) for c in codes)  # jamais conservés en clair
    left = mfa.use_recovery_code(codes[3], hashes)
    assert left is not None and len(left) == 9
    assert mfa.use_recovery_code(codes[3], left) is None   # déjà utilisé
    assert mfa.use_recovery_code(codes[4].upper().replace("-", " "), left) is not None  # saisie souple


@pytest.mark.parametrize("bad", ["", "abcde-fghjk", "x" * 10, None])
def test_recovery_code_wrong(bad):
    _, hashes = mfa.new_recovery_codes()
    assert mfa.use_recovery_code(bad, hashes) is None


# --- Verrouillage ---------------------------------------------------------------------

def test_lock_after_five_failures_and_escalation():
    failures, locks, until = 0, 0, None
    for _ in range(4):
        failures, locks, until = mfa.after_failure(failures, locks, NOW)
        assert until is None
    failures, locks, until = mfa.after_failure(failures, locks, NOW)
    assert (failures, locks, until) == (0, 1, NOW + 300)
    assert mfa.locked(until, NOW + 299) and not mfa.locked(until, NOW + 300)
    assert not mfa.locked(None, NOW)
    durations = []
    for _ in range(12):  # les verrouillages suivants doublent, plafonnés à 24 h
        for _ in range(5):
            failures, locks, until = mfa.after_failure(failures, locks, NOW)
        durations.append(until - NOW)
    assert durations[:3] == [600, 1200, 2400] and max(durations) == 86400


# --- Quelles connexions exigent la MFA -------------------------------------------------

@pytest.mark.parametrize("backend,required", [
    ("netbox.authentication.ObjectPermissionBackend", True),   # compte local NetBox
    ("netbox.authentication.LDAPBackend", True),               # LDAPS
    ("django.contrib.auth.backends.ModelBackend", True),
    ("social_core.backends.azuread.AzureADOAuth2", False),     # OIDC : MFA du fournisseur
    ("social_core.backends.saml.SAMLAuth", False),
    ("netbox.authentication.RemoteUserBackend", False),
    ("mon.backend.inconnu", True),                             # en cas de doute : MFA
    (None, True), ("", True),
    ("social_core_backends_faux", True),
])
def test_mfa_required(backend, required):
    assert mfa.mfa_required(backend) is required


# --- Configuration -------------------------------------------------------------------

@pytest.mark.parametrize("kind,message", [("webauthn", "demande la section auth.mfa.webauthn"),
                                          ("sms", "'totp' ou 'webauthn' attendu"),
                                          (None, "'totp' ou 'webauthn' attendu")])
def test_break_glass_mfa_kind(tmp_path, kind, message):
    import copy
    from auspex.config import ConfigError, parse_config
    from conftest import BASE_CONFIG
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "admin", "mfa": kind}}
    with pytest.raises(ConfigError, match=message):
        parse_config(raw, tmp_path)
    raw["auth"]["break_glass"]["mfa"] = "totp"
    parse_config(raw, tmp_path)


# --- Codes par e-mail ----------------------------------------------------------------

KEY = b"cle-du-serveur"


def test_email_code_roundtrip_and_expiry():
    code, digest = mfa.new_email_code(KEY)
    assert len(code) == 8 and code.isdigit() and code not in digest
    exp = NOW + mfa.EMAIL_TTL
    assert mfa.check_email_code(code, digest, exp, KEY, NOW)
    assert mfa.check_email_code(code[:4] + " " + code[4:], digest, exp, KEY, NOW)
    assert not mfa.check_email_code(code, digest, exp, KEY, exp)            # expiré
    assert not mfa.check_email_code(code, digest, exp, b"autre-cle", NOW)  # autre serveur
    assert not mfa.check_email_code(code, None, exp, KEY, NOW)             # aucun code en cours
    assert not mfa.check_email_code("1234567", digest, exp, KEY, NOW)
    assert not mfa.check_email_code(str((int(code) + 1) % 10**8).zfill(8), digest, exp, KEY, NOW)


def test_email_rate_limit():
    ok, wait, sent = mfa.can_send_email([], NOW)
    assert ok and wait == 0
    ok, wait, _ = mfa.can_send_email([NOW - 10], NOW)
    assert not ok and 49 <= wait <= 51                     # une minute entre deux envois
    five = [NOW - 3000, NOW - 2000, NOW - 1000, NOW - 500, NOW - 100]
    ok, wait, _ = mfa.can_send_email(five, NOW)
    assert not ok and wait > 500                           # 5 par heure au plus
    ok, _, kept = mfa.can_send_email([NOW - 4000] + five[1:], NOW)
    assert ok and len(kept) == 4                            # les envois de plus d'une heure sont oubliés


@pytest.mark.parametrize("addr,masked", [("jean.dupont@ville.fr", "j***@ville.fr"),
                                         ("x@a.fr", "x***@a.fr"), ("", "adresse inconnue"),
                                         ("pas-une-adresse", "adresse inconnue")])
def test_mask_email(addr, masked):
    assert mfa.mask_email(addr) == masked


def _cfg(tmp_path, mfa_block):
    import copy
    from auspex.config import parse_config
    from conftest import BASE_CONFIG
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "admin", "mfa": "totp"}, "mfa": mfa_block}
    return parse_config(raw, tmp_path).access


def test_mfa_config_email(tmp_path):
    a = _cfg(tmp_path, {"methods": ["totp", "email"],
                        "email": {"smtp_server": "smtp.ville.fr", "from": "auspex@ville.fr"}})
    assert a.mfa_methods == ("totp", "email")
    assert (a.mail.server, a.mail.port, a.mail.security) == ("smtp.ville.fr", 587, "starttls")
    a = _cfg(tmp_path, {"methods": ["email"], "email": {"smtp_server": "s", "from": "a@b.fr", "security": "tls"}})
    assert a.mail.port == 465
    assert _cfg(tmp_path, {"methods": ["totp"]}).mail is None


@pytest.mark.parametrize("block,message", [
    ({"methods": ["totp", "email"]}, "serveur d'envoi obligatoire"),
    ({"methods": ["email"], "email": {"from": "a@b.fr"}}, "smtp_server : obligatoire"),
    ({"methods": ["email"], "email": {"smtp_server": "s", "from": "a@b.fr", "password": "x"}}, "AUSPEX_SMTP_PASSWORD"),
    ({"methods": ["email"], "email": {"smtp_server": "s", "from": "a@b.fr", "security": "ssl"}}, "starttls"),
    ({"methods": ["email"], "email": {"smtp_server": "s", "from": "pas-une-adresse"}}, "adresse e-mail"),
    ({"methods": ["sms"]}, "parmi 'totp', 'email'"),
    ({"methods": []}, "liste non vide"),
    ({"methods": ["totp"], "email": {"smtp_server": "s", "from": "a@b.fr"}}, "n'est pas dans"),
])
def test_mfa_config_errors(tmp_path, block, message):
    from auspex.config import ConfigError
    with pytest.raises(ConfigError, match=message):
        _cfg(tmp_path, block)


def test_mfa_config_ca_file(tmp_path):
    from auspex.config import ConfigError
    (tmp_path / "ca-interne.pem").write_text("x")
    a = _cfg(tmp_path, {"methods": ["email"], "email": {"smtp_server": "s", "from": "a@b.fr", "ca_file": "ca-interne.pem"}})
    assert a.mail.ca_file == str(tmp_path / "ca-interne.pem")
    with pytest.raises(ConfigError, match="ca_file : fichier introuvable"):
        _cfg(tmp_path, {"methods": ["email"], "email": {"smtp_server": "s", "from": "a@b.fr", "ca_file": "absent.pem"}})
