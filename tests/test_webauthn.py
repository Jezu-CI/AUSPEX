"""WebAuthn : vérification côté serveur, avec un authentificateur simulé."""

import hashlib
import json
import os
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from auspex import webauthn as wa

RP, ORIGIN = "auspex.ville.fr", "https://auspex.ville.fr"


def cbor(v) -> bytes:
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    if isinstance(v, bool):
        return bytes([0xF5 if v else 0xF4])
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(v)


class Authenticator:
    """Clé de sécurité simulée (comme l'authentificateur virtuel des navigateurs)."""

    def __init__(self, alg=-8, rp_id=RP):
        self.alg, self.rp_id, self.count = alg, rp_id, 0
        self.cred_id = os.urandom(32)
        if alg == -8:
            self.key = ed25519.Ed25519PrivateKey.generate()
            raw = self.key.public_key().public_bytes_raw()
            self.cose = cbor({1: 1, 3: -8, -1: 6, -2: raw})
        elif alg == -7:
            self.key = ec.generate_private_key(ec.SECP256R1())
            n = self.key.public_key().public_numbers()
            self.cose = cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
        else:
            self.key = rsa.generate_private_key(65537, 2048)
            n = self.key.public_key().public_numbers()
            self.cose = cbor({1: 3, 3: -257, -1: n.n.to_bytes(256, "big"), -2: n.e.to_bytes(3, "big")})

    def auth_data(self, flags, attested=False):
        data = hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self.count)
        if attested:
            data += b"\0" * 16 + struct.pack(">H", len(self.cred_id)) + self.cred_id + self.cose
        return data

    def client_data(self, kind, challenge, origin=ORIGIN, **extra):
        return json.dumps({"type": kind, "challenge": wa.b64url(challenge), "origin": origin, **extra}).encode()

    def create(self, challenge, origin=ORIGIN, flags=wa.FLAG_UP | wa.FLAG_UV | wa.FLAG_AT, fmt="none"):
        att = cbor({"fmt": fmt, "attStmt": {}, "authData": self.auth_data(flags, attested=bool(flags & wa.FLAG_AT))})
        return {"clientDataJSON": wa.b64url(self.client_data("webauthn.create", challenge, origin)),
                "attestationObject": wa.b64url(att)}

    def sign(self, data):
        if self.alg == -8:
            return self.key.sign(data)
        if self.alg == -7:
            return self.key.sign(data, ec.ECDSA(hashes.SHA256()))
        return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    def get(self, challenge, origin=ORIGIN, flags=wa.FLAG_UP | wa.FLAG_UV, bump=True, **extra):
        if bump:
            self.count += 1
        ad = self.auth_data(flags)
        cd = self.client_data("webauthn.get", challenge, origin, **extra)
        return {"clientDataJSON": wa.b64url(cd), "authenticatorData": wa.b64url(ad),
                "signature": wa.b64url(self.sign(ad + hashlib.sha256(cd).digest()))}


@pytest.mark.parametrize("alg", [-8, -7, -257])
def test_register_then_authenticate(alg):
    a = Authenticator(alg)
    ch = os.urandom(32)
    reg = wa.verify_registration(a.create(ch), ch, ORIGIN, RP)
    assert reg.credential_id == a.cred_id and reg.public_key == a.cose and reg.user_verified
    count = reg.sign_count
    for _ in range(3):
        ch = os.urandom(32)
        count = wa.verify_assertion(a.get(ch), reg.public_key, count, ch, ORIGIN, RP)
    assert count == 3


def test_registration_refusals():
    a = Authenticator()
    ch = os.urandom(32)
    cases = [
        (a.create(os.urandom(32)), "défi différent"),
        (a.create(ch, origin="https://auspex.ville.fr.phishing.example"), "origine inattendue"),
        (a.create(ch, flags=wa.FLAG_AT), "présence de l'utilisateur"),
        (Authenticator(rp_id="phishing.example").create(ch), "autre site"),
        (a.create(ch, flags=wa.FLAG_UP), "aucune clé"),
    ]
    for response, needle in cases:
        with pytest.raises(wa.WebAuthnError) as exc:
            wa.verify_registration(response, ch, ORIGIN, RP)
        assert needle in str(exc.value), needle
    with pytest.raises(wa.WebAuthnError, match="vérification de l'utilisateur"):
        wa.verify_registration(a.create(ch, flags=wa.FLAG_UP | wa.FLAG_AT), ch, ORIGIN, RP, require_uv=True)
    # Réponse d'authentification présentée à l'inscription : type refusé
    with pytest.raises(wa.WebAuthnError, match="webauthn.create"):
        wa.verify_registration({**a.get(ch), "attestationObject": a.create(ch)["attestationObject"]},
                               ch, ORIGIN, RP)


def test_assertion_refusals():
    a = Authenticator(-7)
    ch = os.urandom(32)
    reg = wa.verify_registration(a.create(ch), ch, ORIGIN, RP)
    good = a.get(ch)
    tampered = dict(good, signature=wa.b64url(b"\0" * 70))
    cases = [
        (tampered, "signature"),
        (a.get(os.urandom(32)), "défi différent"),
        (a.get(ch, origin="http://auspex.ville.fr"), "origine inattendue"),
        (a.get(ch, flags=0), "présence de l'utilisateur"),
        (a.get(ch, crossOrigin=True), "autre origine"),
    ]
    for response, needle in cases:
        with pytest.raises(wa.WebAuthnError) as exc:
            wa.verify_assertion(response, reg.public_key, 0, ch, ORIGIN, RP)
        assert needle in str(exc.value), needle
    # Signature d'une autre clé
    other = Authenticator(-7)
    with pytest.raises(wa.WebAuthnError, match="signature"):
        wa.verify_assertion(other.get(ch), reg.public_key, 0, ch, ORIGIN, RP)


def test_cloned_key_detected():
    a = Authenticator()
    ch = os.urandom(32)
    reg = wa.verify_registration(a.create(ch), ch, ORIGIN, RP)
    count = wa.verify_assertion(a.get(ch), reg.public_key, 0, ch, ORIGIN, RP)
    replay = a.get(ch, bump=False)                       # même compteur : rejeu ou clone
    with pytest.raises(wa.WebAuthnError, match="clonée"):
        wa.verify_assertion(replay, reg.public_key, count, ch, ORIGIN, RP)


def test_counterless_authenticators_accepted():
    """Certaines clés (passkeys synchronisées) laissent le compteur à 0."""
    a = Authenticator()
    ch = os.urandom(32)
    reg = wa.verify_registration(a.create(ch), ch, ORIGIN, RP)
    for _ in range(2):
        assert wa.verify_assertion(a.get(ch, bump=False), reg.public_key, 0, ch, ORIGIN, RP) == 0


@pytest.mark.parametrize("data", [
    b"", b"\x1f", b"\x5a\xff\xff\xff\xff", b"\x9f", b"\xa1\x81\x00\x00",
    b"\x81" * 40 + b"\x00", b"\x63ab",
])
def test_malformed_cbor(data):
    with pytest.raises(wa.WebAuthnError):
        wa.cbor_loads(data)


def test_garbage_responses():
    ch = os.urandom(32)
    for response in (None, {}, {"clientDataJSON": "!!!"}, {"clientDataJSON": wa.b64url(b"pas du json")},
                     {"clientDataJSON": wa.b64url(b"[]")}):
        with pytest.raises(wa.WebAuthnError):
            wa.verify_registration(response, ch, ORIGIN, RP)
        with pytest.raises(wa.WebAuthnError):
            wa.verify_assertion(response, b"", 0, ch, ORIGIN, RP)


def test_weak_rsa_refused():
    k = rsa.generate_private_key(65537, 1024)
    n = k.public_key().public_numbers()
    cose = cbor({1: 3, 3: -257, -1: n.n.to_bytes(128, "big"), -2: n.e.to_bytes(3, "big")})
    with pytest.raises(wa.WebAuthnError, match="trop courte"):
        wa._public_key(cose)


def test_options():
    uid = wa.user_handle("secret", 42)
    assert uid == wa.user_handle("secret", 42) and uid != wa.user_handle("secret", 43) and len(uid) == 16
    o = wa.registration_options(b"c" * 32, RP, "Auspex", uid, "agent1", exclude=[b"k1"])
    assert o["attestation"] == "none" and [p["alg"] for p in o["pubKeyCredParams"]] == [-8, -7, -257]
    assert o["excludeCredentials"][0]["id"] == wa.b64url(b"k1") and o["rp"]["id"] == RP
    a = wa.assertion_options(b"c" * 32, RP, [b"k1", b"k2"])
    assert len(a["allowCredentials"]) == 2 and a["rpId"] == RP


# --- Configuration ------------------------------------------------------------------------

def _cfg(mfa=None, break_glass_mfa="totp"):
    import copy

    from conftest import BASE_CONFIG

    from auspex.config import parse_config
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "secours", "mfa": break_glass_mfa}}
    if mfa is not None:
        raw["auth"]["mfa"] = mfa
    return parse_config(raw)


def test_config_webauthn():
    cfg = _cfg({"methods": ["webauthn", "totp"], "webauthn": {"domaine": RP, "adresse": ORIGIN}},
               break_glass_mfa="webauthn")
    a = cfg.access
    assert a.mfa_methods == ("webauthn", "totp") and a.webauthn.rp_id == RP and a.webauthn.origin == ORIGIN
    assert a.break_glass_mfa == "webauthn" and a.webauthn.require_uv is False


@pytest.mark.parametrize("mfa, bg, needle", [
    ({"methods": ["webauthn"]}, "totp", "auth.mfa.webauthn : obligatoire"),
    ({"methods": ["totp"]}, "webauthn", "auth.break_glass.mfa : 'webauthn' demande"),
    ({"methods": ["webauthn"], "webauthn": {"domaine": "10.0.0.1", "adresse": "https://10.0.0.1"}}, "totp",
     "pas une adresse IP"),
    ({"methods": ["webauthn"], "webauthn": {"domaine": RP, "adresse": "http://auspex.ville.fr"}}, "totp",
     "HTTPS obligatoire"),
    ({"methods": ["webauthn"], "webauthn": {"domaine": "autre.fr", "adresse": ORIGIN}}, "totp",
     "domaines parents"),
    ({"methods": ["webauthn"], "webauthn": {"domaine": RP, "adresse": ORIGIN, "exiger_code": "oui"}}, "totp",
     "exiger_code"),
    ({"methods": ["sms"]}, "totp", "'totp', 'email', 'webauthn'"),
    (None, "sms", "'totp' ou 'webauthn'"),
])
def test_config_webauthn_errors(mfa, bg, needle):
    from auspex.config import ConfigError
    with pytest.raises(ConfigError) as exc:
        _cfg(mfa, bg)
    assert needle in " | ".join(exc.value.problems)
