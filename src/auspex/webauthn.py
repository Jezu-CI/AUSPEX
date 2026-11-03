"""WebAuthn (clés de sécurité FIDO2, Windows Hello, Touch ID) : vérification côté serveur.

Implémentation volontairement réduite à ce dont Auspex a besoin, sans
dépendance au-delà de « cryptography » :

- inscription : attestation « none » demandée ; la déclaration d'attestation
  éventuellement fournie n'est pas vérifiée (Auspex ne restreint pas les
  modèles de clés) ; tout le reste l'est : type, défi, origine, identifiant de
  la partie de confiance (rpId), présence de l'utilisateur, algorithme ;
- authentification : signature sur authenticatorData || SHA-256(clientDataJSON)
  avec la clé publique enregistrée, défi, origine, rpId, présence, compteur
  de signatures (une clé clonée est détectée quand le compteur recule).

Algorithmes : Ed25519 (-8), ES256 (-7), RS256 (-257).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
from dataclasses import dataclass

ALGORITHMS = (-8, -7, -257)
FLAG_UP, FLAG_UV, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x40, 0x80
MAX_CBOR = 64 * 1024


class WebAuthnError(ValueError):
    pass


# --- Encodage --------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text) -> bytes:
    if not isinstance(text, str) or len(text) > 4 * MAX_CBOR:
        raise WebAuthnError("donnée base64url attendue")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise WebAuthnError("base64url invalide") from exc


# --- CBOR (sous-ensemble utilisé par WebAuthn) ----------------------------------------------

def cbor_decode(data: bytes, offset: int = 0, depth: int = 0):
    """Décode un élément CBOR ; renvoie (valeur, position suivante)."""
    if depth > 16:
        raise WebAuthnError("CBOR trop imbriqué")
    if offset >= len(data):
        raise WebAuthnError("CBOR tronqué")
    head = data[offset]
    major, info = head >> 5, head & 0x1F
    offset += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if offset + size > len(data):
            raise WebAuthnError("CBOR tronqué")
        arg = int.from_bytes(data[offset:offset + size], "big")
        offset += size
    else:
        raise WebAuthnError("CBOR : longueur indéfinie ou réservée non prise en charge")
    if major == 0:
        return arg, offset
    if major == 1:
        return -1 - arg, offset
    if major in (2, 3):
        if arg > MAX_CBOR or offset + arg > len(data):
            raise WebAuthnError("CBOR tronqué")
        raw = data[offset:offset + arg]
        if major == 3:
            try:
                return raw.decode("utf-8"), offset + arg
            except UnicodeDecodeError as exc:
                raise WebAuthnError("CBOR : texte invalide") from exc
        return bytes(raw), offset + arg
    if major in (4, 5):
        if arg > 1024:
            raise WebAuthnError("CBOR : trop d'éléments")
        if major == 4:
            items = []
            for _ in range(arg):
                v, offset = cbor_decode(data, offset, depth + 1)
                items.append(v)
            return items, offset
        out = {}
        for _ in range(arg):
            k, offset = cbor_decode(data, offset, depth + 1)
            if isinstance(k, (list, dict)):
                raise WebAuthnError("CBOR : clé de table invalide")
            v, offset = cbor_decode(data, offset, depth + 1)
            out[k] = v
        return out, offset
    if major == 6:                      # étiquette : ignorée, valeur décodée
        return cbor_decode(data, offset, depth + 1)
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], offset
    raise WebAuthnError("CBOR : type non pris en charge")


def cbor_loads(data: bytes):
    value, end = cbor_decode(data)
    if end != len(data):
        raise WebAuthnError("CBOR : données en trop")
    return value


# --- Clés COSE ----------------------------------------------------------------------------

def cose_alg(cose: bytes) -> int:
    key = cbor_loads(cose)
    if not isinstance(key, dict) or 3 not in key:
        raise WebAuthnError("clé COSE invalide")
    return key[3]


def _public_key(cose: bytes):
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    key = cbor_loads(cose)
    if not isinstance(key, dict):
        raise WebAuthnError("clé COSE invalide")
    kty, alg = key.get(1), key.get(3)
    try:
        if kty == 1 and alg == -8 and key.get(-1) == 6:                     # OKP, Ed25519
            return alg, ed25519.Ed25519PublicKey.from_public_bytes(key[-2])
        if kty == 2 and alg == -7 and key.get(-1) == 1:                     # EC2, P-256
            x, y = key[-2], key[-3]
            if len(x) != 32 or len(y) != 32:
                raise WebAuthnError("clé P-256 invalide")
            return alg, ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x + y)
        if kty == 3 and alg == -257:                                        # RSA
            n, e = int.from_bytes(key[-1], "big"), int.from_bytes(key[-2], "big")
            if n.bit_length() < 2048:
                raise WebAuthnError("clé RSA trop courte")
            return alg, rsa.RSAPublicNumbers(e, n).public_key()
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, WebAuthnError):
            raise
        raise WebAuthnError("clé COSE invalide") from exc
    raise WebAuthnError(f"algorithme non pris en charge (kty {kty}, alg {alg})")


def _verify_signature(cose: bytes, signature: bytes, data: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    alg, pub = _public_key(cose)
    try:
        if alg == -8:
            pub.verify(signature, data)
        elif alg == -7:
            pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            pub.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise WebAuthnError("signature invalide") from exc


# --- Données de l'authentificateur -----------------------------------------------------

@dataclass
class AuthData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    aaguid: bytes | None = None
    credential_id: bytes | None = None
    public_key: bytes | None = None      # COSE, tel que reçu


def parse_auth_data(data: bytes) -> AuthData:
    if len(data) < 37:
        raise WebAuthnError("authenticatorData trop court")
    flags = data[32]
    out = AuthData(data[:32], flags, struct.unpack(">I", data[33:37])[0])
    pos = 37
    if flags & FLAG_AT:
        if len(data) < pos + 18:
            raise WebAuthnError("authenticatorData tronqué")
        out.aaguid = data[pos:pos + 16]
        (n,) = struct.unpack(">H", data[pos + 16:pos + 18])
        pos += 18
        if n == 0 or n > 1023 or len(data) < pos + n:
            raise WebAuthnError("identifiant de clé invalide")
        out.credential_id = data[pos:pos + n]
        pos += n
        _, end = cbor_decode(data, pos)
        out.public_key = data[pos:end]
        pos = end
    if flags & FLAG_ED:
        _, pos = cbor_decode(data, pos)
    if pos != len(data):
        raise WebAuthnError("authenticatorData : données en trop")
    return out


def _client_data(raw: bytes, kind: str, challenge: bytes, origin: str) -> None:
    try:
        cd = json.loads(raw)
    except ValueError as exc:
        raise WebAuthnError("clientDataJSON illisible") from exc
    if not isinstance(cd, dict) or cd.get("type") != kind:
        raise WebAuthnError(f"type attendu : {kind}")
    got = b64url_decode(cd.get("challenge", ""))
    if not hmac.compare_digest(got, challenge):
        raise WebAuthnError("défi différent (rejeu ou autre session)")
    if cd.get("origin") != origin:
        raise WebAuthnError(f"origine inattendue : {str(cd.get('origin'))[:100]}")
    if cd.get("crossOrigin") is True:
        raise WebAuthnError("appel depuis une autre origine (iframe) refusé")


def _check_auth_data(ad: AuthData, rp_id: str, require_uv: bool) -> None:
    if not hmac.compare_digest(ad.rp_id_hash, hashlib.sha256(rp_id.encode()).digest()):
        raise WebAuthnError("clé émise pour un autre site (rpId)")
    if not ad.flags & FLAG_UP:
        raise WebAuthnError("présence de l'utilisateur non confirmée")
    if require_uv and not ad.flags & FLAG_UV:
        raise WebAuthnError("vérification de l'utilisateur (code PIN, biométrie) exigée")


@dataclass
class Registration:
    credential_id: bytes
    public_key: bytes
    sign_count: int
    aaguid: bytes
    user_verified: bool


def verify_registration(response: dict, challenge: bytes, origin: str, rp_id: str,
                        require_uv: bool = False) -> Registration:
    """`response` : objet renvoyé par le navigateur (champs en base64url)."""
    if not isinstance(response, dict):
        raise WebAuthnError("réponse attendue")
    client_data = b64url_decode(response.get("clientDataJSON"))
    _client_data(client_data, "webauthn.create", challenge, origin)
    att = cbor_loads(b64url_decode(response.get("attestationObject")))
    if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes) or "fmt" not in att:
        raise WebAuthnError("attestationObject invalide")
    ad = parse_auth_data(att["authData"])
    _check_auth_data(ad, rp_id, require_uv)
    if not ad.flags & FLAG_AT or not ad.credential_id or not ad.public_key:
        raise WebAuthnError("aucune clé dans la réponse d'inscription")
    alg, _ = _public_key(ad.public_key)
    if alg not in ALGORITHMS:
        raise WebAuthnError("algorithme non pris en charge")
    return Registration(ad.credential_id, ad.public_key, ad.sign_count, ad.aaguid or b"",
                        bool(ad.flags & FLAG_UV))


def verify_assertion(response: dict, public_key: bytes, stored_count: int, challenge: bytes, origin: str,
                     rp_id: str, require_uv: bool = False) -> int:
    """Vérifie une authentification ; renvoie le nouveau compteur de signatures."""
    if not isinstance(response, dict):
        raise WebAuthnError("réponse attendue")
    client_data = b64url_decode(response.get("clientDataJSON"))
    _client_data(client_data, "webauthn.get", challenge, origin)
    auth_data = b64url_decode(response.get("authenticatorData"))
    ad = parse_auth_data(auth_data)
    _check_auth_data(ad, rp_id, require_uv)
    _verify_signature(public_key, b64url_decode(response.get("signature")),
                      auth_data + hashlib.sha256(client_data).digest())
    if (ad.sign_count or stored_count) and ad.sign_count <= stored_count:
        raise WebAuthnError("compteur de signatures en recul : clé peut-être clonée")
    return ad.sign_count


def user_handle(secret: str, user_pk) -> bytes:
    """Identifiant opaque de l'utilisateur pour l'authentificateur (ni nom ni numéro en clair)."""
    return hmac.new(secret.encode(), f"auspex-webauthn:{user_pk}".encode(), hashlib.sha256).digest()[:16]


def registration_options(challenge: bytes, rp_id: str, rp_name: str, user_id: bytes, username: str,
                         exclude: list[bytes] = ()) -> dict:
    return {
        "challenge": b64url(challenge),
        "rp": {"id": rp_id, "name": rp_name},
        "user": {"id": b64url(user_id), "name": username, "displayName": username},
        "pubKeyCredParams": [{"type": "public-key", "alg": a} for a in ALGORITHMS],
        "timeout": 120000,
        "attestation": "none",
        "authenticatorSelection": {"residentKey": "discouraged", "userVerification": "preferred"},
        "excludeCredentials": [{"type": "public-key", "id": b64url(c)} for c in exclude],
    }


def assertion_options(challenge: bytes, rp_id: str, allow: list[bytes]) -> dict:
    return {
        "challenge": b64url(challenge),
        "rpId": rp_id,
        "timeout": 120000,
        "userVerification": "preferred",
        "allowCredentials": [{"type": "public-key", "id": b64url(c)} for c in allow],
    }
