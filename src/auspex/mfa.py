"""Double authentification par code à usage unique (TOTP, RFC 6238).

Module sans dépendance à NetBox ni à Django : le plugin NetBox l'appelle pour
l'inscription et la vérification. Toute la cryptographie et les règles sont
ici, et testées (vecteurs officiels de la RFC 6238).

Règles :

- Codes à 6 chiffres, période de 30 s, HMAC-SHA1 : ce que lisent toutes les
  applications d'authentification (Aegis, FreeOTP, Google/Microsoft
  Authenticator...).
- Tolérance d'une période avant et après (horloge du téléphone décalée).
- Anti-rejeu : un code accepté ne l'est plus jamais, ni aucun code plus ancien.
- Codes de secours : 10 codes à usage unique, conservés uniquement sous forme
  d'empreinte.
- Quelles connexions exigent la MFA : toutes celles qui ne passent pas par un
  fournisseur d'identité (comptes locaux, LDAPS). Un mécanisme inconnu exige
  la MFA : en cas de doute, on demande.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

DIGITS = 6
PERIOD = 30
WINDOW = 1
MAX_FAILURES = 5
LOCK_SECONDS = 300
MAX_LOCK_SECONDS = 86400
RECOVERY_CODES = 10
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # sans 0/o, 1/l/i : pas de confusion


# --- TOTP ---------------------------------------------------------------------

def new_secret() -> str:
    """Secret de 160 bits, en base32 (ce que saisit l'application)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    s = secret.replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226 (la base de TOTP)."""
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def counter_at(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // PERIOD)


def totp(secret: str, now: float | None = None) -> str:
    return hotp(_key(secret), counter_at(now))


def verify(secret: str, code: str, last_counter: int | None = None, now: float | None = None) -> int | None:
    """Renvoie la période du code s'il est valide et jamais utilisé, sinon None.

    L'appelant enregistre la période renvoyée : c'est l'anti-rejeu.
    """
    code = (code or "").replace(" ", "").strip()
    if len(code) != DIGITS or not code.isdigit():
        return None
    try:
        key = _key(secret)
    except (ValueError, TypeError):
        return None
    current = counter_at(now)
    found = None
    for c in range(current - WINDOW, current + WINDOW + 1):
        # Comparaison à temps constant, sur toute la fenêtre (pas de sortie anticipée).
        if hmac.compare_digest(hotp(key, c), code):
            found = c
    if found is None or (last_counter is not None and found <= last_counter):
        return None
    return found


def otpauth_uri(secret: str, username: str, issuer: str = "Auspex") -> str:
    """Adresse lue par les applications (QR code ou saisie)."""
    label = urllib.parse.quote(f"{issuer}:{username}")
    query = urllib.parse.urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1",
                                    "digits": DIGITS, "period": PERIOD})
    return f"otpauth://totp/{label}?{query}"


def grouped(secret: str) -> str:
    """Secret lisible pour une saisie à la main : groupes de 4."""
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


# --- Codes de secours -----------------------------------------------------------

def _normalize_recovery(code: str) -> str:
    return (code or "").strip().lower().replace("-", "").replace(" ", "")


def _hash_recovery(code: str) -> str:
    # Codes aléatoires de 50 bits, essais limités par le verrouillage :
    # une empreinte SHA-256 suffit (pas de mot de passe humain à protéger).
    return hashlib.sha256(("auspex-recovery:" + _normalize_recovery(code)).encode()).hexdigest()


def new_recovery_codes(n: int = RECOVERY_CODES) -> tuple[list[str], list[str]]:
    """(codes à montrer UNE fois à l'utilisateur, empreintes à conserver)."""
    codes = []
    for _ in range(n):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes, [_hash_recovery(c) for c in codes]


def use_recovery_code(code: str, hashes: list[str]) -> list[str] | None:
    """Empreintes restantes si le code est valide (il est alors consommé), sinon None."""
    if len(_normalize_recovery(code)) != 10:
        return None
    h = _hash_recovery(code)
    match = [x for x in hashes if hmac.compare_digest(x, h)]
    if not match:
        return None
    return [x for x in hashes if x != match[0]]


# --- Codes par e-mail -------------------------------------------------------------
#
# Pour les équipes sans téléphone professionnel. Plus faible que TOTP : qui lit
# la messagerie de l'utilisateur passe la MFA. Jamais pour le brise-glace (il
# doit fonctionner quand la messagerie est en panne).

EMAIL_DIGITS = 8
EMAIL_TTL = 600            # validité d'un code : 10 min
EMAIL_RESEND_SECONDS = 60  # pas plus d'un envoi par minute...
EMAIL_MAX_PER_HOUR = 5     # ... ni plus de 5 par heure (anti-inondation de la boîte)


def email_digest(code: str, key: bytes) -> str:
    """Empreinte du code (HMAC avec une clé du serveur) : jamais conservé en clair."""
    return hmac.new(key, ("auspex-email:" + (code or "").strip()).encode(), hashlib.sha256).hexdigest()


def new_email_code(key: bytes) -> tuple[str, str]:
    """(code à envoyer, empreinte à conserver)."""
    code = "".join(secrets.choice("0123456789") for _ in range(EMAIL_DIGITS))
    return code, email_digest(code, key)


def check_email_code(code: str, digest: str | None, expires: float | None, key: bytes,
                     now: float | None = None) -> bool:
    code = (code or "").replace(" ", "").strip()
    if not digest or expires is None or len(code) != EMAIL_DIGITS or not code.isdigit():
        return False
    if (time.time() if now is None else now) >= expires:
        return False
    return hmac.compare_digest(email_digest(code, key), digest)


def can_send_email(sent: list[float], now: float | None = None) -> tuple[bool, int, list[float]]:
    """(envoi autorisé ?, secondes à attendre sinon, historique de la dernière heure)."""
    now = time.time() if now is None else now
    recent = sorted(t for t in sent if now - t < 3600)
    if recent and now - recent[-1] < EMAIL_RESEND_SECONDS:
        return False, int(EMAIL_RESEND_SECONDS - (now - recent[-1])) + 1, recent
    if len(recent) >= EMAIL_MAX_PER_HOUR:
        return False, int(3600 - (now - recent[0])) + 1, recent
    return True, 0, recent


def mask_email(address: str) -> str:
    """j***@exemple.fr : assez pour reconnaître sa boîte, pas pour la deviner."""
    local, _, domain = (address or "").partition("@")
    if not local or not domain:
        return "adresse inconnue"
    return f"{local[0]}***@{domain}"


# --- Verrouillage après échecs ---------------------------------------------------

def locked(locked_until: float | None, now: float | None = None) -> bool:
    return locked_until is not None and (time.time() if now is None else now) < locked_until


def after_failure(failures: int, locks: int = 0, now: float | None = None) -> tuple[int, int, float | None]:
    """(échecs, verrouillages successifs, fin du verrouillage ou None).

    Tous les MAX_FAILURES échecs : verrouillage, dont la durée double à chaque
    fois (5 min, 10, 20... jusqu'à 24 h), tant qu'aucune connexion ne réussit.
    Un verrouillage fixe de 5 min laisserait ~1 400 essais par jour, soit
    ~0,4 % de chances de deviner un code chaque jour.
    """
    failures += 1
    if failures < MAX_FAILURES:
        return failures, locks, None
    duration = min(LOCK_SECONDS * 2 ** locks, MAX_LOCK_SECONDS)
    return 0, locks + 1, (time.time() if now is None else now) + duration


# --- Quelles connexions exigent la MFA -----------------------------------------------

# Connexions déléguées à un fournisseur d'identité (OIDC, SAML, en-tête d'un
# proxy d'authentification) : la MFA est celle du fournisseur.
_SSO_PREFIXES = ("social_core.backends.",)
# Carte à puce : possession de la carte et code PIN, vérifiés par le front HTTPS.
_SSO_BACKENDS = {"netbox.authentication.RemoteUserBackend", "netbox_auspex.carte.CarteBackend"}


def mfa_required(backend: str | None) -> bool:
    """`backend` : le mécanisme qui a authentifié la session (Django).

    Comptes locaux et LDAPS : MFA exigée. Inconnu ou absent : exigée aussi.
    """
    if not backend:
        return True
    return not (backend in _SSO_BACKENDS or backend.startswith(_SSO_PREFIXES))
