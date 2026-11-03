"""Connexion par carte à puce : identité tirée du certificat client.

La vérification cryptographique (chaîne jusqu'aux autorités des cartes,
révocation, possession de la clé privée, donc de la carte et de son code
PIN) est faite par le front HTTPS (nginx) sur le port dédié. NetBox ne
reçoit l'identité que du front, prouvé par un secret partagé, et refait les
contrôles qui ne coûtent rien (dates, émetteur connu).

Ce module : lecture des autorités et des listes de révocation (validation de
la configuration), extraction de l'identifiant (UPN Microsoft, e-mail, CN).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import unquote

UPN_OID = "1.3.6.1.4.1.311.20.2.3"     # userPrincipalName (cartes d'ouverture de session Windows)
MAX_CERT = 16 * 1024


class CardError(ValueError):
    pass


def _x509():
    from cryptography import x509
    return x509


def load_authorities(data: bytes) -> list:
    """Certificats d'autorité d'un fichier PEM (au moins un, tous marqués AC)."""
    x509 = _x509()
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError as exc:
        raise CardError("fichier PEM de certificats illisible") from exc
    if not certs:
        raise CardError("aucun certificat dans le fichier")
    for c in certs:
        try:
            bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            bc = None
        if bc is None or not bc.ca:
            raise CardError(f"« {c.subject.rfc4514_string()[:80]} » n'est pas une autorité de certification")
    return certs


def load_crls(data: bytes) -> list:
    """Listes de révocation d'un fichier PEM (une ou plusieurs)."""
    x509 = _x509()
    blocks = [b for b in data.split(b"-----END X509 CRL-----") if b"-----BEGIN X509 CRL-----" in b]
    if not blocks:
        raise CardError("aucune liste de révocation (bloc « X509 CRL ») dans le fichier")
    try:
        return [x509.load_pem_x509_crl(b + b"-----END X509 CRL-----\n") for b in blocks]
    except ValueError as exc:
        raise CardError("liste de révocation illisible") from exc


def crl_expiry(data: bytes) -> datetime | None:
    """Date de la prochaine mise à jour la plus proche (une LCR périmée bloque toutes les cartes)."""
    dates = [c.next_update_utc for c in load_crls(data) if c.next_update_utc]
    return min(dates) if dates else None


def parse_forwarded_cert(header: str):
    """Certificat transmis par le front (variable nginx $ssl_client_escaped_cert)."""
    if not header or len(header) > 3 * MAX_CERT:
        raise CardError("certificat absent")
    pem = unquote(header).encode()
    try:
        return _x509().load_pem_x509_certificate(pem)
    except ValueError as exc:
        raise CardError("certificat illisible") from exc


def _upn(cert) -> str | None:
    x509 = _x509()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    for name in san.get_values_for_type(x509.OtherName):
        if name.type_id.dotted_string == UPN_OID:
            raw = name.value
            # DER : UTF8String (0x0C) de longueur courte ou longue
            if len(raw) >= 2 and raw[0] == 0x0C:
                length, start = raw[1], 2
                if length & 0x80:
                    n = length & 0x7F
                    length, start = int.from_bytes(raw[2:2 + n], "big"), 2 + n
                return raw[start:start + length].decode("utf-8", "replace")
    return None


def _email(cert) -> str | None:
    x509 = _x509()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        values = san.get_values_for_type(x509.RFC822Name)
        if values:
            return values[0]
    except x509.ExtensionNotFound:
        pass
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)
    return attrs[0].value if attrs else None


def _cn(cert) -> str | None:
    attrs = cert.subject.get_attributes_for_oid(_x509().NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


@dataclass
class CardIdentity:
    username: str
    subject: str
    issuer: str
    serial: str


def identity(cert, rule: str, now: datetime | None = None) -> CardIdentity:
    """Nom d'utilisateur NetBox selon la règle (upn, upn_court, email, cn)."""
    now = now or datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise CardError("certificat de la carte hors de sa période de validité")
    if rule in ("upn", "upn_court"):
        value = _upn(cert)
        if value and rule == "upn_court":
            value = value.split("@", 1)[0]
    elif rule == "email":
        value = _email(cert)
    elif rule == "cn":
        value = _cn(cert)
    else:
        raise CardError(f"règle d'identification inconnue : {rule}")
    if not value:
        raise CardError(f"le certificat ne contient pas d'identifiant « {rule} »")
    value = value.strip()
    # Mêmes règles que les noms d'utilisateur de Django : lettres, chiffres, . @ + - _
    if not re.fullmatch(r"[\w.@+-]{1,150}", value):
        raise CardError(f"identifiant « {value[:60]} » inutilisable comme nom d'utilisateur NetBox")
    return CardIdentity(username=value,
                        subject=cert.subject.rfc4514_string()[:300], issuer=cert.issuer.rfc4514_string()[:300],
                        serial=format(cert.serial_number, "X"))
