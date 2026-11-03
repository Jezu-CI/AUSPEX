"""Carte à puce : lecture des autorités et LCR, identité tirée du certificat client."""

import copy
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from auspex import carte
from auspex.config import ConfigError, parse_config

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def name(cn, email=None):
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if email:
        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    return x509.Name(attrs)


def make_ca(cn="AC Cartes Ville"):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(cn)).public_key(key.public_key())
            .serial_number(1).not_valid_before(NOW - timedelta(days=365)).not_valid_after(NOW + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def utf8_der(text):
    raw = text.encode()
    return b"\x0c" + (bytes([len(raw)]) if len(raw) < 128 else b"\x81" + bytes([len(raw)])) + raw


def make_user_cert(ca, cn="jdupont", upn="jdupont@ville.local", email="jean.dupont@ville.fr",
                   days=(-30, 365), with_email_attr=False):
    ca_key, ca_cert = ca
    key = ec.generate_private_key(ec.SECP256R1())
    san = []
    if upn:
        san.append(x509.OtherName(x509.ObjectIdentifier(carte.UPN_OID), utf8_der(upn)))
    if email:
        san.append(x509.RFC822Name(email))
    b = (x509.CertificateBuilder().subject_name(name(cn, email if with_email_attr else None))
         .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW + timedelta(days=days[0])).not_valid_after(NOW + timedelta(days=days[1])))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return b.sign(ca_key, hashes.SHA256())


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.mark.parametrize("rule, expected", [("upn", "jdupont@ville.local"), ("upn_court", "jdupont"),
                                            ("email", "jean.dupont@ville.fr"), ("cn", "jdupont")])
def test_identity_rules(rule, expected):
    """CN : seulement s'il est le nom d'utilisateur (« Jean Dupont », avec espace, est refusé)."""
    cert = make_user_cert(make_ca())
    assert carte.identity(cert, rule, NOW).username == expected


def test_long_upn_and_email_attribute():
    long_upn = "a" * 150 + "@v.fr"
    cert = make_user_cert(make_ca(), upn=long_upn, email=None, with_email_attr=False)
    with pytest.raises(carte.CardError):          # > 150 caractères : refusé
        carte.identity(cert, "upn", NOW)
    cert = make_user_cert(make_ca(), upn="x" * 130 + "@v.fr")
    assert carte.identity(cert, "upn", NOW).username.startswith("x" * 130)
    cert = make_user_cert(make_ca(), email=None, upn=None, cn="Agent", with_email_attr=False)
    with pytest.raises(carte.CardError, match="ne contient pas"):
        carte.identity(cert, "email", NOW)


def test_expired_or_future_certificate():
    ca = make_ca()
    for days in ((-400, -1), (5, 400)):
        with pytest.raises(carte.CardError, match="validité"):
            carte.identity(make_user_cert(ca, days=days), "upn", NOW)


def test_unusable_identifiers():
    for upn in ("jean dupont@v.fr", "a/b@v.fr", "x\nadmin", "<script>@v.fr"):
        with pytest.raises(carte.CardError):
            carte.identity(make_user_cert(make_ca(), upn=upn), "upn", NOW)


def test_forwarded_cert_from_nginx():
    cert = make_user_cert(make_ca())
    header = quote(pem(cert).decode(), safe="")            # comme $ssl_client_escaped_cert
    assert carte.parse_forwarded_cert(header).serial_number == cert.serial_number
    for bad in ("", "x" * 60000, quote("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")):
        with pytest.raises(carte.CardError):
            carte.parse_forwarded_cert(bad)


def test_authorities_and_crl_files():
    ca_key, ca_cert = make_ca()
    assert len(carte.load_authorities(pem(ca_cert) + pem(make_ca("AC 2")[1]))) == 2
    with pytest.raises(carte.CardError, match="n'est pas une autorité"):
        carte.load_authorities(pem(make_user_cert((ca_key, ca_cert))))
    with pytest.raises(carte.CardError):
        carte.load_authorities(b"pas un certificat")
    crl = (x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject).last_update(NOW)
           .next_update(NOW + timedelta(days=7)).sign(ca_key, hashes.SHA256()))
    data = crl.public_bytes(serialization.Encoding.PEM)
    assert len(carte.load_crls(data * 2)) == 2
    assert carte.crl_expiry(data) == NOW + timedelta(days=7)
    with pytest.raises(carte.CardError, match="aucune liste"):
        carte.load_crls(pem(ca_cert))


def _cfg(tmp_path, block):
    from conftest import BASE_CONFIG
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "secours", "mfa": "totp"}, "carte": block}
    return parse_config(raw, tmp_path)


def test_config(tmp_path):
    ca_key, ca_cert = make_ca()
    (tmp_path / "ac.pem").write_bytes(pem(ca_cert))
    crl = (x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject).last_update(NOW)
           .next_update(NOW + timedelta(days=7)).sign(ca_key, hashes.SHA256()))
    (tmp_path / "lcr.pem").write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    cfg = _cfg(tmp_path, {"adresse": "https://auspex.ville.fr:8443", "autorites": "ac.pem",
                          "revocation": "lcr.pem", "identifiant": "upn_court"})
    c = cfg.access.card
    assert c.address == "https://auspex.ville.fr:8443" and c.identifier == "upn_court" and c.crl_file.endswith("lcr.pem")
    (tmp_path / "pas-ac.pem").write_bytes(pem(make_user_cert((ca_key, ca_cert))))
    with pytest.raises(ConfigError) as exc:
        _cfg(tmp_path, {"adresse": "https://auspex.ville.fr", "autorites": "pas-ac.pem", "revocation": "absent.pem",
                        "identifiant": "matricule", "creer_comptes": "oui", "autre": 1})
    text = " | ".join(exc.value.problems)
    for needle in ("auth.carte.adresse", "n'est pas une autorité", "revocation : fichier introuvable",
                   "'matricule' inconnu", "creer_comptes", "auth.carte.autre : clé inconnue"):
        assert needle in text, needle


def test_cn_with_space_refused():
    with pytest.raises(carte.CardError, match="inutilisable"):
        carte.identity(make_user_cert(make_ca(), cn="Jean Dupont"), "cn", NOW)


def test_deploy_section(tmp_path):
    from auspex.deploy import _card_section
    from tests_carte_helpers import ca_and_crl
    ca, crl = ca_and_crl(days_valid=3)
    (tmp_path / "ac.pem").write_bytes(ca)
    (tmp_path / "lcr.pem").write_bytes(crl)
    block = {"adresse": "https://a.fr:8443", "autorites": "ac.pem", "revocation": "lcr.pem"}
    cfg = _cfg(tmp_path, block)
    sec = _card_section(cfg)
    assert sec.changes and sec.action and any("à renouveler" in n for n in sec.notes)
    sec.action()
    folder = cfg.state_dir / "acces"
    assert sorted(p.name for p in folder.iterdir()) == ["carte.conf", "cartes-ac.pem", "cartes-lcr.pem"]
    assert not _card_section(cfg).changes                          # idempotent
    _, expired = ca_and_crl(days_valid=-1)
    (tmp_path / "lcr.pem").write_bytes(expired)
    sec = _card_section(_cfg(tmp_path, block))
    assert any("périmée" in n for n in sec.notes) and not sec.errors   # l'analyse n'est pas bloquée
    from conftest import BASE_CONFIG
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "secours", "mfa": "totp"}}
    off = parse_config(raw, tmp_path)
    sec = _card_section(off)
    assert sec.changes == ["- port carte désactivé"]
    sec.action()
    assert sorted(p.name for p in folder.iterdir()) == ["carte.conf"] and (folder / "carte.conf").read_bytes() == b""
