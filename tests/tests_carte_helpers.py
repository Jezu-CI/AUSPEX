"""Petite AC de test (PEM) et sa liste de révocation."""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def ca_and_crl(days_valid: int = 7):
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AC Cartes test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(key, hashes.SHA256()))
    crl = (x509.CertificateRevocationListBuilder().issuer_name(name).last_update(now - timedelta(days=1))
           .next_update(now + timedelta(days=days_valid)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM), crl.public_bytes(serialization.Encoding.PEM)
