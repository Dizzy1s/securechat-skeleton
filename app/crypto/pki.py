# app/crypto/pki.py
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import datetime

def load_cert_from_pem_bytes(pem_bytes: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_bytes)

def verify_cert_signed_by_ca(cert_bytes: bytes, ca_cert_bytes: bytes) -> bool:
    cert = load_cert_from_pem_bytes(cert_bytes)
    ca_cert = load_cert_from_pem_bytes(ca_cert_bytes)
    try:
        # verify signature chain
        ca_pub = ca_cert.public_key()
        ca_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                      padding.PKCS1v15(), cert.signature_hash_algorithm)
    except Exception:
        return False
    # check validity period
    now = datetime.datetime.utcnow()
    if cert.not_valid_before > now or cert.not_valid_after < now:
        return False
    return True

def cert_common_name(cert_bytes: bytes) -> str:
    cert = load_cert_from_pem_bytes(cert_bytes)
    for r in cert.subject:
        if r.oid == NameOID.COMMON_NAME:
            return r.value
    return ""
