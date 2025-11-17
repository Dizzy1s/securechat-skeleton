# app/crypto/pki.py
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timezone
from typing import Optional


def load_cert_from_pem_bytes(pem_bytes: bytes) -> x509.Certificate:
    """Load X.509 certificate from PEM bytes."""
    return x509.load_pem_x509_certificate(pem_bytes)


def verify_cert_signed_by_ca(cert_bytes: bytes, ca_cert_bytes: bytes) -> bool:
    """
    Verify that a certificate is directly signed by the given CA.
    Also checks validity period using UTC-aware properties (2025+ compatible).
    """
    try:
        cert = load_cert_from_pem_bytes(cert_bytes)
        ca_cert = load_cert_from_pem_bytes(ca_cert_bytes)

        # --- 1. Verify cryptographic signature ---
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm,
        )

        # --- 2. Check validity period (UTC-aware, no deprecation warnings) ---
        now = datetime.now(timezone.utc)
        if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
            return False

        # --- 3. Optional: Basic path validation (issuer == CA subject) ---
        if cert.issuer != ca_cert.subject:
            return False

        return True

    except InvalidSignature:
        return False
    except Exception as e:
        # Any parsing error, invalid format, etc.
        print(f"[PKI] Certificate verification failed: {e}")
        return False


def cert_common_name(cert_bytes: bytes) -> str:
    """
    Extract Common Name (CN) from certificate subject.
    Returns empty string if not found.
    """
    try:
        cert = load_cert_from_pem_bytes(cert_bytes)
        for attribute in cert.subject:
            if attribute.oid == NameOID.COMMON_NAME:
                return attribute.value
    except Exception:
        pass
    return ""