# app/crypto/sign.py
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509

def load_privkey(path: str, password: bytes = None):
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=password)

def load_pubkey_from_cert_bytes(cert_bytes: bytes):
    cert = x509.load_pem_x509_certificate(cert_bytes)
    return cert.public_key()

def rsa_sign_b64(privkey, data: bytes) -> str:
    sig = privkey.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(sig).decode()

def rsa_verify_b64(pubkey, data: bytes, sig_b64: str) -> bool:
    sig = base64.b64decode(sig_b64)
    try:
        pubkey.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
