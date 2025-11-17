# app/crypto/aes.py
import os
import base64
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def _pad(data: bytes) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def _unpad(padded: bytes) -> bytes:
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def aes_encrypt_bytes(key16: bytes, plaintext: bytes) -> dict:
    """Return dict with base64 iv and ct"""
    if len(key16) != 16:
        raise ValueError("AES key must be 16 bytes")
    iv = os.urandom(16)
    pt = _pad(plaintext)
    cipher = Cipher(algorithms.AES(key16), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(pt) + encryptor.finalize()
    return {"iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()}

def aes_decrypt_bytes(key16: bytes, iv_b64: str, ct_b64: str) -> bytes:
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    cipher = Cipher(algorithms.AES(key16), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    return _unpad(padded)
