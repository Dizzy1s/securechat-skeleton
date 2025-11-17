import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def _unpad(padded: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def aes_encrypt_bytes(key: bytes, plaintext: bytes) -> dict:
    """
    Encrypts plaintext using AES-128-CBC with PKCS7 padding.
    Returns: {"iv": bytes, "ct": bytes}  ← RAW BYTES (exactly what client/server expect)
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long")

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padded = _pad(plaintext)
    ct = encryptor.update(padded) + encryptor.finalize()

    return {"iv": iv, "ct": ct}


def aes_decrypt_bytes(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts AES-128-CBC ciphertext with PKCS7 padding.
    Input: key (bytes), iv (bytes), ct (bytes)
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return _unpad(padded)