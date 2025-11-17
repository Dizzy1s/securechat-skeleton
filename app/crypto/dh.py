# app/crypto/dh.py
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import Hash

def generate_parameters(key_size: int = 2048):
    return dh.generate_parameters(generator=2, key_size=key_size)

def generate_private_key(parameters):
    return parameters.generate_private_key()

def public_int_from_private(priv):
    return priv.public_key().public_numbers().y

def make_peer_public_from_int(peer_y: int, priv):
    params = priv.private_numbers().parameter_numbers
    pn = dh.DHPublicNumbers(peer_y, params)
    return pn.public_key()

def derive_aes16_from_shared(priv, peer_y: int) -> bytes:
    """Derive 16-byte AES key = Trunc16(SHA256(shared_secret_bytes))."""
    peer_pub = make_peer_public_from_int(peer_y, priv)
    shared = priv.exchange(peer_pub)  # raw shared bytes
    digest = Hash(hashes.SHA256())
    digest.update(shared)
    full = digest.finalize()
    return full[:16]
