# app/crypto/dh.py
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_parameters(key_size: int = 2048):
    """
    Generate DH parameters (safe prime + generator).
    Uses RFC 7919 standardized groups in modern versions.
    """
    return dh.generate_parameters(generator=2, key_size=key_size)


def generate_private_key(parameters) -> dh.DHPrivateKey:
    """Generate a private key from the given parameters."""
    return parameters.generate_private_key()


def public_int_from_private(priv: dh.DHPrivateKey) -> int:
    """Extract the public value (Y = g^x mod p) as integer."""
    return priv.public_key().public_numbers().y


def make_peer_public_from_int(peer_y: int, local_private_key: dh.DHPrivateKey) -> dh.DHPublicKey:
    """
    Reconstruct the peer's DHPublicKey from the integer they sent.
    This is required for .exchange() — fixed for cryptography ≥42.0.0
    """
    # Correct way in 2025+: use .parameters() on the private key
    params = local_private_key.parameters()
    peer_numbers = dh.DHPublicNumbers(peer_y, params.parameter_numbers())
    return peer_numbers.public_key()


def derive_aes16_from_shared(local_private_key: dh.DHPrivateKey, peer_y: int) -> bytes:
    """
    Perform DH key exchange and derive a strong 16-byte AES key using HKDF-SHA256.
    This is the recommended modern way (better than raw SHA256 truncate).
    """
    peer_pub = make_peer_public_from_int(peer_y, local_private_key)
    shared_secret = local_private_key.exchange(peer_pub)

    # HKDF-SHA256 with info string for domain separation
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,                    # Ephemeral DH → no salt needed
        info=b"securechat-session-v1",  # Change per usage context if needed
    ).derive(shared_secret)

    return derived_key