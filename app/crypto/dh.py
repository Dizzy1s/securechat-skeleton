from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def generate_parameters(key_size: int = 2048):
    return dh.generate_parameters(generator=2, key_size=key_size)


def generate_private_key(parameters):
    return parameters.generate_private_key()


def public_int_from_private(private_key):
    return private_key.public_key().public_numbers().y


def _peer_public_from_int(y_int: int, local_private_key):
    params = local_private_key.parameters()
    numbers = dh.DHPublicNumbers(y_int, params.parameter_numbers())
    return numbers.public_key()


def derive_aes16_from_shared(local_private_key, peer_public_int: int) -> bytes:
    """
    THIS ORDER IS NOW FIXED AND CONSISTENT EVERYWHERE:
    derive_aes16_from_shared(my_private_key, their_public_int)
    """
    peer_pub = _peer_public_from_int(peer_public_int, local_private_key)
    shared_secret = local_private_key.exchange(peer_pub)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"SECURECHAT2025",   # ← Exact same on client AND server
    ).derive(shared_secret)