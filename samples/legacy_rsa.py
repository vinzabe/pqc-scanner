"""Legacy crypto sample. Used as a fixture for the scanner tests."""
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH


def make_rsa_key():
    # Classical RSA key generation
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_ecdsa_key():
    return ec.generate_private_key(ec.SECP256R1())


def derive_shared(my_key, peer_pubkey):
    return my_key.exchange(ec.ECDH(), peer_pubkey)


def legacy_hash(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def legacy_sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()
