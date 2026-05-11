"""Clean module — does not use any PQ-vulnerable crypto."""
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, data, None)


def sha256_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
