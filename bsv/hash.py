import hashlib
import hmac

from Cryptodome.Hash import RIPEMD160


def sha1(payload: bytes) -> bytes:
    # SHA1 is required by Bitcoin Script OP_SHA1 opcode specification
    return hashlib.sha1(payload).digest()  # noqa: S324  # NOSONAR


def sha256(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def double_sha256(payload: bytes) -> bytes:
    return sha256(sha256(payload))


def ripemd160(payload: bytes) -> bytes:
    return RIPEMD160.new(payload).digest()


def ripemd160_sha256(payload: bytes) -> bytes:
    return ripemd160(sha256(payload))


hash256 = double_sha256
hash160 = ripemd160_sha256


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def hmac_sha512(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha512).digest()


def hmac_sha1(key: bytes, message: bytes) -> bytes:
    # SHA1 is required by Bitcoin protocol specifications
    return hmac.new(key, message, hashlib.sha1).digest()  # noqa: S324  # NOSONAR
