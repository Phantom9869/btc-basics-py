import hashlib

from . import ripemd160 as _ripemd160


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    return sha256(sha256(data))


def ripemd160(data: bytes) -> bytes:
    # OpenSSL 3 moved ripemd160 to the legacy provider, so hashlib may not
    # have it. Fall back to the pure Python version in that case.
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        return _ripemd160.digest(data)


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))
