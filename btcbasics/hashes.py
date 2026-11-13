import hashlib

from . import ripemd160 as _ripemd160


def _as_bytes(data, name):
    if isinstance(data, memoryview):
        data = data.tobytes()
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{name}() expected bytes-like, got {type(data).__name__}")
    return bytes(data)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(_as_bytes(data, "sha256")).digest()


def sha256d(data: bytes) -> bytes:
    return sha256(sha256(_as_bytes(data, "sha256d")))


def ripemd160(data: bytes) -> bytes:
    # OpenSSL 3 moved ripemd160 to the legacy provider, so hashlib may not
    # have it. Fall back to the pure Python version in that case.
    data = _as_bytes(data, "ripemd160")
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        return _ripemd160.digest(data)


def hash160(data: bytes) -> bytes:
    data = _as_bytes(data, "hash160")
    return ripemd160(sha256(data))
