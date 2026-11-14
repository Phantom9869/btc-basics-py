import hashlib
from typing import Union

from . import ripemd160 as _ripemd160

BytesLike = Union[bytes, bytearray, memoryview]


def _as_bytes(data: BytesLike, name: str) -> bytes:
    if isinstance(data, memoryview):
        data = data.tobytes()
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{name}() expected bytes-like, got {type(data).__name__}")
    return bytes(data)


def sha256(data: BytesLike) -> bytes:
    return hashlib.sha256(_as_bytes(data, "sha256")).digest()


def sha256d(data: BytesLike) -> bytes:
    return sha256(sha256(_as_bytes(data, "sha256d")))


def ripemd160(data: BytesLike) -> bytes:
    # OpenSSL 3 moved ripemd160 to the legacy provider, so hashlib may not
    # have it. Fall back to the pure Python version in that case.
    data = _as_bytes(data, "ripemd160")
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        return _ripemd160.digest(data)


def hash160(data: BytesLike) -> bytes:
    data = _as_bytes(data, "hash160")
    return ripemd160(sha256(data))
