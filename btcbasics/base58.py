from .hashes import _as_bytes, sha256d

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}


def b58encode(data: bytes) -> str:
    data = _as_bytes(data, "b58encode")
    num = int.from_bytes(data, "big")
    out = []
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(ALPHABET[rem])

    # Leading zero bytes vanish when the bytes are turned into an integer,
    # so each one is written as a '1' (the zero digit) to keep the length.
    zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * zeros + "".join(reversed(out))


def b58decode(s: str) -> bytes:
    if not isinstance(s, str):
        raise TypeError(f"b58decode() expected str, got {type(s).__name__}")
    # Bitcoin Core's DecodeBase58 ignores leading and trailing spaces so
    # a pasted address with a newline still decodes. Spaces in the middle
    # stay invalid.
    s = s.strip()
    num = 0
    for i, c in enumerate(s):
        if c not in _INDEX:
            raise ValueError(f"invalid base58 character: {c!r} at position {i}")
        num = num * 58 + _INDEX[c]

    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    zeros = len(s) - len(s.lstrip("1"))
    return b"\x00" * zeros + body


def b58encode_check(payload: bytes) -> str:
    payload = _as_bytes(payload, "b58encode_check")
    checksum = sha256d(payload)[:4]
    return b58encode(payload + checksum)


def b58decode_check(s: str) -> bytes:
    if not isinstance(s, str):
        raise TypeError(f"b58decode_check() expected str, got {type(s).__name__}")
    raw = b58decode(s)
    if len(raw) < 4:
        raise ValueError("too short for base58check")
    payload, checksum = raw[:-4], raw[-4:]
    if sha256d(payload)[:4] != checksum:
        raise ValueError("bad checksum")
    return payload
