from typing import Tuple, Union

BytesLike = Union[bytes, bytearray, memoryview]


def _as_bytes(data: BytesLike, name: str) -> bytes:
    if isinstance(data, memoryview):
        data = data.tobytes()
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{name}() expected bytes-like, got {type(data).__name__}")
    return bytes(data)


def encode_compact_size(n: int) -> bytes:
    """Encode n as a Bitcoin CompactSize (canonical varint)."""
    if isinstance(n, bool) or not isinstance(n, int):
        raise TypeError(f"encode_compact_size() expected int, got {type(n).__name__}")
    if n < 0:
        raise ValueError("compact size must be non-negative")
    if n > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("compact size must fit in 64 bits")
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def decode_compact_size(data: BytesLike) -> Tuple[int, bytes]:
    """Decode a canonical CompactSize.

    Returns (value, remaining_bytes). Rejects truncated or non-canonical
    encodings, matching Bitcoin Core's ReadCompactSize().
    """
    data = _as_bytes(data, "decode_compact_size")
    if not data:
        raise ValueError("truncated compact size")
    prefix = data[0]
    if prefix < 253:
        return prefix, data[1:]
    if prefix == 0xFD:
        need = 3
        width = 2
        minimum = 253
    elif prefix == 0xFE:
        need = 5
        width = 4
        minimum = 0x10000
    else:
        need = 9
        width = 8
        minimum = 0x100000000
    if len(data) < need:
        raise ValueError("truncated compact size")
    value = int.from_bytes(data[1:need], "little")
    if value < minimum:
        raise ValueError("non-canonical compact size")
    return value, data[need:]
