from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]


def _as_bytes(data: BytesLike, name: str) -> bytes:
    if isinstance(data, memoryview):
        data = data.tobytes()
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{name}() expected bytes-like, got {type(data).__name__}")
    return bytes(data)


def _parse_txid_hex(value: str, name: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{name}() expected str, got {type(value).__name__}")
    raw = value.strip()
    if raw[:2].lower() == "0x":
        raw = raw[2:]
    try:
        data = bytes.fromhex(raw)
    except ValueError:
        raise ValueError(f"{name}() expected 32-byte hex, got {value!r}") from None
    if len(data) != 32:
        raise ValueError(f"{name}() expected 32 bytes, got {len(data)}")
    return data


def txid_from_hash(digest: BytesLike) -> str:
    """Return the display txid or block hash for a 32-byte internal digest.

    Bitcoin RPC and block explorers show SHA256d results in reverse byte
    order from the bytes stored in a block header or used inside a
    transaction.
    """
    data = _as_bytes(digest, "txid_from_hash")
    if len(data) != 32:
        raise ValueError(f"txid_from_hash() expected 32 bytes, got {len(data)}")
    return data[::-1].hex()


def hash_from_txid(txid: str) -> bytes:
    """Parse a display txid or block hash into the 32-byte internal digest."""
    return _parse_txid_hex(txid, "hash_from_txid")[::-1]
