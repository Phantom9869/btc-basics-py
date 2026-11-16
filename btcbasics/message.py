from typing import Union

from .hashes import sha256d
from .varint import encode_compact_size

BytesLike = Union[bytes, bytearray, memoryview]

# The 24-byte header Bitcoin Core prepends before the message length and body.
# HashWriter serializes it as CompactSize(24) || header, i.e. 0x18 + header.
MESSAGE_MAGIC = b"Bitcoin Signed Message:\n"


def _as_message_bytes(message: Union[str, BytesLike]) -> bytes:
    if isinstance(message, str):
        return message.encode("utf-8")
    if isinstance(message, memoryview):
        message = message.tobytes()
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(
            f"signed_message_hash() expected str or bytes-like, got {type(message).__name__}"
        )
    return bytes(message)


def signed_message_hash(message: Union[str, BytesLike]) -> bytes:
    """Return the SHA256d digest used when signing a Bitcoin message.

    This is HashWriter << "Bitcoin Signed Message:\n" << message, the same
    construction Bitcoin Core's MessageHash() uses: each string is written
    as a CompactSize length prefix followed by the UTF-8 (or raw) bytes.
    """
    body = _as_message_bytes(message)
    payload = (
        encode_compact_size(len(MESSAGE_MAGIC))
        + MESSAGE_MAGIC
        + encode_compact_size(len(body))
        + body
    )
    return sha256d(payload)
