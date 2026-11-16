import hashlib

import pytest

from btcbasics import MESSAGE_MAGIC, signed_message_hash
from btcbasics.varint import encode_compact_size


def _core_hash(message: bytes) -> bytes:
    # Bitcoin Core's HashWriter << magic << message, built without going
    # through signed_message_hash(): CompactSize(len) || bytes for each
    # string, then SHA256d.
    payload = (
        encode_compact_size(len(MESSAGE_MAGIC))
        + MESSAGE_MAGIC
        + encode_compact_size(len(message))
        + message
    )
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()


def test_magic_is_the_core_header():
    assert MESSAGE_MAGIC == b"Bitcoin Signed Message:\n"
    assert len(MESSAGE_MAGIC) == 24
    assert encode_compact_size(len(MESSAGE_MAGIC)) == b"\x18"


# Independent SHA256d of the well-known construction, including the
# hard-coded 0x18 prefix used in most implementations.
@pytest.mark.parametrize("message, expected", [
    (b"", "80e795d4a4caadd7047af389d9f7f220562feb6196032e2131e10563352c4bcc"),
    (b"hello", "cf0447ec85f0ce7150a257db32ebfcb7523dae17c36dbd1be598779fec0484f4"),
    (b"Hello World", "a7af0baad5ae99b97fc69b3a0d1abcf3ef17f131cc4776e1bc11933ec8550f49"),
])
def test_signed_message_hash_vectors(message, expected):
    prefix = b"\x18Bitcoin Signed Message:\n" + encode_compact_size(len(message)) + message
    assert hashlib.sha256(hashlib.sha256(prefix).digest()).hexdigest() == expected
    assert signed_message_hash(message).hex() == expected
    assert _core_hash(message).hex() == expected


def test_signed_message_hash_accepts_str():
    assert signed_message_hash("Hello World") == signed_message_hash(b"Hello World")


def test_signed_message_hash_utf8():
    text = "caf\u00e9"
    assert signed_message_hash(text) == signed_message_hash(text.encode("utf-8"))
    assert signed_message_hash(text) == _core_hash(text.encode("utf-8"))


def test_long_message_uses_three_byte_varint():
    message = b"a" * 253
    digest = signed_message_hash(message)
    prefix = b"\x18Bitcoin Signed Message:\n\xfd\xfd\x00" + message
    assert hashlib.sha256(hashlib.sha256(prefix).digest()).digest() == digest
    assert digest.hex() == "df167ad249ff5837e6acada677118b2ecc6757ab4cdade39caead99ef0220230"


def test_signed_message_hash_accepts_bytes_like():
    expected = signed_message_hash(b"hello")
    assert signed_message_hash(bytearray(b"hello")) == expected
    assert signed_message_hash(memoryview(b"hello")) == expected


def test_signed_message_hash_rejects_other_types():
    with pytest.raises(TypeError, match="expected str or bytes-like"):
        signed_message_hash(None)
    with pytest.raises(TypeError, match="expected str or bytes-like"):
        signed_message_hash(123)
