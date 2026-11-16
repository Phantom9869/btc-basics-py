import pytest

from btcbasics import decode_compact_size, encode_compact_size


# Canonical encodings from the Bitcoin protocol documentation, plus the
# boundary values Bitcoin Core checks in serialize_tests.cpp.
VECTORS = [
    (0, "00"),
    (1, "01"),
    (252, "fc"),
    (253, "fdfd00"),
    (254, "fdfe00"),
    (0xFFFF, "fdffff"),
    (0x10000, "fe00000100"),
    (0xFFFFFFFF, "feffffffff"),
    (0x100000000, "ff0000000001000000"),
    (0xFFFFFFFFFFFFFFFF, "ffffffffffffffffff"),
]


@pytest.mark.parametrize("value, hex_value", VECTORS)
def test_canonical_vectors(value, hex_value):
    encoded = bytes.fromhex(hex_value)
    assert encode_compact_size(value) == encoded
    assert decode_compact_size(encoded) == (value, b"")


def test_roundtrip_powers_of_two():
    # Matches Bitcoin Core's compactsize test: encode i-1 and i for
    # powers of two up to MAX_SIZE (0x02000000).
    values = []
    i = 1
    while i <= 0x02000000:
        values.extend((i - 1, i))
        i *= 2
    blob = b"".join(encode_compact_size(n) for n in values)
    decoded = []
    rest = blob
    while rest:
        n, rest = decode_compact_size(rest)
        decoded.append(n)
    assert decoded == values


def test_decode_leaves_trailing_bytes():
    assert decode_compact_size(bytes.fromhex("01ab")) == (1, bytes.fromhex("ab"))
    assert decode_compact_size(bytes.fromhex("fdfd00ffff")) == (253, bytes.fromhex("ffff"))


# Non-canonical encodings from Bitcoin Core's noncanonical test.
@pytest.mark.parametrize("hex_value", [
    "fd0000",        # 0 encoded with three bytes
    "fdfc00",        # 0xfc encoded with three bytes
    "fe00000000",    # 0 encoded with five bytes
    "feffff0000",    # 0xffff encoded with five bytes
    "ff0000000000000000",  # 0 encoded with nine bytes
    "ffffffff0100000000",  # 0x01ffffff encoded with nine bytes
])
def test_noncanonical_rejected(hex_value):
    with pytest.raises(ValueError, match="non-canonical compact size"):
        decode_compact_size(bytes.fromhex(hex_value))


def test_canonical_0xfd_is_accepted():
    assert decode_compact_size(bytes.fromhex("fdfd00")) == (253, b"")


# Truncated prefixes from Bitcoin Core's truncated_compact_size test.
@pytest.mark.parametrize("hex_value", ["", "fd", "fd01", "fe010000", "ff01000000000000"])
def test_truncated_rejected(hex_value):
    with pytest.raises(ValueError, match="truncated compact size"):
        decode_compact_size(bytes.fromhex(hex_value))


def test_encode_rejects_negative_and_too_large():
    with pytest.raises(ValueError, match="non-negative"):
        encode_compact_size(-1)
    with pytest.raises(ValueError, match="64 bits"):
        encode_compact_size(0x10000000000000000)


def test_encode_rejects_bool_and_non_int():
    with pytest.raises(TypeError, match="expected int"):
        encode_compact_size(True)
    with pytest.raises(TypeError, match="expected int"):
        encode_compact_size(1.0)


def test_decode_accepts_bytes_like():
    encoded = encode_compact_size(300)
    assert decode_compact_size(bytearray(encoded)) == (300, b"")
    assert decode_compact_size(memoryview(encoded)) == (300, b"")


def test_decode_rejects_str():
    with pytest.raises(TypeError, match=r"decode_compact_size\(\) expected bytes-like"):
        decode_compact_size("00")
