import pytest

from btcbasics.bech32 import (
    BECH32,
    BECH32M,
    bech32_decode,
    bech32_decode_any,
    bech32_encode,
    bech32m_decode,
    bech32m_encode,
    convertbits,
)

# Official BIP 173 valid Bech32 strings (not necessarily SegWit addresses).
VALID_BECH32 = [
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
]

# Official BIP 173 invalid Bech32 strings.
INVALID_BECH32 = [
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    "pzry9x0s0muk",
    "1pzry9x0s0muk",
    "x1b4n0q5v",
    "li1dgmt3",
    "10a06t8",
    "1qzzfhee",
]


@pytest.mark.parametrize("encoded", VALID_BECH32)
def test_official_valid_bech32(encoded):
    hrp, data = bech32_decode(encoded)
    assert bech32_encode(hrp, data) == encoded.lower()


@pytest.mark.parametrize("encoded", INVALID_BECH32)
def test_official_invalid_bech32(encoded):
    with pytest.raises(ValueError):
        bech32_decode(encoded)


def test_decode_rejects_mixed_case():
    with pytest.raises(ValueError, match="mixed-case"):
        bech32_decode("A12uel5L")


def test_decode_strips_whitespace():
    hrp, data = bech32_decode("  a12uel5l\n")
    assert hrp == "a"
    assert bech32_encode(hrp, data) == "a12uel5l"


def test_decode_rejects_non_str():
    with pytest.raises(TypeError, match=r"bech32_decode\(\) expected str"):
        bech32_decode(b"a12uel5l")


def test_encode_always_lowercase():
    assert bech32_encode("A", []) == "a12uel5l"


def test_encode_rejects_out_of_range_values():
    with pytest.raises(ValueError, match="0-31"):
        bech32_encode("bc", [32])


def test_convertbits_roundtrip():
    payload = list(bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6"))
    five = convertbits(payload, 8, 5)
    assert five is not None
    back = convertbits(five, 5, 8, pad=False)
    assert back == payload


def test_convertbits_rejects_non_zero_padding():
    # 5-bit groups that cannot be packed back into bytes without leftover bits.
    assert convertbits([0x1F], 5, 8, pad=False) is None


# Official BIP 350 valid Bech32m strings (not necessarily SegWit addresses).
VALID_BECH32M = [
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
]

# Official BIP 350 invalid Bech32m strings.
INVALID_BECH32M = [
    "\x201xj0phk",
    "\x7f1g6xzxy",
    "\x801vctc34",
    "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
    "qyrz8wqd2c9m",
    "1qyrz8wqd2c9m",
    "y1b0jsk6g",
    "lt1igcx5c0",
    "in1muywd",
    "mm1crxm3i",
    "au1s5cgom",
    "M1VUXWEZ",
    "16plkw9",
    "1p2gdwpf",
]


@pytest.mark.parametrize("encoded", VALID_BECH32M)
def test_official_valid_bech32m(encoded):
    hrp, data = bech32m_decode(encoded)
    assert bech32m_encode(hrp, data) == encoded.lower()
    got_hrp, got_data, encoding = bech32_decode_any(encoded)
    assert (got_hrp, got_data, encoding) == (hrp, data, BECH32M)


@pytest.mark.parametrize("encoded", INVALID_BECH32M)
def test_official_invalid_bech32m(encoded):
    with pytest.raises(ValueError):
        bech32m_decode(encoded)


@pytest.mark.parametrize("encoded", VALID_BECH32M)
def test_bech32_decode_rejects_bech32m(encoded):
    # A string cannot be valid Bech32 and Bech32m at the same time.
    with pytest.raises(ValueError, match="checksum"):
        bech32_decode(encoded)


@pytest.mark.parametrize("encoded", VALID_BECH32)
def test_bech32m_decode_rejects_bech32(encoded):
    with pytest.raises(ValueError, match="checksum"):
        bech32m_decode(encoded)


def test_decode_any_distinguishes_encodings():
    hrp, data, encoding = bech32_decode_any("a12uel5l")
    assert encoding == BECH32
    assert bech32_encode(hrp, data) == "a12uel5l"

    hrp, data, encoding = bech32_decode_any("a1lqfn3a")
    assert encoding == BECH32M
    assert bech32m_encode(hrp, data) == "a1lqfn3a"


def test_encode_accepts_encoding_argument():
    assert bech32_encode("a", [], encoding=BECH32) == "a12uel5l"
    assert bech32_encode("a", [], encoding=BECH32M) == "a1lqfn3a"


def test_encode_rejects_unknown_encoding():
    with pytest.raises(ValueError, match="unknown Bech32 encoding"):
        bech32_encode("a", [], encoding=0)


def test_decode_rejects_longer_than_90_characters():
    # Official BIP 350 vector: 84-character HRP makes the string 91 long.
    too_long = "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4"
    assert len(too_long) == 91
    with pytest.raises(ValueError, match="90 characters"):
        bech32_decode_any(too_long)


def test_bech32m_decode_strips_whitespace():
    hrp, data = bech32m_decode("  a1lqfn3a\n")
    assert hrp == "a"
    assert bech32m_encode(hrp, data) == "a1lqfn3a"


def test_bech32m_decode_rejects_non_str():
    with pytest.raises(TypeError, match=r"bech32m_decode\(\) expected str"):
        bech32m_decode(b"a1lqfn3a")
