import pytest

from btcbasics.bech32 import bech32_decode, bech32_encode, convertbits

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
