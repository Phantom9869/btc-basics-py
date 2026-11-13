import pytest

from btcbasics.base58 import b58decode, b58decode_check, b58encode, b58encode_check

GENESIS_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
GENESIS_HASH160 = "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"


@pytest.mark.parametrize("raw, encoded", [
    ("", ""),
    ("61", "2g"),
    ("626262", "a3gV"),
    ("636363", "aPEr"),
    ("00", "1"),
    ("0000", "11"),
    ("00000000000000000000", "1111111111"),
    ("516b6fcd0f", "ABnLTmg"),
    ("572e4794", "3EFU7m"),
    ("10c8511e", "Rt5zm"),
])
def test_base58_vectors(raw, encoded):
    assert b58encode(bytes.fromhex(raw)) == encoded
    assert b58decode(encoded) == bytes.fromhex(raw)


def test_leading_zeros_preserved():
    data = b"\x00\x00\x01\x02"
    assert b58encode(data).startswith("11")
    assert b58decode(b58encode(data)) == data


def test_invalid_character():
    # 0, O, I and l are left out of the alphabet on purpose.
    for bad in ("0", "O", "I", "l"):
        with pytest.raises(ValueError):
            b58decode("1" + bad)


def test_genesis_address_roundtrip():
    payload = bytes.fromhex("00" + GENESIS_HASH160)
    assert b58encode_check(payload) == GENESIS_ADDRESS
    assert b58decode_check(GENESIS_ADDRESS) == payload


def test_p2sh_address():
    payload = bytes.fromhex("05" + "f815b036d9bbbce5e9f2a00abd1bf3dc91e95510")
    assert b58encode_check(payload) == "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC"


def test_bad_checksum():
    tampered = GENESIS_ADDRESS[:-1] + ("b" if GENESIS_ADDRESS[-1] != "b" else "c")
    with pytest.raises(ValueError, match="checksum"):
        b58decode_check(tampered)


def test_too_short():
    with pytest.raises(ValueError):
        b58decode_check("1")

def test_decode_strips_surrounding_whitespace():
    addr = "  \n" + GENESIS_ADDRESS + "\t\r\n  "
    payload = bytes.fromhex("00" + GENESIS_HASH160)
    assert b58decode_check(addr) == payload


def test_decode_rejects_internal_whitespace():
    with pytest.raises(ValueError, match="invalid base58 character"):
        b58decode("2g 2g")


def test_invalid_character_includes_position():
    with pytest.raises(ValueError, match="at position 1"):
        b58decode("1O")
