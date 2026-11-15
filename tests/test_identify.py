import pytest

from btcbasics.address import identify_address
from btcbasics.base58 import b58encode_check

GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
P2SH = "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC"
P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
P2WSH = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
P2TR = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
V16 = "BC1SW50QGDZ25J"
WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"


def test_identify_p2pkh():
    info = identify_address(GENESIS)
    assert info.valid
    assert info.type == "p2pkh"
    assert info.network == "mainnet"
    assert info.version == 0
    assert info.payload == bytes.fromhex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18")
    assert info.error is None


def test_identify_p2sh():
    info = identify_address(P2SH)
    assert info.valid
    assert info.type == "p2sh"
    assert info.network == "mainnet"
    assert info.payload == bytes.fromhex("f815b036d9bbbce5e9f2a00abd1bf3dc91e95510")


def test_identify_p2wpkh():
    info = identify_address(P2WPKH)
    assert info.valid
    assert info.type == "p2wpkh"
    assert info.network == "mainnet"
    assert info.version == 0
    assert info.payload == bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")


def test_identify_p2wsh_testnet():
    info = identify_address(P2WSH)
    assert info.valid
    assert info.type == "p2wsh"
    assert info.network == "testnet"
    assert info.version == 0


def test_identify_p2tr():
    info = identify_address("  " + P2TR.upper() + "\n")
    assert info.valid
    assert info.type == "p2tr"
    assert info.network == "mainnet"
    assert info.version == 1
    assert info.payload == bytes.fromhex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )


def test_identify_witness_v16():
    info = identify_address(V16)
    assert info.valid
    assert info.type == "witness"
    assert info.network == "mainnet"
    assert info.version == 16
    assert info.payload == bytes.fromhex("751e")


def test_identify_wif():
    info = identify_address(WIF)
    assert info.valid
    assert info.type == "wif"
    assert info.network == "mainnet"
    assert info.compressed is False
    assert info.payload == bytes.fromhex(
        "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
    )


def test_identify_invalid_checksum():
    info = identify_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
    assert not info.valid
    assert info.type == "unknown"
    assert "checksum" in info.error


def test_identify_invalid_segwit_keeps_network():
    info = identify_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")
    assert not info.valid
    assert info.network == "mainnet"
    assert "checksum" in info.error


def test_identify_wrong_segwit_hrp():
    info = identify_address(
        "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut"
    )
    assert not info.valid
    assert "HRP" in info.error


def test_identify_empty_and_non_str():
    info = identify_address("   ")
    assert not info.valid
    assert info.error == "empty address"
    with pytest.raises(TypeError, match=r"identify_address\(\) expected str"):
        identify_address(b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")


def test_identify_unknown_version_byte():
    # Version 0x1e is not a P2PKH, P2SH or WIF prefix.
    encoded = b58encode_check(b"\x1e" + b"\x11" * 20)
    info = identify_address(encoded)
    assert not info.valid
    assert info.type == "unknown"
    assert info.version == 0x1E
    assert "unknown version byte" in info.error


def test_identify_p2pkh_wrong_payload_length():
    encoded = b58encode_check(b"\x00" + b"\x11" * 21)
    info = identify_address(encoded)
    assert not info.valid
    assert info.type == "p2pkh"
    assert info.network == "mainnet"
    assert "20 byte hash" in info.error
