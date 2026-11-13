import pytest

from btcbasics.address import p2pkh_address, p2sh_address
from btcbasics.base58 import b58decode_check
from btcbasics.hashes import hash160

# Genesis coinbase public key and the address it paid to.
GENESIS_PUBKEY = bytes.fromhex(
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
    "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
)
GENESIS_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

# Published vector from the Technical background of version 1 Bitcoin addresses.
PUBKEY = bytes.fromhex(
    "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352"
    "2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6"
)
ADDRESS = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"

P2SH_HASH = bytes.fromhex("f815b036d9bbbce5e9f2a00abd1bf3dc91e95510")
P2SH_ADDRESS = "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC"


def test_p2pkh_from_pubkey_and_hash():
    assert p2pkh_address(GENESIS_PUBKEY) == GENESIS_ADDRESS
    assert p2pkh_address(hash160(GENESIS_PUBKEY)) == GENESIS_ADDRESS
    assert p2pkh_address(PUBKEY) == ADDRESS


def test_p2pkh_from_compressed_pubkey():
    compressed = bytes.fromhex("02" + "11" * 32)
    addr = p2pkh_address(compressed)
    payload = b58decode_check(addr)
    assert payload[0] == 0x00
    assert payload[1:] == hash160(compressed)
    assert addr.startswith("1")


def test_p2pkh_testnet():
    addr = p2pkh_address(GENESIS_PUBKEY, testnet=True)
    payload = b58decode_check(addr)
    assert payload[0] == 0x6F
    assert payload[1:] == hash160(GENESIS_PUBKEY)
    assert addr[0] in "mn"


def test_p2sh_address():
    assert p2sh_address(P2SH_HASH) == P2SH_ADDRESS
    testnet = p2sh_address(P2SH_HASH, testnet=True)
    assert b58decode_check(testnet)[0] == 0xC4
    assert testnet.startswith("2")


def test_p2pkh_rejects_bad_pubkey():
    with pytest.raises(ValueError, match="0x02 or 0x03"):
        p2pkh_address(b"\x01" + b"\x11" * 32)
    with pytest.raises(ValueError, match="0x04"):
        p2pkh_address(b"\x05" + b"\x11" * 64)
    with pytest.raises(ValueError, match="20-byte HASH160"):
        p2pkh_address(b"\x11" * 21)


def test_p2sh_rejects_wrong_length():
    with pytest.raises(ValueError, match="20-byte script hash"):
        p2sh_address(b"\x11" * 21)
