import pytest

from btcbasics.address import SegwitAddress, decode_segwit_address, p2pkh_address, p2sh_address, p2wpkh_address, p2wsh_address
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


# BIP 173 official SegWit v0 vectors.
# HASH160 of the compressed secp256k1 generator.
P2WPKH_PUBKEY = bytes.fromhex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
P2WPKH_HASH = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
P2WPKH_ADDRESS = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
P2WPKH_ADDRESS_UPPER = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"

P2WSH_TESTNET = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
P2WSH_TESTNET_HASH = bytes.fromhex(
    "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
)

P2WSH_ZERO = "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy"
P2WSH_ZERO_HASH = bytes.fromhex(
    "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
)


def test_p2wpkh_from_pubkey_and_hash():
    assert p2wpkh_address(P2WPKH_PUBKEY) == P2WPKH_ADDRESS
    assert p2wpkh_address(P2WPKH_HASH) == P2WPKH_ADDRESS


def test_p2wpkh_testnet():
    addr = p2wpkh_address(P2WPKH_HASH, testnet=True)
    got = decode_segwit_address(addr)
    assert got.hrp == "tb"
    assert got.version == 0
    assert got.program == P2WPKH_HASH
    assert addr.startswith("tb1q")


def test_p2wsh_official_vectors():
    assert p2wsh_address(P2WSH_TESTNET_HASH, testnet=True) == P2WSH_TESTNET
    assert p2wsh_address(P2WSH_ZERO_HASH, testnet=True) == P2WSH_ZERO
    mainnet = p2wsh_address(P2WSH_TESTNET_HASH)
    assert mainnet.startswith("bc1q")
    assert decode_segwit_address(mainnet).program == P2WSH_TESTNET_HASH


def test_decode_segwit_accepts_uppercase():
    got = decode_segwit_address(P2WPKH_ADDRESS_UPPER)
    assert got == SegwitAddress(hrp="bc", version=0, program=P2WPKH_HASH)


def test_decode_segwit_strips_whitespace():
    got = decode_segwit_address("  " + P2WPKH_ADDRESS + "\n")
    assert got.program == P2WPKH_HASH


def test_decode_segwit_rejects_mixed_case():
    # Flip a letter; digits like the trailing 4 are the same in both cases.
    mixed = P2WPKH_ADDRESS[:3] + P2WPKH_ADDRESS[3].upper() + P2WPKH_ADDRESS[4:]
    with pytest.raises(ValueError, match="mixed-case"):
        decode_segwit_address(mixed)


def test_decode_segwit_rejects_bad_checksum():
    with pytest.raises(ValueError, match="checksum"):
        decode_segwit_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")


def test_decode_segwit_rejects_wrong_v0_length():
    # BIP 173: BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P is v0 with a 21-byte program.
    with pytest.raises(ValueError, match="20 or 32 bytes"):
        decode_segwit_address("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P")


def test_decode_segwit_rejects_non_v0():
    # BIP 173 witness v16 address, encoded with Bech32 (not Bech32m).
    with pytest.raises(ValueError, match="only witness version 0"):
        decode_segwit_address("BC1SW50QA3JX3S")


def test_p2wpkh_rejects_uncompressed_and_bad_length():
    with pytest.raises(ValueError, match="compressed public key"):
        p2wpkh_address(b"\x04" + b"\x11" * 64)
    with pytest.raises(ValueError, match="20-byte HASH160"):
        p2wpkh_address(b"\x11" * 21)


def test_p2wsh_rejects_wrong_length():
    with pytest.raises(ValueError, match="32-byte script hash"):
        p2wsh_address(b"\x11" * 20)
