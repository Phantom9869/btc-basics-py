import pytest

from btcbasics import hash_from_txid, sha256d, txid_from_hash


# Genesis block header and the display hash from Bitcoin Core chainparams.
GENESIS_HEADER = bytes.fromhex(
    "01000000"
    + "00" * 32
    + "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    + "29ab5f49"
    + "ffff001d"
    + "1dac2b7c"
)
GENESIS_BLOCK_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

# Merkle root as stored in the header (internal order) and as asserted in
# Bitcoin Core: genesis.hashMerkleRoot == uint256{"4a5e1e..."}.
GENESIS_MERKLE_INTERNAL = bytes.fromhex(
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
)
GENESIS_TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"


def test_genesis_block_hash_display():
    assert txid_from_hash(sha256d(GENESIS_HEADER)) == GENESIS_BLOCK_HASH
    assert hash_from_txid(GENESIS_BLOCK_HASH) == sha256d(GENESIS_HEADER)


def test_genesis_coinbase_txid():
    assert txid_from_hash(GENESIS_MERKLE_INTERNAL) == GENESIS_TXID
    assert hash_from_txid(GENESIS_TXID) == GENESIS_MERKLE_INTERNAL


def test_roundtrip():
    digest = sha256d(b"hello")
    assert hash_from_txid(txid_from_hash(digest)) == digest
    assert txid_from_hash(hash_from_txid(GENESIS_TXID)) == GENESIS_TXID


def test_hash_from_txid_accepts_0x_and_whitespace():
    assert hash_from_txid("  0x" + GENESIS_TXID + "  ") == GENESIS_MERKLE_INTERNAL
    assert hash_from_txid("0X" + GENESIS_TXID.upper()) == GENESIS_MERKLE_INTERNAL


def test_txid_from_hash_accepts_bytes_like():
    assert txid_from_hash(bytearray(GENESIS_MERKLE_INTERNAL)) == GENESIS_TXID
    assert txid_from_hash(memoryview(GENESIS_MERKLE_INTERNAL)) == GENESIS_TXID


def test_txid_from_hash_rejects_wrong_length():
    with pytest.raises(ValueError, match="expected 32 bytes"):
        txid_from_hash(b"\x00" * 31)
    with pytest.raises(ValueError, match="expected 32 bytes"):
        txid_from_hash(b"\x00" * 33)


def test_hash_from_txid_rejects_wrong_length_and_bad_hex():
    with pytest.raises(ValueError, match="expected 32 bytes"):
        hash_from_txid("00" * 31)
    with pytest.raises(ValueError, match="expected 32-byte hex"):
        hash_from_txid("zz" * 32)


def test_type_errors():
    with pytest.raises(TypeError, match=r"txid_from_hash\(\) expected bytes-like"):
        txid_from_hash(GENESIS_TXID)
    with pytest.raises(TypeError, match=r"hash_from_txid\(\) expected str"):
        hash_from_txid(GENESIS_MERKLE_INTERNAL)
