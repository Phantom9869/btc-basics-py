import pytest

from btcbasics import merkle_root, sha256d, txid_from_hash
from btcbasics.txid import hash_from_txid

# Genesis coinbase is the only transaction in block 0, so the merkle
# root is the txid itself.
GENESIS_TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

# Block 170: coinbase + the first payment (Satoshi to Hal Finney).
BLOCK_170_COINBASE = "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082"
BLOCK_170_PAYMENT = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
BLOCK_170_ROOT = "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"


def test_genesis_single_txid():
    assert merkle_root([GENESIS_TXID]) == GENESIS_TXID
    assert merkle_root((GENESIS_TXID,)) == GENESIS_TXID


def test_block_170_merkle_root():
    assert merkle_root([BLOCK_170_COINBASE, BLOCK_170_PAYMENT]) == BLOCK_170_ROOT
    # Order is significant: swapping the two leaves must not produce
    # the header's merkle root.
    assert merkle_root([BLOCK_170_PAYMENT, BLOCK_170_COINBASE]) != BLOCK_170_ROOT


def test_odd_count_duplicates_last_hash():
    # Bitcoin duplicates the last hash when a merkle level has an odd
    # number of entries. Check that against a direct SHA256d of C||C.
    a, b, c = GENESIS_TXID, BLOCK_170_COINBASE, BLOCK_170_PAYMENT
    root = merkle_root([a, b, c])
    ha, hb, hc = hash_from_txid(a), hash_from_txid(b), hash_from_txid(c)
    left = sha256d(ha + hb)
    right = sha256d(hc + hc)
    assert root == txid_from_hash(sha256d(left + right))


def test_whitespace_and_0x_prefix():
    assert merkle_root(["  0x" + GENESIS_TXID + "\n"]) == GENESIS_TXID


def test_errors():
    with pytest.raises(ValueError, match="at least one"):
        merkle_root([])
    with pytest.raises(TypeError, match="sequence of txids"):
        merkle_root(GENESIS_TXID)
    with pytest.raises(TypeError, match="sequence of txids"):
        merkle_root(1)
    with pytest.raises(ValueError, match="32 bytes"):
        merkle_root(["00"])
