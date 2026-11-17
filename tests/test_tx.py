import pytest

from btcbasics import parse_transaction

# Genesis coinbase, the first transaction on the Bitcoin chain.
GENESIS_TX = bytes.fromhex(
    "0100000001000000000000000000000000000000000000000000000000000000"
    "0000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a"
    "616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f662073"
    "65636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a"
    "01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a679"
    "62e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a"
    "4c702b6bf11d5fac00000000"
)
GENESIS_TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
TIMES_HEADLINE = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"

# First confirmed SegWit transaction, in block 481,824.
# txid and wtxid (hash) are from the Bitcoin chain.
SEGWIT_TX = bytes.fromhex(
    "010000000001015836964079411659db5a4cfddd70e3f0de0261268f86c998a6"
    "9a143f47c6c83800000000171600149445e8b825f1a17d5e091948545c906540"
    "96db68ffffffff02d8be04000000000017a91422c17a06117b40516f98268048"
    "00003562e834c98700000000000000004d6a4b424950313431205c6f2f204865"
    "6c6c6f20536567576974203a2d29206b656570206974207374726f6e6721204c"
    "4c415020426974636f696e20747769747465722e636f6d2f6b6873396e650248"
    "3045022100aaa281e0611ba0b5a2cd055f77e5594709d611ad1233e7096394f6"
    "4ffe16f5b202207e2dcc9ef3a54c24471799ab99f6615847b21be2a6b4e02859"
    "18fd025597c5740121021ec0613f21c4e81c4b300426e5e5d30fa651f41e9993"
    "223adbe74dbe603c74fb00000000"
)
SEGWIT_TXID = "8f907925d2ebe48765103e6845c06f1f2bb77c6adc1cc002865865eb5cfd5c1c"
SEGWIT_WTXID = "6117d821f97e3bebab845a8d2378817db4345d8a24012e3dc8f15100a37d5ded"
SEGWIT_PREV = "38c8c6473f149aa698c9868f266102def0e370ddfd4c5adb5916417940963658"


def test_genesis_coinbase():
    tx = parse_transaction(GENESIS_TX)
    assert tx.version == 1
    assert tx.segwit is False
    assert tx.is_coinbase
    assert tx.locktime == 0
    assert len(tx.inputs) == 1
    assert len(tx.outputs) == 1
    assert tx.inputs[0].prev_txid == "00" * 32
    assert tx.inputs[0].prev_index == 0xFFFFFFFF
    assert tx.inputs[0].sequence == 0xFFFFFFFF
    assert TIMES_HEADLINE in tx.inputs[0].script_sig
    assert tx.outputs[0].value == 5_000_000_000
    assert tx.txid() == GENESIS_TXID
    assert tx.wtxid() == GENESIS_TXID
    assert tx.serialize() == GENESIS_TX
    assert tx.serialize(witness=True) == GENESIS_TX
    assert tx.size() == 204
    assert tx.weight() == 816
    assert tx.vsize() == 204


def test_first_segwit_transaction():
    tx = parse_transaction(SEGWIT_TX)
    assert tx.version == 1
    assert tx.segwit is True
    assert not tx.is_coinbase
    assert tx.locktime == 0
    assert len(tx.inputs) == 1
    assert len(tx.outputs) == 2
    assert tx.inputs[0].prev_txid == SEGWIT_PREV
    assert tx.inputs[0].prev_index == 0
    assert tx.inputs[0].sequence == 0xFFFFFFFF
    assert len(tx.inputs[0].witness) == 2
    assert tx.outputs[0].value == 311_000
    assert tx.outputs[1].value == 0
    assert tx.outputs[0].script_pubkey.hex() == (
        "a91422c17a06117b40516f9826804800003562e834c987"
    )
    assert b"BIP141" in tx.outputs[1].script_pubkey
    assert tx.txid() == SEGWIT_TXID
    assert tx.wtxid() == SEGWIT_WTXID
    assert tx.txid() != tx.wtxid()
    assert tx.serialize() == SEGWIT_TX
    assert tx.size() == 302
    assert tx.weight() == 878
    assert tx.vsize() == 220
    # The txid preimage omits marker, flag and witness.
    stripped = tx.serialize(witness=False)
    assert stripped.startswith(b"\x01\x00\x00\x00\x01")
    assert len(stripped) == 192
    assert parse_transaction(stripped).segwit is False
    assert parse_transaction(stripped).txid() == SEGWIT_TXID


def test_accepts_bytes_like():
    assert parse_transaction(bytearray(GENESIS_TX)).txid() == GENESIS_TXID
    assert parse_transaction(memoryview(GENESIS_TX)).txid() == GENESIS_TXID


def test_truncated_and_trailing():
    with pytest.raises(ValueError, match="truncated"):
        parse_transaction(GENESIS_TX[:-1])
    with pytest.raises(ValueError, match="trailing data"):
        parse_transaction(GENESIS_TX + b"\x00")
    with pytest.raises(TypeError, match="expected bytes-like"):
        parse_transaction(GENESIS_TX.hex())


def test_rejects_zero_inputs():
    # version 1, marker/flag missing, vin count 0, vout count 0, locktime 0
    with pytest.raises(ValueError, match="no inputs"):
        parse_transaction(bytes.fromhex("01000000000000000000"))
