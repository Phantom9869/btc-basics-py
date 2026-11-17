import pytest

from btcbasics.__main__ import main


def test_encode_with_version(capsys):
    assert main(["encode", "62e907b15cbf27d5425399ebf6f0fb50ebb88f18", "--version", "0x00"]) == 0
    assert capsys.readouterr().out.strip() == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def test_decode_valid(capsys):
    assert main(["decode", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]) == 0
    out = capsys.readouterr().out
    assert "0x00 (mainnet P2PKH)" in out
    assert "62e907b15cbf27d5425399ebf6f0fb50ebb88f18" in out


def test_decode_invalid(capsys):
    assert main(["decode", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"]) == 1
    assert "bad checksum" in capsys.readouterr().err


def test_hash(capsys):
    assert main(["hash", "sha256", "616263"]) == 0
    assert capsys.readouterr().out.strip().startswith("ba7816bf")


def test_version_out_of_range(capsys):
    assert main(["encode", "00", "--version", "256"]) == 1


def test_hash_accepts_0x_prefix(capsys):
    assert main(["hash", "sha256", "0x616263"]) == 0
    assert capsys.readouterr().out.strip().startswith("ba7816bf")


def test_hash_accepts_uppercase_0x_and_spaces(capsys):
    assert main(["hash", "sha256", "  0X61 62 63  "]) == 0
    assert capsys.readouterr().out.strip().startswith("ba7816bf")


def test_encode_payload_accepts_0x_prefix(capsys):
    assert main(["encode", "0x62e907b15cbf27d5425399ebf6f0fb50ebb88f18", "--version", "0x00"]) == 0
    assert capsys.readouterr().out.strip() == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def test_invalid_hex_still_rejected():
    with pytest.raises(SystemExit):
        main(["hash", "sha256", "0xzz"])


WIF_UNCOMPRESSED = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
WIF_PRIV = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"


def test_decode_wif(capsys):
    assert main(["decode", WIF_UNCOMPRESSED]) == 0
    out = capsys.readouterr().out
    assert "0x80 (mainnet WIF)" in out
    assert f"private key: {WIF_PRIV}" in out
    assert "compressed: no" in out


def test_wif_encode_uncompressed(capsys):
    assert main(["wif", "encode", WIF_PRIV, "--uncompressed"]) == 0
    assert capsys.readouterr().out.strip() == WIF_UNCOMPRESSED


def test_wif_decode(capsys):
    assert main(["wif", "decode", WIF_UNCOMPRESSED]) == 0
    out = capsys.readouterr().out
    assert f"private key: {WIF_PRIV}" in out
    assert "compressed: no" in out
    assert "testnet: no" in out


def test_wif_encode_rejects_short_key(capsys):
    assert main(["wif", "encode", "00"]) == 1
    assert "32 bytes" in capsys.readouterr().err


def test_address_p2pkh_from_hash(capsys):
    assert main(["address", "p2pkh", "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"]) == 0
    assert capsys.readouterr().out.strip() == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def test_address_p2sh_testnet(capsys):
    assert main(["address", "p2sh", "f815b036d9bbbce5e9f2a00abd1bf3dc91e95510", "--testnet"]) == 0
    addr = capsys.readouterr().out.strip()
    assert addr.startswith("2")


def test_address_rejects_bad_length(capsys):
    assert main(["address", "p2pkh", "00"]) == 1
    assert "20-byte HASH160" in capsys.readouterr().err


P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
P2WPKH_HASH = "751e76e8199196d454941c45d1b3a323f1433bd6"
P2WSH_HASH = "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
P2WSH_TESTNET = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"


def test_address_p2wpkh(capsys):
    assert main(["address", "p2wpkh", P2WPKH_HASH]) == 0
    assert capsys.readouterr().out.strip() == P2WPKH


def test_address_p2wsh_testnet(capsys):
    assert main(["address", "p2wsh", P2WSH_HASH, "--testnet"]) == 0
    assert capsys.readouterr().out.strip() == P2WSH_TESTNET


def test_decode_segwit(capsys):
    assert main(["decode", P2WPKH]) == 0
    out = capsys.readouterr().out
    assert "bc (mainnet P2WPKH)" in out
    assert "witness version: 0" in out
    assert P2WPKH_HASH in out


def test_decode_segwit_invalid(capsys):
    assert main(["decode", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"]) == 1
    assert "checksum" in capsys.readouterr().err


import json


def test_json_hash(capsys):
    assert main(["--json", "hash", "sha256", "616263"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["algo"] == "sha256"
    assert data["digest"].startswith("ba7816bf")


def test_json_flag_after_subcommand(capsys):
    assert main(["hash", "--json", "sha256", "616263"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["digest"].startswith("ba7816bf")


def test_json_decode_p2pkh(capsys):
    assert main(["--json", "decode", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {
        "type": "mainnet P2PKH",
        "version": 0,
        "payload": "62e907b15cbf27d5425399ebf6f0fb50ebb88f18",
    }


def test_json_decode_segwit(capsys):
    assert main(["--json", "decode", P2WPKH]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["type"] == "mainnet P2WPKH"
    assert data["hrp"] == "bc"
    assert data["witness_version"] == 0
    assert data["program"] == P2WPKH_HASH


def test_json_address_and_wif(capsys):
    assert main(["--json", "address", "p2pkh", "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["address"] == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert data["type"] == "p2pkh"
    assert data["testnet"] is False

    assert main(["--json", "wif", "decode", WIF_UNCOMPRESSED]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {"private_key": WIF_PRIV, "compressed": False, "testnet": False}


def test_json_does_not_change_error_output(capsys):
    assert main(["--json", "decode", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "bad checksum" in captured.err


P2TR = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
P2TR_KEY = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
P2TR_TESTNET = "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c"
P2TR_TESTNET_KEY = "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
V16 = "bc1sw50qgdz25j"


def test_address_p2tr(capsys):
    assert main(["address", "p2tr", P2TR_KEY]) == 0
    assert capsys.readouterr().out.strip() == P2TR


def test_address_p2tr_testnet(capsys):
    assert main(["address", "p2tr", P2TR_TESTNET_KEY, "--testnet"]) == 0
    assert capsys.readouterr().out.strip() == P2TR_TESTNET


def test_decode_p2tr(capsys):
    assert main(["decode", P2TR]) == 0
    out = capsys.readouterr().out
    assert "bc (mainnet P2TR)" in out
    assert "witness version: 1" in out
    assert P2TR_KEY in out


def test_decode_witness_v16(capsys):
    assert main(["decode", V16]) == 0
    out = capsys.readouterr().out
    assert "bc (mainnet witness v16)" in out
    assert "witness version: 16" in out
    assert "751e" in out


def test_json_decode_p2tr(capsys):
    assert main(["--json", "decode", P2TR]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["type"] == "mainnet P2TR"
    assert data["hrp"] == "bc"
    assert data["witness_version"] == 1
    assert data["program"] == P2TR_KEY


def test_address_p2tr_rejects_bad_length(capsys):
    assert main(["address", "p2tr", "00"]) == 1
    assert "32-byte x-only public key" in capsys.readouterr().err


def test_validate_p2pkh(capsys):
    assert main(["validate", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]) == 0
    out = capsys.readouterr().out
    assert "valid: yes" in out
    assert "type: p2pkh" in out
    assert "network: mainnet" in out
    assert "62e907b15cbf27d5425399ebf6f0fb50ebb88f18" in out


def test_validate_p2tr(capsys):
    assert main(["validate", P2TR]) == 0
    out = capsys.readouterr().out
    assert "valid: yes" in out
    assert "type: p2tr" in out
    assert "network: mainnet" in out
    assert "witness version: 1" in out
    assert P2TR_KEY in out


def test_validate_witness_v16(capsys):
    assert main(["validate", V16]) == 0
    out = capsys.readouterr().out
    assert "type: witness v16" in out
    assert "witness version: 16" in out


def test_validate_wif(capsys):
    assert main(["validate", WIF_UNCOMPRESSED]) == 0
    out = capsys.readouterr().out
    assert "type: wif" in out
    assert f"private key: {WIF_PRIV}" in out
    assert "compressed: no" in out


def test_validate_invalid(capsys):
    assert main(["validate", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"]) == 1
    out = capsys.readouterr().out
    assert "valid: no" in out
    assert "error: bad checksum" in out


def test_json_validate_p2tr(capsys):
    assert main(["--json", "validate", P2TR]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {
        "valid": True,
        "type": "p2tr",
        "network": "mainnet",
        "witness_version": 1,
        "program": P2TR_KEY,
    }


def test_json_validate_invalid(capsys):
    assert main(["--json", "validate", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["valid"] is False
    assert data["type"] == "unknown"
    assert "checksum" in data["error"]


def test_scriptpubkey_p2tr(capsys):
    assert main(["scriptpubkey", P2TR]) == 0
    assert capsys.readouterr().out.strip() == "5120" + P2TR_KEY


def test_scriptpubkey_from_script(capsys):
    assert main(["scriptpubkey", "--from-script", "5120" + P2TR_KEY]) == 0
    assert capsys.readouterr().out.strip() == P2TR


def test_scriptpubkey_from_script_testnet(capsys):
    assert main(["scriptpubkey", "--from-script", "0020" + P2WSH_HASH, "--testnet"]) == 0
    assert capsys.readouterr().out.strip() == P2WSH_TESTNET


def test_scriptpubkey_rejects_wif(capsys):
    assert main(["scriptpubkey", WIF_UNCOMPRESSED]) == 1
    assert "WIF" in capsys.readouterr().err


def test_scriptpubkey_requires_argument(capsys):
    assert main(["scriptpubkey"]) == 1
    assert "required" in capsys.readouterr().err


def test_json_scriptpubkey(capsys):
    assert main(["--json", "scriptpubkey", P2TR]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {"scriptpubkey": "5120" + P2TR_KEY}


def test_varint_encode(capsys):
    assert main(["varint", "encode", "253"]) == 0
    assert capsys.readouterr().out.strip() == "fdfd00"


def test_varint_encode_accepts_hex(capsys):
    assert main(["varint", "encode", "0xffff"]) == 0
    assert capsys.readouterr().out.strip() == "fdffff"


def test_varint_decode(capsys):
    assert main(["varint", "decode", "0xfdfd00"]) == 0
    assert capsys.readouterr().out.strip() == "253"


def test_varint_decode_rejects_noncanonical(capsys):
    assert main(["varint", "decode", "fd0000"]) == 1
    assert "non-canonical" in capsys.readouterr().err


def test_varint_decode_rejects_trailing_data(capsys):
    assert main(["varint", "decode", "01ab"]) == 1
    assert "trailing data" in capsys.readouterr().err


def test_json_varint(capsys):
    assert main(["--json", "varint", "encode", "253"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {"value": 253, "encoded": "fdfd00"}


def test_message_hash(capsys):
    assert main(["message-hash", "Hello World"]) == 0
    assert capsys.readouterr().out.strip() == (
        "a7af0baad5ae99b97fc69b3a0d1abcf3ef17f131cc4776e1bc11933ec8550f49"
    )


def test_json_message_hash(capsys):
    assert main(["--json", "message-hash", "hello"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {
        "message": "hello",
        "hash": "cf0447ec85f0ce7150a257db32ebfcb7523dae17c36dbd1be598779fec0484f4",
    }


GENESIS_TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
GENESIS_MERKLE_INTERNAL = "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"


def test_txid(capsys):
    assert main(["txid", GENESIS_MERKLE_INTERNAL]) == 0
    assert capsys.readouterr().out.strip() == GENESIS_TXID
    assert main(["txid", "0x" + GENESIS_TXID]) == 0
    assert capsys.readouterr().out.strip() == GENESIS_MERKLE_INTERNAL


def test_txid_rejects_wrong_length(capsys):
    assert main(["txid", "00" * 31]) == 1
    assert "32 bytes" in capsys.readouterr().err


def test_json_txid(capsys):
    assert main(["--json", "txid", GENESIS_MERKLE_INTERNAL]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {"input": GENESIS_MERKLE_INTERNAL, "reversed": GENESIS_TXID}


BIP39_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
BIP39_SEED = (
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
    "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
)


def test_seed(capsys):
    assert main(["seed", BIP39_MNEMONIC, "--passphrase", "TREZOR"]) == 0
    assert capsys.readouterr().out.strip() == BIP39_SEED


def test_seed_rejects_bad_checksum(capsys):
    bad = BIP39_MNEMONIC.rsplit(" ", 1)[0] + " abandon"
    assert main(["seed", bad]) == 1
    assert "checksum" in capsys.readouterr().err


def test_json_seed(capsys):
    assert main(["--json", "seed", BIP39_MNEMONIC, "--passphrase", "TREZOR"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {
        "seed": BIP39_SEED,
        "entropy": "00" * 16,
        "words": 12,
    }



XPRV_V1 = (
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv"
    "NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
)
XPUB_V1 = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ES"
    "FjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)
BIP32_SEED = "000102030405060708090a0b0c0d0e0f"


def test_xkey_master(capsys):
    assert main(["xkey", "master", BIP32_SEED]) == 0
    assert capsys.readouterr().out.strip() == XPRV_V1


def test_xkey_master_testnet(capsys):
    assert main(["xkey", "master", BIP32_SEED, "--testnet"]) == 0
    assert capsys.readouterr().out.strip().startswith("tprv")


def test_xkey_decode(capsys):
    assert main(["xkey", "decode", XPRV_V1]) == 0
    out = capsys.readouterr().out
    assert "type: mainnet xprv" in out
    assert "depth: 0" in out
    assert "fingerprint: 00000000" in out
    assert "child: 0" in out


def test_xkey_decode_xpub(capsys):
    assert main(["xkey", "decode", XPUB_V1]) == 0
    out = capsys.readouterr().out
    assert "type: mainnet xpub" in out
    assert "public key:" in out


def test_xkey_decode_rejects_bad_checksum(capsys):
    assert main(["xkey", "decode", XPRV_V1[:-1] + "L"]) == 1
    assert "invalid:" in capsys.readouterr().err


def test_json_xkey_master(capsys):
    assert main(["--json", "xkey", "master", BIP32_SEED]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["encoded"] == XPRV_V1
    assert data["type"] == "mainnet xprv"
    assert data["depth"] == 0
    assert data["hardened"] is False
    assert "private_key" in data


GENESIS_HEADER = (
    "0100000000000000000000000000000000000000000000000000000000000000"
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
    "4b1e5e4a29ab5f49ffff001d1dac2b7c"
)
GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


def test_header_genesis(capsys):
    assert main(["header", GENESIS_HEADER]) == 0
    out = capsys.readouterr().out
    assert "version: 1" in out
    assert f"hash: {GENESIS_HASH}" in out
    assert "bits: 0x1d00ffff" in out
    assert "difficulty: 1" in out
    assert "meets target: yes" in out
    assert "nonce: 2083236893" in out


def test_header_rejects_short(capsys):
    assert main(["header", "00" * 79]) == 1
    assert "80 bytes" in capsys.readouterr().err


def test_json_header_genesis(capsys):
    assert main(["--json", "header", "0x" + GENESIS_HEADER]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["hash"] == GENESIS_HASH
    assert data["difficulty"] == "1"
    assert data["meets_target"] is True
    assert data["version"] == 1
    assert data["nonce"] == 2083236893


GENESIS_TX = (
    "0100000001000000000000000000000000000000000000000000000000000000"
    "0000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a"
    "616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f662073"
    "65636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a"
    "01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a679"
    "62e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a"
    "4c702b6bf11d5fac00000000"
)
GENESIS_COINBASE_TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"


def test_tx_genesis(capsys):
    assert main(["tx", GENESIS_TX]) == 0
    out = capsys.readouterr().out
    assert "version: 1" in out
    assert "segwit: no" in out
    assert "coinbase: yes" in out
    assert "  0: 5000000000" in out
    assert f"txid: {GENESIS_COINBASE_TXID}" in out
    assert f"wtxid: {GENESIS_COINBASE_TXID}" in out


def test_tx_rejects_truncated(capsys):
    assert main(["tx", GENESIS_TX[:-2]]) == 1
    assert "invalid:" in capsys.readouterr().err


def test_json_tx_genesis(capsys):
    assert main(["--json", "tx", "0x" + GENESIS_TX]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["txid"] == GENESIS_COINBASE_TXID
    assert data["coinbase"] is True
    assert data["segwit"] is False
    assert data["outputs"][0]["value"] == 5_000_000_000


def test_amount_btc(capsys):
    assert main(["amount", "50"]) == 0
    assert capsys.readouterr().out.strip() == "5000000000"


def test_amount_from_sats(capsys):
    assert main(["amount", "5000000000", "--from-sats"]) == 0
    assert capsys.readouterr().out.strip() == "50"


def test_amount_rejects_too_many_decimals(capsys):
    assert main(["amount", "0.000000001"]) == 1
    assert "invalid:" in capsys.readouterr().err


def test_json_amount(capsys):
    assert main(["--json", "amount", "0.00311"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {"btc": "0.00311", "satoshis": 311000}


BLOCK_170_COINBASE = "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082"
BLOCK_170_PAYMENT = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
BLOCK_170_ROOT = "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"


def test_merkle_genesis(capsys):
    assert main(["merkle", GENESIS_COINBASE_TXID]) == 0
    assert capsys.readouterr().out.strip() == GENESIS_COINBASE_TXID


def test_merkle_block_170(capsys):
    assert main(["merkle", BLOCK_170_COINBASE, BLOCK_170_PAYMENT]) == 0
    assert capsys.readouterr().out.strip() == BLOCK_170_ROOT


def test_merkle_rejects_bad_txid(capsys):
    assert main(["merkle", "00"]) == 1
    assert "invalid:" in capsys.readouterr().err


def test_json_merkle(capsys):
    assert main(["--json", "merkle", BLOCK_170_COINBASE, BLOCK_170_PAYMENT]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["merkle_root"] == BLOCK_170_ROOT
    assert data["transactions"] == 2
