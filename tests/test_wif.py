import pytest

from btcbasics.wif import WIFKey, decode_wif, encode_wif

# Published uncompressed WIF vector (bitcoin.it Wallet import format).
PRIVKEY = bytes.fromhex("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
WIF_UNCOMPRESSED = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"

# Same 32-byte key, encoded with the compressed flag.
PRIVKEY_C = bytes.fromhex("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd")


def test_published_uncompressed_wif():
    assert encode_wif(PRIVKEY, compressed=False) == WIF_UNCOMPRESSED
    got = decode_wif(WIF_UNCOMPRESSED)
    assert got == WIFKey(private_key=PRIVKEY, compressed=False, testnet=False)


def test_compressed_and_testnet_roundtrip():
    wif = encode_wif(PRIVKEY_C, compressed=True)
    got = decode_wif(wif)
    assert got.private_key == PRIVKEY_C
    assert got.compressed is True
    assert got.testnet is False
    assert wif.startswith("K") or wif.startswith("L")

    testnet = encode_wif(PRIVKEY_C, compressed=True, testnet=True)
    got = decode_wif(testnet)
    assert got.private_key == PRIVKEY_C
    assert got.compressed is True
    assert got.testnet is True
    assert testnet.startswith("c")


def test_decode_wif_strips_whitespace():
    assert decode_wif("  " + WIF_UNCOMPRESSED + "\n").private_key == PRIVKEY


def test_encode_wif_rejects_wrong_length():
    with pytest.raises(ValueError, match="32 bytes"):
        encode_wif(b"\x00" * 31)


def test_decode_wif_rejects_address():
    with pytest.raises(ValueError, match="not a WIF version byte"):
        decode_wif("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")


def test_decode_wif_rejects_bad_compressed_flag():
    from btcbasics.base58 import b58encode_check

    bogus = b58encode_check(b"\x80" + PRIVKEY + b"\x02")
    with pytest.raises(ValueError, match="compressed flag"):
        decode_wif(bogus)
