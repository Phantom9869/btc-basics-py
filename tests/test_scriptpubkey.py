import pytest

from btcbasics.address import address_to_scriptpubkey, scriptpubkey_to_address

# Official BIP 350 address <-> scriptPubKey vectors, plus P2PKH and P2SH.
VECTORS = [
    (
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
    ),
    (
        "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC",
        "a914f815b036d9bbbce5e9f2a00abd1bf3dc91e9551087",
    ),
    (
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "0014751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    ),
    (
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
        "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    ("BC1SW50QGDZ25J", "6002751e"),
    (
        "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
        "5210751e76e8199196d454941c45d1b3a323",
    ),
    (
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
    (
        "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
        "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
]

WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"


@pytest.mark.parametrize("addr, script_hex", VECTORS)
def test_official_scriptpubkey_vectors(addr, script_hex):
    assert address_to_scriptpubkey(addr) == bytes.fromhex(script_hex)


@pytest.mark.parametrize("addr, script_hex", VECTORS)
def test_scriptpubkey_roundtrip(addr, script_hex):
    script = address_to_scriptpubkey(addr)
    assert script == bytes.fromhex(script_hex)
    testnet = addr.lower().startswith("tb")
    got = scriptpubkey_to_address(script, testnet=testnet)
    # Base58 addresses are case-sensitive; Bech32 encodes as lowercase.
    expected = addr.lower() if addr.lower().startswith(("bc1", "tb1")) else addr
    assert got == expected


def test_scriptpubkey_rejects_wif():
    with pytest.raises(ValueError, match="WIF"):
        address_to_scriptpubkey(WIF)


def test_scriptpubkey_rejects_invalid_address():
    with pytest.raises(ValueError, match="checksum"):
        address_to_scriptpubkey("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")


def test_scriptpubkey_rejects_unknown_script():
    with pytest.raises(ValueError, match="unsupported scriptPubKey"):
        scriptpubkey_to_address(b"\x00")
    with pytest.raises(ValueError, match="unsupported scriptPubKey"):
        scriptpubkey_to_address(b"\x6a\x01\xff")  # OP_RETURN


def test_p2pkh_script_to_testnet_address():
    script = address_to_scriptpubkey("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    addr = scriptpubkey_to_address(script, testnet=True)
    assert addr[0] in "mn"
    assert address_to_scriptpubkey(addr) == script
