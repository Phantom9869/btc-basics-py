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
