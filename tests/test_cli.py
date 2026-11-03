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
