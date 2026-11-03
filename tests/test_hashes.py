import hashlib

import pytest

from btcbasics import ripemd160
from btcbasics.hashes import hash160, sha256, sha256d


def test_sha256_vectors():
    assert sha256(b"").hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256d():
    assert sha256d(b"hello").hex() == "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"


def test_genesis_block_hash():
    header = bytes.fromhex(
        "01000000"
        + "00" * 32
        + "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
        + "29ab5f49"
        + "ffff001d"
        + "1dac2b7c"
    )
    # Block hashes are displayed byte-reversed.
    assert sha256d(header)[::-1].hex() == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


@pytest.mark.parametrize("msg, expected", [
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"a" * 1000, "aa69deee9a8922e92f8105e007f76110f381e9cf"),
])
def test_pure_python_ripemd160(msg, expected):
    assert ripemd160.digest(msg).hex() == expected


def test_pure_python_ripemd160_million_a():
    assert ripemd160.digest(b"a" * 1_000_000).hex() == "52783243c1697bdbe16d37f97f68f08325dc1528"


def test_genesis_pubkey_hash160():
    pubkey = bytes.fromhex(
        "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
        "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
    )
    assert hash160(pubkey).hex() == "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"


def test_fallback_used_when_hashlib_lacks_ripemd(monkeypatch):
    def no_ripemd(name, *args, **kwargs):
        raise ValueError("unsupported hash type")

    monkeypatch.setattr(hashlib, "new", no_ripemd)
    assert hash160(b"abc").hex() == ripemd160.digest(sha256(b"abc")).hex()
