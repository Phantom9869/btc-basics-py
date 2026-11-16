import json
from pathlib import Path

import pytest

from btcbasics import (
    ENGLISH_WORDLIST_SHA256,
    english_wordlist,
    entropy_to_mnemonic,
    mnemonic_to_entropy,
    mnemonic_to_seed,
)
from btcbasics.hashes import sha256

VECTORS = json.loads(
    (Path(__file__).parent / "data" / "bip39_english_vectors.json").read_text()
)["english"]

WORDLIST_PATH = Path(__file__).resolve().parents[1] / "btcbasics" / "wordlists" / "english.txt"


def test_bundled_wordlist_matches_official_checksum():
    raw = WORDLIST_PATH.read_bytes()
    assert sha256(raw).hex() == ENGLISH_WORDLIST_SHA256
    words = english_wordlist()
    assert len(words) == 2048
    assert words[0] == "abandon"
    assert words[-1] == "zoo"
    assert words == tuple(raw.decode("ascii").splitlines())


@pytest.mark.parametrize("entropy, mnemonic, seed, _xprv", VECTORS)
def test_official_english_vectors(entropy, mnemonic, seed, _xprv):
    raw = bytes.fromhex(entropy)
    assert entropy_to_mnemonic(raw) == mnemonic
    assert mnemonic_to_entropy(mnemonic) == raw
    # The published Trezor / BIP 39 English vectors all use this passphrase.
    assert mnemonic_to_seed(mnemonic, "TREZOR") == bytes.fromhex(seed)


def test_mnemonic_normalizes_whitespace_and_case():
    entropy, mnemonic, seed, _ = VECTORS[0]
    messy = "  " + mnemonic.upper().replace(" ", "  \n") + "  "
    assert mnemonic_to_entropy(messy) == bytes.fromhex(entropy)
    assert mnemonic_to_seed(messy, "TREZOR") == bytes.fromhex(seed)


def test_empty_passphrase_differs_from_trezor():
    mnemonic = VECTORS[0][1]
    assert mnemonic_to_seed(mnemonic) != mnemonic_to_seed(mnemonic, "TREZOR")
    assert len(mnemonic_to_seed(mnemonic)) == 64


def test_invalid_checksum_is_rejected():
    words = VECTORS[0][1].split()
    words[-1] = "abandon"  # last word carries checksum bits
    with pytest.raises(ValueError, match="invalid mnemonic checksum"):
        mnemonic_to_entropy(" ".join(words))
    with pytest.raises(ValueError, match="invalid mnemonic checksum"):
        mnemonic_to_seed(" ".join(words))


def test_unknown_word_is_rejected():
    with pytest.raises(ValueError, match="unknown BIP 39 word: notaword"):
        mnemonic_to_entropy("abandon " * 11 + "notaword")


def test_wrong_word_count_is_rejected():
    with pytest.raises(ValueError, match="12, 15, 18, 21 or 24"):
        mnemonic_to_entropy("abandon abandon abandon")


def test_entropy_length_is_validated():
    with pytest.raises(ValueError, match="16, 20, 24, 28 or 32 bytes"):
        entropy_to_mnemonic(b"\x00" * 15)
    with pytest.raises(TypeError, match="expected bytes-like"):
        entropy_to_mnemonic("00" * 16)
    with pytest.raises(TypeError, match="expected str"):
        mnemonic_to_entropy(b"abandon")
    with pytest.raises(TypeError, match="passphrase"):
        mnemonic_to_seed(VECTORS[0][1], passphrase=b"TREZOR")


def test_entropy_to_mnemonic_accepts_bytes_like():
    raw = bytes.fromhex(VECTORS[0][0])
    assert entropy_to_mnemonic(bytearray(raw)) == VECTORS[0][1]
    assert entropy_to_mnemonic(memoryview(raw)) == VECTORS[0][1]
