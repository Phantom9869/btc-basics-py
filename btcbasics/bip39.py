import hashlib
import unicodedata
from typing import Dict, List, Optional, Tuple, Union

from importlib.resources import files

from .hashes import sha256

BytesLike = Union[bytes, bytearray, memoryview]

# SHA-256 of the official BIP 39 English wordlist
# (bitcoin/bips bip-0039/english.txt), including the trailing newline.
ENGLISH_WORDLIST_SHA256 = (
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
)

_WORDS: Optional[List[str]] = None
_INDEX: Optional[Dict[str, int]] = None


def _as_bytes(data: BytesLike, name: str) -> bytes:
    if isinstance(data, memoryview):
        data = data.tobytes()
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{name}() expected bytes-like, got {type(data).__name__}")
    return bytes(data)


def _wordlist() -> Tuple[List[str], Dict[str, int]]:
    global _WORDS, _INDEX
    if _WORDS is None:
        raw = files("btcbasics").joinpath("wordlists").joinpath("english.txt").read_bytes()
        if sha256(raw).hex() != ENGLISH_WORDLIST_SHA256:
            raise RuntimeError(
                "bundled BIP 39 English wordlist failed its official checksum"
            )
        words = raw.decode("ascii").splitlines()
        if len(words) != 2048:
            raise RuntimeError("bundled BIP 39 English wordlist is malformed")
        _WORDS = words
        _INDEX = {word: i for i, word in enumerate(words)}
    return _WORDS, _INDEX  # type: ignore[return-value]


def english_wordlist() -> Tuple[str, ...]:
    """Return the bundled official BIP 39 English wordlist."""
    words, _ = _wordlist()
    return tuple(words)


def entropy_to_mnemonic(entropy: BytesLike) -> str:
    """Turn 16-32 bytes of entropy into a BIP 39 English mnemonic."""
    entropy = _as_bytes(entropy, "entropy_to_mnemonic")
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("entropy must be 16, 20, 24, 28 or 32 bytes")
    words, _ = _wordlist()
    ent_bits = len(entropy) * 8
    cs_bits = ent_bits // 32
    checksum = sha256(entropy)[0] >> (8 - cs_bits)
    acc = (int.from_bytes(entropy, "big") << cs_bits) | checksum
    n_words = (ent_bits + cs_bits) // 11
    out = []
    for i in range(n_words - 1, -1, -1):
        out.append(words[(acc >> (i * 11)) & 0x7FF])
    return " ".join(out)


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """Decode a BIP 39 English mnemonic and check its checksum."""
    if not isinstance(mnemonic, str):
        raise TypeError(
            f"mnemonic_to_entropy() expected str, got {type(mnemonic).__name__}"
        )
    words_in = unicodedata.normalize("NFKD", mnemonic).strip().lower().split()
    n_words = len(words_in)
    if n_words not in (12, 15, 18, 21, 24):
        raise ValueError("mnemonic must be 12, 15, 18, 21 or 24 words")
    _, index = _wordlist()
    acc = 0
    for word in words_in:
        try:
            acc = (acc << 11) | index[word]
        except KeyError:
            raise ValueError(f"unknown BIP 39 word: {word}") from None
    total_bits = n_words * 11
    cs_bits = total_bits // 33
    ent_bits = total_bits - cs_bits
    checksum = acc & ((1 << cs_bits) - 1)
    entropy = (acc >> cs_bits).to_bytes(ent_bits // 8, "big")
    expected = sha256(entropy)[0] >> (8 - cs_bits)
    if checksum != expected:
        raise ValueError("invalid mnemonic checksum")
    return entropy


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Derive a 64-byte BIP 39 seed with PBKDF2-HMAC-SHA512.

    The mnemonic is validated first. Both the mnemonic and passphrase are
    NFKD-normalized, and the salt is the literal prefix "mnemonic" plus
    the passphrase, as specified by BIP 39 (2048 rounds).
    """
    mnemonic_to_entropy(mnemonic)
    if not isinstance(passphrase, str):
        raise TypeError(
            f"mnemonic_to_seed() expected a str passphrase, got {type(passphrase).__name__}"
        )
    words = unicodedata.normalize("NFKD", mnemonic).strip().lower().split()
    sentence = unicodedata.normalize("NFKD", " ".join(words)).encode("utf-8")
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", sentence, salt, 2048, dklen=64)
