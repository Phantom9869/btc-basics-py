"""BIP 32 extended key serialization (xprv/xpub/tprv/tpub).

This module encodes and decodes the 78-byte Base58Check payload and
derives a master private key from a seed. Child-key derivation is out
of scope: it needs elliptic-curve point arithmetic.
"""

import hmac
import hashlib
from typing import Dict, NamedTuple, Tuple

from .base58 import b58decode_check, b58encode_check
from .hashes import BytesLike, _as_bytes

# secp256k1 field prime and group order (SEC 2, 2.4.1).
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

MAINNET_XPRV = 0x0488ADE4
MAINNET_XPUB = 0x0488B21E
TESTNET_XPRV = 0x04358394
TESTNET_XPUB = 0x043587CF

# version byte -> (network, is_private, prefix)
_VERSIONS: Dict[int, Tuple[str, bool, str]] = {
    MAINNET_XPRV: ("mainnet", True, "xprv"),
    MAINNET_XPUB: ("mainnet", False, "xpub"),
    TESTNET_XPRV: ("testnet", True, "tprv"),
    TESTNET_XPUB: ("testnet", False, "tpub"),
}
_VERSION_BY_NET_PRIV = {
    ("mainnet", True): MAINNET_XPRV,
    ("mainnet", False): MAINNET_XPUB,
    ("testnet", True): TESTNET_XPRV,
    ("testnet", False): TESTNET_XPUB,
}

HARDENED = 0x80000000
_PAYLOAD_LEN = 78


class ExtendedKey(NamedTuple):
    network: str
    private: bool
    depth: int
    fingerprint: bytes
    child: int
    chain_code: bytes
    key: bytes

    @property
    def prefix(self) -> str:
        return "xprv" if self.private and self.network == "mainnet" else (
            "xpub" if not self.private and self.network == "mainnet" else (
                "tprv" if self.private else "tpub"
            )
        )

    @property
    def hardened(self) -> bool:
        return self.child >= HARDENED

    @property
    def child_index(self) -> int:
        """The child number with the hardened bit cleared."""
        return self.child & ~HARDENED


def _is_on_curve(pubkey: bytes) -> bool:
    if len(pubkey) != 33 or pubkey[0] not in (0x02, 0x03):
        return False
    x = int.from_bytes(pubkey[1:], "big")
    if x >= SECP256K1_P:
        return False
    y2 = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    # Quadratic residue test (including y == 0, which is on the curve).
    return pow(y2, (SECP256K1_P - 1) // 2, SECP256K1_P) in (0, 1)


def _validate_key_material(private: bool, key: bytes) -> None:
    if private:
        if len(key) != 32:
            raise ValueError("private key must be 32 bytes")
        secret = int.from_bytes(key, "big")
        if not 1 <= secret < SECP256K1_N:
            raise ValueError("private key is not in the range 1..n-1")
        return
    if len(key) != 33 or key[0] not in (0x02, 0x03):
        raise ValueError("public key must be a 33-byte compressed SEC point")
    if not _is_on_curve(key):
        raise ValueError("public key is not a valid secp256k1 point")


def _validate_depth(depth: int, fingerprint: bytes, child: int) -> None:
    if not 0 <= depth <= 255:
        raise ValueError("depth must fit in one byte")
    if len(fingerprint) != 4:
        raise ValueError("parent fingerprint must be 4 bytes")
    if not 0 <= child <= 0xFFFFFFFF:
        raise ValueError("child number must fit in 4 bytes")
    if depth == 0:
        if fingerprint != b"\x00\x00\x00\x00":
            raise ValueError("master key parent fingerprint must be zero")
        if child != 0:
            raise ValueError("master key child number must be zero")


def decode_extended_key(s: str) -> ExtendedKey:
    """Decode an xprv/xpub/tprv/tpub string and check its structure."""
    if not isinstance(s, str):
        raise TypeError(f"decode_extended_key() expected str, got {type(s).__name__}")
    payload = b58decode_check(s)
    if len(payload) != _PAYLOAD_LEN:
        raise ValueError(f"extended key payload must be {_PAYLOAD_LEN} bytes, got {len(payload)}")
    version = int.from_bytes(payload[0:4], "big")
    if version not in _VERSIONS:
        raise ValueError(f"unknown extended key version: 0x{version:08x}")
    network, private, _prefix = _VERSIONS[version]
    depth = payload[4]
    fingerprint = payload[5:9]
    child = int.from_bytes(payload[9:13], "big")
    chain_code = payload[13:45]
    key_data = payload[45:78]
    if private:
        if key_data[0] != 0x00:
            raise ValueError("private extended key must use a 0x00 key prefix")
        key = key_data[1:]
    else:
        if key_data[0] not in (0x02, 0x03):
            raise ValueError("public extended key must use a 0x02 or 0x03 prefix")
        key = key_data
    _validate_depth(depth, fingerprint, child)
    _validate_key_material(private, key)
    return ExtendedKey(
        network=network,
        private=private,
        depth=depth,
        fingerprint=fingerprint,
        child=child,
        chain_code=chain_code,
        key=key,
    )


def encode_extended_key(key: ExtendedKey) -> str:
    """Serialize an extended key to a BIP 32 Base58Check string."""
    if not isinstance(key, ExtendedKey):
        raise TypeError(
            f"encode_extended_key() expected ExtendedKey, got {type(key).__name__}"
        )
    if key.network not in ("mainnet", "testnet"):
        raise ValueError("network must be 'mainnet' or 'testnet'")
    _validate_depth(key.depth, key.fingerprint, key.child)
    _validate_key_material(key.private, key.key)
    if len(key.chain_code) != 32:
        raise ValueError("chain code must be 32 bytes")
    version = _VERSION_BY_NET_PRIV[(key.network, key.private)]
    key_data = (b"\x00" + key.key) if key.private else key.key
    payload = (
        version.to_bytes(4, "big")
        + bytes([key.depth])
        + key.fingerprint
        + key.child.to_bytes(4, "big")
        + key.chain_code
        + key_data
    )
    return b58encode_check(payload)


def master_from_seed(seed: BytesLike, *, testnet: bool = False) -> ExtendedKey:
    """Derive the BIP 32 master private key from a seed (HMAC-SHA512).

    The seed is typically a 64-byte BIP 39 seed. BIP 32 recommends 16 to
    64 bytes. No elliptic-curve math is required for the master key.
    """
    seed = _as_bytes(seed, "master_from_seed")
    if not 16 <= len(seed) <= 64:
        raise ValueError("seed must be 16 to 64 bytes")
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    secret, chain_code = digest[:32], digest[32:]
    _validate_key_material(True, secret)
    return ExtendedKey(
        network="testnet" if testnet else "mainnet",
        private=True,
        depth=0,
        fingerprint=b"\x00\x00\x00\x00",
        child=0,
        chain_code=chain_code,
        key=secret,
    )
