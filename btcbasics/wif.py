"""Wallet Import Format (WIF) for raw 32-byte private keys."""

from typing import NamedTuple

from .base58 import b58decode_check, b58encode_check
from .hashes import BytesLike, _as_bytes

MAINNET_WIF = 0x80
TESTNET_WIF = 0xEF


class WIFKey(NamedTuple):
    private_key: bytes
    compressed: bool
    testnet: bool


def encode_wif(private_key: BytesLike, *, compressed: bool = True, testnet: bool = False) -> str:
    private_key = _as_bytes(private_key, "encode_wif")
    if len(private_key) != 32:
        raise ValueError("private key must be 32 bytes")
    payload = bytes([TESTNET_WIF if testnet else MAINNET_WIF]) + private_key
    if compressed:
        payload += b"\x01"
    return b58encode_check(payload)


def decode_wif(s: str) -> WIFKey:
    if not isinstance(s, str):
        raise TypeError(f"decode_wif() expected str, got {type(s).__name__}")
    payload = b58decode_check(s)
    if not payload:
        raise ValueError("too short for WIF")
    version, body = payload[0], payload[1:]
    if version not in (MAINNET_WIF, TESTNET_WIF):
        raise ValueError(f"not a WIF version byte: 0x{version:02x}")
    if len(body) == 32:
        key, compressed = body, False
    elif len(body) == 33 and body[-1] == 0x01:
        key, compressed = body[:-1], True
    else:
        raise ValueError(
            "WIF payload must be a 32-byte key, optionally plus a 0x01 compressed flag"
        )
    return WIFKey(private_key=key, compressed=compressed, testnet=version == TESTNET_WIF)
