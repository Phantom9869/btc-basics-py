"""P2PKH, P2SH and SegWit v0 (P2WPKH/P2WSH) address helpers."""

from typing import NamedTuple

from .base58 import b58encode_check
from .bech32 import bech32_decode, bech32_encode, convertbits
from .hashes import _as_bytes, hash160

MAINNET_P2PKH = 0x00
MAINNET_P2SH = 0x05
TESTNET_P2PKH = 0x6F
TESTNET_P2SH = 0xC4

MAINNET_HRP = "bc"
TESTNET_HRP = "tb"


class SegwitAddress(NamedTuple):
    hrp: str
    version: int
    program: bytes


def _hash160_from_pubkey_or_hash(data: bytes, name: str) -> bytes:
    data = _as_bytes(data, name)
    if len(data) == 20:
        return data
    if len(data) == 33:
        if data[0] not in (0x02, 0x03):
            raise ValueError("compressed public key must start with 0x02 or 0x03")
        return hash160(data)
    if len(data) == 65:
        if data[0] != 0x04:
            raise ValueError("uncompressed public key must start with 0x04")
        return hash160(data)
    raise ValueError(f"{name}() expects a 20-byte HASH160 or a 33/65-byte public key")


def p2pkh_address(data: bytes, *, testnet: bool = False) -> str:
    digest = _hash160_from_pubkey_or_hash(data, "p2pkh_address")
    version = TESTNET_P2PKH if testnet else MAINNET_P2PKH
    return b58encode_check(bytes([version]) + digest)


def p2sh_address(script_hash: bytes, *, testnet: bool = False) -> str:
    script_hash = _as_bytes(script_hash, "p2sh_address")
    if len(script_hash) != 20:
        raise ValueError("p2sh_address() expects a 20-byte script hash")
    version = TESTNET_P2SH if testnet else MAINNET_P2SH
    return b58encode_check(bytes([version]) + script_hash)


def _encode_segwit_v0(program: bytes, *, testnet: bool) -> str:
    five = convertbits(program, 8, 5)
    if five is None:
        raise ValueError("invalid SegWit program")
    hrp = TESTNET_HRP if testnet else MAINNET_HRP
    return bech32_encode(hrp, [0] + five)


def p2wpkh_address(data: bytes, *, testnet: bool = False) -> str:
    """Build a native SegWit v0 P2WPKH address (bc1q... / tb1q...).

    Accepts a 20-byte HASH160 or a 33-byte compressed public key.
    Uncompressed keys are rejected; BIP 141 requires compressed pubkeys.
    """
    data = _as_bytes(data, "p2wpkh_address")
    if len(data) == 20:
        program = data
    elif len(data) == 33:
        if data[0] not in (0x02, 0x03):
            raise ValueError("compressed public key must start with 0x02 or 0x03")
        program = hash160(data)
    elif len(data) == 65:
        raise ValueError("P2WPKH requires a compressed public key")
    else:
        raise ValueError("p2wpkh_address() expects a 20-byte HASH160 or a 33-byte compressed public key")
    return _encode_segwit_v0(program, testnet=testnet)


def p2wsh_address(script_hash: bytes, *, testnet: bool = False) -> str:
    """Build a native SegWit v0 P2WSH address from a 32-byte SHA-256 script hash."""
    script_hash = _as_bytes(script_hash, "p2wsh_address")
    if len(script_hash) != 32:
        raise ValueError("p2wsh_address() expects a 32-byte script hash")
    return _encode_segwit_v0(script_hash, testnet=testnet)


def decode_segwit_address(addr: str) -> SegwitAddress:
    """Decode a native SegWit v0 address into HRP, version and witness program."""
    if not isinstance(addr, str):
        raise TypeError(f"decode_segwit_address() expected str, got {type(addr).__name__}")
    hrp, data = bech32_decode(addr)
    if hrp not in (MAINNET_HRP, TESTNET_HRP):
        raise ValueError(f"unsupported SegWit HRP: {hrp!r}")
    if not data:
        raise ValueError("empty SegWit address")
    version = data[0]
    if version != 0:
        raise ValueError(f"only witness version 0 is supported, got {version}")
    program_bits = convertbits(data[1:], 5, 8, pad=False)
    if program_bits is None:
        raise ValueError("invalid SegWit padding")
    program = bytes(program_bits)
    if len(program) not in (20, 32):
        raise ValueError("witness version 0 program must be 20 or 32 bytes")
    return SegwitAddress(hrp=hrp, version=version, program=program)
