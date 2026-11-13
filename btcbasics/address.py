"""P2PKH and P2SH Base58Check address helpers."""

from .base58 import b58encode_check
from .hashes import _as_bytes, hash160

MAINNET_P2PKH = 0x00
MAINNET_P2SH = 0x05
TESTNET_P2PKH = 0x6F
TESTNET_P2SH = 0xC4


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
