"""P2PKH, P2SH, SegWit v0 (P2WPKH/P2WSH) and Taproot (P2TR) address helpers."""

from typing import NamedTuple, Optional

from .base58 import b58decode_check, b58encode_check
from .bech32 import BECH32, BECH32M, CHARSET, bech32_decode_any, bech32_encode, convertbits
from .hashes import BytesLike, _as_bytes, hash160
from .wif import MAINNET_WIF, TESTNET_WIF, decode_wif

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


def _hash160_from_pubkey_or_hash(data: BytesLike, name: str) -> bytes:
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


def p2pkh_address(data: BytesLike, *, testnet: bool = False) -> str:
    digest = _hash160_from_pubkey_or_hash(data, "p2pkh_address")
    version = TESTNET_P2PKH if testnet else MAINNET_P2PKH
    return b58encode_check(bytes([version]) + digest)


def p2sh_address(script_hash: BytesLike, *, testnet: bool = False) -> str:
    script_hash = _as_bytes(script_hash, "p2sh_address")
    if len(script_hash) != 20:
        raise ValueError("p2sh_address() expects a 20-byte script hash")
    version = TESTNET_P2SH if testnet else MAINNET_P2SH
    return b58encode_check(bytes([version]) + script_hash)


def encode_segwit_address(program: BytesLike, *, version: int = 0, testnet: bool = False) -> str:
    """Build a native SegWit address for witness versions 0 through 16.

    Version 0 uses Bech32 and a 20 or 32-byte program (P2WPKH / P2WSH).
    Versions 1 through 16 use Bech32m and a program of 2 to 40 bytes.
    """
    program = _as_bytes(program, "encode_segwit_address")
    if version == 0:
        encoding = BECH32
        if len(program) not in (20, 32):
            raise ValueError("witness version 0 program must be 20 or 32 bytes")
    elif 1 <= version <= 16:
        encoding = BECH32M
        if not 2 <= len(program) <= 40:
            raise ValueError("witness version 1-16 program must be 2 to 40 bytes")
    else:
        raise ValueError("witness version must be 0 through 16")
    five = convertbits(program, 8, 5)
    if five is None:
        raise ValueError("invalid SegWit program")
    hrp = TESTNET_HRP if testnet else MAINNET_HRP
    return bech32_encode(hrp, [version] + five, encoding=encoding)


def p2wpkh_address(data: BytesLike, *, testnet: bool = False) -> str:
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
    return encode_segwit_address(program, version=0, testnet=testnet)


def p2wsh_address(script_hash: BytesLike, *, testnet: bool = False) -> str:
    """Build a native SegWit v0 P2WSH address from a 32-byte SHA-256 script hash."""
    script_hash = _as_bytes(script_hash, "p2wsh_address")
    if len(script_hash) != 32:
        raise ValueError("p2wsh_address() expects a 32-byte script hash")
    return encode_segwit_address(script_hash, version=0, testnet=testnet)


def p2tr_address(output_key: BytesLike, *, testnet: bool = False) -> str:
    """Build a Taproot (P2TR, SegWit v1) address from a 32-byte x-only public key."""
    output_key = _as_bytes(output_key, "p2tr_address")
    if len(output_key) != 32:
        raise ValueError("p2tr_address() expects a 32-byte x-only public key")
    return encode_segwit_address(output_key, version=1, testnet=testnet)


def decode_segwit_address(addr: str) -> SegwitAddress:
    """Decode a native SegWit v0-v16 address into HRP, version and witness program.

    Version 0 must be Bech32 with a 20 or 32-byte program. Versions 1
    through 16 must be Bech32m with a program of 2 to 40 bytes.
    """
    if not isinstance(addr, str):
        raise TypeError(f"decode_segwit_address() expected str, got {type(addr).__name__}")
    hrp, data, encoding = bech32_decode_any(addr)
    if hrp not in (MAINNET_HRP, TESTNET_HRP):
        raise ValueError(f"unsupported SegWit HRP: {hrp!r}")
    if not data:
        raise ValueError("empty SegWit address")
    version = data[0]
    if not 0 <= version <= 16:
        raise ValueError(f"witness version must be 0 through 16, got {version}")
    expected = BECH32 if version == 0 else BECH32M
    name = "Bech32" if expected == BECH32 else "Bech32m"
    if encoding != expected:
        raise ValueError(f"witness version {version} must use {name}")
    program_bits = convertbits(data[1:], 5, 8, pad=False)
    if program_bits is None:
        raise ValueError("invalid SegWit padding")
    program = bytes(program_bits)
    if version == 0:
        if len(program) not in (20, 32):
            raise ValueError("witness version 0 program must be 20 or 32 bytes")
    elif not 2 <= len(program) <= 40:
        raise ValueError("witness version 1-16 program must be 2 to 40 bytes")
    return SegwitAddress(hrp=hrp, version=version, program=program)


class AddressInfo(NamedTuple):
    type: str
    network: Optional[str]
    valid: bool
    payload: Optional[bytes] = None
    version: Optional[int] = None
    compressed: Optional[bool] = None
    error: Optional[str] = None


def segwit_script_type(version: int, program: bytes) -> str:
    """Return 'p2wpkh', 'p2wsh', 'p2tr', or 'witness' for a decoded program."""
    if version == 0:
        return "p2wpkh" if len(program) == 20 else "p2wsh"
    if version == 1 and len(program) == 32:
        return "p2tr"
    return "witness"


def _has_bech32_shape(s: str) -> bool:
    text = s.strip()
    # Mixed-case strings are not valid Bech32, but still shouldn't be
    # parsed as Base58 if they otherwise look like a SegWit address.
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text):
        return False
    hrp, rest = text[:pos], text[pos + 1 :]
    if not all(33 <= ord(c) <= 126 for c in hrp):
        return False
    return all(c in CHARSET for c in rest)


def identify_address(s: str) -> AddressInfo:
    """Classify a Bitcoin address or WIF key and say whether it is valid.

    Does not raise on a malformed string: `valid` is False and `error`
    explains why. Raises TypeError if `s` is not a str.
    """
    if not isinstance(s, str):
        raise TypeError(f"identify_address() expected str, got {type(s).__name__}")
    raw = s.strip()
    if not raw:
        return AddressInfo(type="unknown", network=None, valid=False, error="empty address")

    if _has_bech32_shape(raw) or raw.lower().startswith(("bc1", "tb1")):
        low = raw.lower()
        if low.startswith("tb1"):
            network: Optional[str] = "testnet"
        elif low.startswith("bc1"):
            network = "mainnet"
        else:
            network = None
        try:
            info = decode_segwit_address(s)
        except ValueError as e:
            return AddressInfo(type="unknown", network=network, valid=False, error=str(e))
        typ = segwit_script_type(info.version, info.program)
        return AddressInfo(
            type=typ,
            network="testnet" if info.hrp == TESTNET_HRP else "mainnet",
            valid=True,
            payload=info.program,
            version=info.version,
        )

    try:
        payload = b58decode_check(s)
    except ValueError as e:
        return AddressInfo(type="unknown", network=None, valid=False, error=str(e))

    if not payload:
        return AddressInfo(type="unknown", network=None, valid=False, error="empty payload")

    version, body = payload[0], payload[1:]
    if version in (MAINNET_WIF, TESTNET_WIF):
        network = "testnet" if version == TESTNET_WIF else "mainnet"
        try:
            key = decode_wif(s)
        except ValueError as e:
            return AddressInfo(
                type="wif",
                network=network,
                valid=False,
                payload=body,
                version=version,
                error=str(e),
            )
        return AddressInfo(
            type="wif",
            network="testnet" if key.testnet else "mainnet",
            valid=True,
            payload=key.private_key,
            version=version,
            compressed=key.compressed,
        )

    versions = {
        MAINNET_P2PKH: ("p2pkh", "mainnet"),
        MAINNET_P2SH: ("p2sh", "mainnet"),
        TESTNET_P2PKH: ("p2pkh", "testnet"),
        TESTNET_P2SH: ("p2sh", "testnet"),
    }
    if version in versions:
        typ, network = versions[version]
        if len(body) != 20:
            return AddressInfo(
                type=typ,
                network=network,
                valid=False,
                payload=body,
                version=version,
                error=f"expected 20 byte hash, got {len(body)}",
            )
        return AddressInfo(
            type=typ,
            network=network,
            valid=True,
            payload=body,
            version=version,
        )

    return AddressInfo(
        type="unknown",
        network=None,
        valid=False,
        payload=body,
        version=version,
        error=f"unknown version byte: 0x{version:02x}",
    )
