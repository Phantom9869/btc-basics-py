"""Bech32 encoding and decoding (BIP 173)."""

from typing import List, Optional, Sequence, Tuple

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CHARSET_INDEX = {c: i for i, c in enumerate(CHARSET)}
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values: Sequence[int]) -> int:
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _GEN[i]
    return chk


def _hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _create_checksum(hrp: str, data: Sequence[int]) -> List[int]:
    values = _hrp_expand(hrp) + list(data) + [0, 0, 0, 0, 0, 0]
    polymod = _polymod(values) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _verify_checksum(hrp: str, data: Sequence[int]) -> bool:
    return _polymod(_hrp_expand(hrp) + list(data)) == 1


def _check_hrp(hrp: str) -> str:
    if not hrp or len(hrp) > 83:
        raise ValueError("HRP must be 1 to 83 characters")
    for i, c in enumerate(hrp):
        if not 33 <= ord(c) <= 126:
            raise ValueError(f"invalid HRP character: {c!r} at position {i}")
    return hrp.lower()


def convertbits(
    data: Sequence[int], frombits: int, tobits: int, *, pad: bool = True
) -> Optional[List[int]]:
    """Re-pack integers from `frombits`-wide groups into `tobits`-wide groups."""
    acc = 0
    bits = 0
    out: List[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or value >> frombits:
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return out


def bech32_encode(hrp: str, data: Sequence[int]) -> str:
    """Encode `data` (5-bit values) with a Bech32 checksum. Always lowercase."""
    hrp = _check_hrp(hrp)
    for i, value in enumerate(data):
        if not 0 <= value <= 31:
            raise ValueError(f"Bech32 data values must be 0-31, got {value} at position {i}")
    combined = list(data) + _create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def bech32_decode(s: str) -> Tuple[str, List[int]]:
    """Decode a Bech32 string to `(hrp, data)` without the checksum.

    Accepts all-lowercase or all-uppercase input, but not mixed case.
    Leading and trailing whitespace is ignored, same as Base58 decode.
    """
    if not isinstance(s, str):
        raise TypeError(f"bech32_decode() expected str, got {type(s).__name__}")
    s = s.strip()
    if not s:
        raise ValueError("empty Bech32 string")
    if s.lower() != s and s.upper() != s:
        raise ValueError("mixed-case Bech32 string")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1:
        raise ValueError("missing HRP separator")
    if pos + 7 > len(s):
        raise ValueError("too short for a Bech32 checksum")
    hrp, encoded = s[:pos], s[pos + 1 :]
    _check_hrp(hrp)
    data: List[int] = []
    for i, c in enumerate(encoded):
        if c not in _CHARSET_INDEX:
            raise ValueError(f"invalid Bech32 character: {c!r} at position {pos + 1 + i}")
        data.append(_CHARSET_INDEX[c])
    if not _verify_checksum(hrp, data):
        raise ValueError("bad Bech32 checksum")
    return hrp, data[:-6]
