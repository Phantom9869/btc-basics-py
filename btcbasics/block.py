"""Bitcoin block headers, compact nBits targets and difficulty."""

from decimal import Decimal
from typing import NamedTuple

from .hashes import BytesLike, _as_bytes, sha256d
from .txid import txid_from_hash

# Genesis nBits; difficulty is the ratio of this target to a header's target.
BITS_DIFFICULTY_1 = 0x1D00FFFF
HEADER_SIZE = 80


def bits_to_target(bits: int) -> int:
    """Decode a compact nBits value, matching Bitcoin Core SetCompact().

    Negative encodings and values that overflow 256 bits are rejected; those
    are not valid proof-of-work targets.
    """
    if isinstance(bits, bool) or not isinstance(bits, int):
        raise TypeError(f"bits_to_target() expected int, got {type(bits).__name__}")
    if not 0 <= bits <= 0xFFFFFFFF:
        raise ValueError("nBits must fit in 4 bytes")
    size = bits >> 24
    word = bits & 0x007FFFFF
    if size <= 3:
        target = word >> (8 * (3 - size))
    else:
        target = word << (8 * (size - 3))
    negative = word != 0 and (bits & 0x00800000) != 0
    overflow = word != 0 and (
        size > 34 or (word > 0xFF and size > 33) or (word > 0xFFFF and size > 32)
    )
    if negative:
        raise ValueError("nBits encoding is negative")
    if overflow or target > (1 << 256) - 1:
        raise ValueError("nBits target overflows 256 bits")
    return target


def target_to_bits(target: int) -> int:
    """Encode a target as compact nBits, matching Bitcoin Core GetCompact()."""
    if isinstance(target, bool) or not isinstance(target, int):
        raise TypeError(f"target_to_bits() expected int, got {type(target).__name__}")
    if target < 0:
        raise ValueError("target must be non-negative")
    if target > (1 << 256) - 1:
        raise ValueError("target overflows 256 bits")
    if target == 0:
        return 0
    # Number of bytes needed to represent target, as in arith_uint256::bits().
    bit_length = target.bit_length()
    size = (bit_length + 7) // 8
    if size <= 3:
        compact = target << (8 * (3 - size))
    else:
        compact = target >> (8 * (size - 3))
    # The 0x00800000 bit is the sign. If it is already set, divide the
    # mantissa by 256 and increase the exponent.
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    if compact > 0x007FFFFF or size > 255:
        raise ValueError("target cannot be encoded as nBits")
    return compact | (size << 24)


def target_to_difficulty(target: int) -> Decimal:
    """Return the difficulty of a target relative to the genesis nBits."""
    if isinstance(target, bool) or not isinstance(target, int):
        raise TypeError(
            f"target_to_difficulty() expected int, got {type(target).__name__}"
        )
    if target <= 0:
        raise ValueError("target must be positive")
    return Decimal(bits_to_target(BITS_DIFFICULTY_1)) / Decimal(target)


def _u32(data: bytes, offset: int, signed: bool = False) -> int:
    return int.from_bytes(data[offset:offset + 4], "little", signed=signed)


class BlockHeader(NamedTuple):
    version: int
    prev_hash: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int

    def serialize(self) -> bytes:
        if len(self.prev_hash) != 32 or len(self.merkle_root) != 32:
            raise ValueError("prev_hash and merkle_root must be 32 bytes")
        if not 0 <= self.timestamp <= 0xFFFFFFFF:
            raise ValueError("timestamp must fit in 4 bytes")
        if not 0 <= self.bits <= 0xFFFFFFFF:
            raise ValueError("nBits must fit in 4 bytes")
        if not 0 <= self.nonce <= 0xFFFFFFFF:
            raise ValueError("nonce must fit in 4 bytes")
        if not -0x80000000 <= self.version <= 0x7FFFFFFF:
            raise ValueError("version must fit in a signed 32-bit integer")
        return (
            self.version.to_bytes(4, "little", signed=True)
            + self.prev_hash
            + self.merkle_root
            + self.timestamp.to_bytes(4, "little")
            + self.bits.to_bytes(4, "little")
            + self.nonce.to_bytes(4, "little")
        )

    def hash(self) -> bytes:
        """SHA256d of the 80-byte header, in internal byte order."""
        return sha256d(self.serialize())

    def block_hash(self) -> str:
        """Explorer-style block hash (reversed internal digest)."""
        return txid_from_hash(self.hash())

    def prev_block_hash(self) -> str:
        return txid_from_hash(self.prev_hash)

    def merkle_root_hash(self) -> str:
        return txid_from_hash(self.merkle_root)

    def target(self) -> int:
        return bits_to_target(self.bits)

    def difficulty(self) -> Decimal:
        return target_to_difficulty(self.target())

    def meets_target(self) -> bool:
        return int.from_bytes(self.hash(), "little") <= self.target()


def parse_block_header(data: BytesLike) -> BlockHeader:
    """Parse an 80-byte Bitcoin block header."""
    data = _as_bytes(data, "parse_block_header")
    if len(data) != HEADER_SIZE:
        raise ValueError(f"block header must be {HEADER_SIZE} bytes, got {len(data)}")
    return BlockHeader(
        version=_u32(data, 0, signed=True),
        prev_hash=data[4:36],
        merkle_root=data[36:68],
        timestamp=_u32(data, 68),
        bits=_u32(data, 72),
        nonce=_u32(data, 76),
    )
