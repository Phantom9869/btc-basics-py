from decimal import Decimal

import pytest

from btcbasics import (
    bits_to_target,
    parse_block_header,
    target_to_bits,
    target_to_difficulty,
)
from btcbasics.block import BITS_DIFFICULTY_1

# 80-byte headers from the Bitcoin chain.
GENESIS_HEADER = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000"
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
    "4b1e5e4a29ab5f49ffff001d1dac2b7c"
)
GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
GENESIS_MERKLE = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
GENESIS_TIME = 1231006505
GENESIS_NONCE = 2083236893
GENESIS_TARGET = (
    "00000000ffff0000000000000000000000000000000000000000000000000000"
)

# First payment block (Satoshi to Hal Finney), 12 Jan 2009.
BLOCK_170_HEADER = bytes.fromhex(
    "0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a"
    "00000000ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166"
    "562cac7d51b96a49ffff001d283e9e70"
)
BLOCK_170_HASH = "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee"
BLOCK_170_PREV = "000000002a22cfee1f2c846adbd12b3e183d4f97683f85dad08a79780a84bd55"
BLOCK_170_MERKLE = "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"
BLOCK_170_TIME = 1231731025
BLOCK_170_NONCE = 1889418792

# Compact-target example from the Bitcoin developer documentation.
WIKI_BITS = 0x1B0404CB
WIKI_TARGET = "00000000000404cb000000000000000000000000000000000000000000000000"


def test_genesis_header():
    header = parse_block_header(GENESIS_HEADER)
    assert header.version == 1
    assert header.prev_hash == b"\x00" * 32
    assert header.prev_block_hash() == "00" * 32
    assert header.merkle_root_hash() == GENESIS_MERKLE
    assert header.timestamp == GENESIS_TIME
    assert header.bits == BITS_DIFFICULTY_1
    assert header.nonce == GENESIS_NONCE
    assert header.block_hash() == GENESIS_HASH
    assert header.hash() == bytes.fromhex(GENESIS_HASH)[::-1]
    assert f"{header.target():064x}" == GENESIS_TARGET
    assert header.difficulty() == 1
    assert header.meets_target()
    assert header.serialize() == GENESIS_HEADER


def test_block_170_header():
    header = parse_block_header(BLOCK_170_HEADER)
    assert header.version == 1
    assert header.prev_block_hash() == BLOCK_170_PREV
    assert header.merkle_root_hash() == BLOCK_170_MERKLE
    assert header.timestamp == BLOCK_170_TIME
    assert header.bits == BITS_DIFFICULTY_1
    assert header.nonce == BLOCK_170_NONCE
    assert header.block_hash() == BLOCK_170_HASH
    assert header.difficulty() == 1
    assert header.meets_target()
    assert header.serialize() == BLOCK_170_HEADER


def test_header_accepts_bytes_like():
    assert parse_block_header(bytearray(GENESIS_HEADER)).block_hash() == GENESIS_HASH
    assert parse_block_header(memoryview(GENESIS_HEADER)).block_hash() == GENESIS_HASH


def test_header_length_and_type():
    with pytest.raises(ValueError, match="80 bytes"):
        parse_block_header(GENESIS_HEADER[:-1])
    with pytest.raises(ValueError, match="80 bytes"):
        parse_block_header(GENESIS_HEADER + b"\x00")
    with pytest.raises(TypeError, match="expected bytes-like"):
        parse_block_header(GENESIS_HEADER.hex())


def test_wiki_compact_target():
    target = bits_to_target(WIKI_BITS)
    assert f"{target:064x}" == WIKI_TARGET
    assert target_to_bits(target) == WIKI_BITS
    assert target_to_difficulty(target) == (
        Decimal(bits_to_target(BITS_DIFFICULTY_1)) / Decimal(target)
    )


def test_bits_roundtrip_sign_bit_shift():
    # A mantissa with the 0x00800000 sign bit set must bump the exponent.
    target = 0x800000
    bits = target_to_bits(target)
    assert bits == 0x04008000
    assert bits_to_target(bits) == target
    assert target_to_bits(0) == 0
    assert bits_to_target(0) == 0
    assert target_to_bits(bits_to_target(BITS_DIFFICULTY_1)) == BITS_DIFFICULTY_1


def test_negative_and_overflow_bits_rejected():
    # Same magnitude as 0x04008000, but with the sign bit set.
    with pytest.raises(ValueError, match="negative"):
        bits_to_target(0x04808000)
    # size=35, word=1: overflows a 256-bit target.
    with pytest.raises(ValueError, match="overflows"):
        bits_to_target(0x23000001)
    with pytest.raises(ValueError, match="4 bytes"):
        bits_to_target(0x100000000)
    with pytest.raises(TypeError, match="expected int"):
        bits_to_target(True)
    with pytest.raises(TypeError, match="expected int"):
        target_to_bits(1.0)
    with pytest.raises(ValueError, match="non-negative"):
        target_to_bits(-1)
    with pytest.raises(ValueError, match="positive"):
        target_to_difficulty(0)


def test_tampered_header_misses_target():
    header = parse_block_header(GENESIS_HEADER)
    bad = header._replace(nonce=header.nonce + 1)
    assert not bad.meets_target()
    assert bad.block_hash() != GENESIS_HASH
