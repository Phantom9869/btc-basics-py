from typing import Union

"""Pure Python RIPEMD-160, used only when hashlib doesn't provide it."""

import struct
from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]

# Message word order for each of the 80 steps, left and right lines.
_R_LEFT = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
_R_RIGHT = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
# Rotation amounts.
_S_LEFT = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
_S_RIGHT = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]
_K_LEFT = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_K_RIGHT = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]

MASK = 0xFFFFFFFF


def _f(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def _compress(state, block):
    x = struct.unpack("<16L", block)
    al, bl, cl, dl, el = state
    ar, br, cr, dr, er = state

    for j in range(80):
        rnd = j // 16
        t = _rol((al + _f(j, bl, cl, dl) + x[_R_LEFT[j]] + _K_LEFT[rnd]) & MASK, _S_LEFT[j])
        t = (t + el) & MASK
        al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t

        # The right line runs the boolean functions in reverse order.
        t = _rol((ar + _f(79 - j, br, cr, dr) + x[_R_RIGHT[j]] + _K_RIGHT[rnd]) & MASK, _S_RIGHT[j])
        t = (t + er) & MASK
        ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t

    h0, h1, h2, h3, h4 = state
    return [
        (h1 + cl + dr) & MASK,
        (h2 + dl + er) & MASK,
        (h3 + el + ar) & MASK,
        (h4 + al + br) & MASK,
        (h0 + bl + cr) & MASK,
    ]


def digest(data: BytesLike) -> bytes:
    if isinstance(data, memoryview):
        data = data.tobytes()
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"digest() expected bytes-like, got {type(data).__name__}")
    data = bytes(data)
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    padded = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + struct.pack("<Q", bit_len)
    for i in range(0, len(padded), 64):
        state = _compress(state, padded[i:i + 64])
    return struct.pack("<5L", *state)
