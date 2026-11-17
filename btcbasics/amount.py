"""Convert between BTC and satoshis with exact Decimal arithmetic."""

import re
from decimal import Decimal, InvalidOperation
from typing import Union

COIN = 100_000_000
MAX_MONEY = 21_000_000 * COIN  # 2,100,000,000,000,000 satoshis
MAX_BTC = 21_000_000

# Whole BTC, or a fraction with at most 8 decimal places. No sign, no
# leading zeros, no scientific notation.
_BTC_RE = re.compile(r"^(?:0|[1-9]\d*)(?:\.\d{1,8})?$")

AmountLike = Union[str, int, Decimal]


def btc_to_sats(amount: AmountLike) -> int:
    """Parse a BTC amount into satoshis.

    Accepts a string, a non-negative int (whole BTC), or a Decimal.
    Fractions may have at most eight decimal places. The result must
    fall in 0 through 21 million BTC inclusive.
    """
    if isinstance(amount, bool) or not isinstance(amount, (str, int, Decimal)):
        raise TypeError(
            f"btc_to_sats() expected str, int or Decimal, got {type(amount).__name__}"
        )
    if isinstance(amount, int):
        if amount < 0:
            raise ValueError("amount must be non-negative")
        if amount > MAX_BTC:
            raise ValueError("amount exceeds 21,000,000 BTC")
        return amount * COIN
    if isinstance(amount, str):
        text = amount.strip()
        if not _BTC_RE.fullmatch(text):
            raise ValueError("invalid BTC amount")
        if "." in text:
            whole, frac = text.split(".")
            frac = frac.ljust(8, "0")
        else:
            whole, frac = text, "00000000"
        sats = int(whole) * COIN + int(frac)
    else:
        if not amount.is_finite() or amount < 0:
            raise ValueError("invalid BTC amount")
        try:
            quantized = amount.quantize(Decimal("0.00000001"))
        except InvalidOperation as exc:
            raise ValueError("invalid BTC amount") from exc
        if quantized != amount:
            raise ValueError("amount has more than 8 decimal places")
        sats = int(quantized * COIN)
    if sats > MAX_MONEY:
        raise ValueError("amount exceeds 21,000,000 BTC")
    return sats


def sats_to_btc(sats: int) -> Decimal:
    """Convert satoshis to BTC as an exact Decimal."""
    if isinstance(sats, bool) or not isinstance(sats, int):
        raise TypeError(f"sats_to_btc() expected int, got {type(sats).__name__}")
    if sats < 0:
        raise ValueError("amount must be non-negative")
    if sats > MAX_MONEY:
        raise ValueError("amount exceeds 21,000,000 BTC")
    return Decimal(sats) / Decimal(COIN)


def format_btc(sats: int) -> str:
    """Format satoshis as a BTC string, without trailing zeros."""
    text = format(sats_to_btc(sats), "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text
