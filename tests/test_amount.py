from decimal import Decimal

import pytest

from btcbasics import COIN, MAX_MONEY, btc_to_sats, format_btc, sats_to_btc


def test_known_amounts():
    assert COIN == 100_000_000
    assert MAX_MONEY == 2_100_000_000_000_000
    assert btc_to_sats("0") == 0
    assert btc_to_sats("0.00000001") == 1
    assert btc_to_sats("1") == COIN
    assert btc_to_sats("50") == 5_000_000_000
    assert btc_to_sats("21000000") == MAX_MONEY
    assert btc_to_sats(50) == 5_000_000_000
    assert btc_to_sats(Decimal("0.00311")) == 311_000
    # Genesis coinbase and the first SegWit payment, as BTC strings.
    assert sats_to_btc(5_000_000_000) == Decimal("50")
    assert sats_to_btc(311_000) == Decimal("0.00311")
    assert sats_to_btc(1) == Decimal("0.00000001")
    assert sats_to_btc(0) == Decimal("0")
    assert sats_to_btc(MAX_MONEY) == Decimal("21000000")


def test_whitespace_and_trailing_zeros():
    assert btc_to_sats("  1.50000000  ") == 150_000_000
    assert btc_to_sats("1.5") == 150_000_000
    assert btc_to_sats("1.50") == btc_to_sats(Decimal("1.50"))


def test_roundtrip_every_scale():
    for sats in (0, 1, 99, COIN - 1, COIN, 5_000_000_000, MAX_MONEY):
        assert btc_to_sats(sats_to_btc(sats)) == sats


def test_rejects_too_many_decimals():
    with pytest.raises(ValueError, match="invalid BTC amount"):
        btc_to_sats("0.000000001")
    with pytest.raises(ValueError, match="8 decimal places"):
        btc_to_sats(Decimal("0.000000001"))
    # Scientific notation in a string is rejected; the same Decimal is 1 sat.
    with pytest.raises(ValueError, match="invalid BTC amount"):
        btc_to_sats("1e-8")
    assert btc_to_sats(Decimal("1e-8")) == 1


def test_rejects_out_of_range_and_bad_types():
    with pytest.raises(ValueError, match="21,000,000"):
        btc_to_sats("21000000.00000001")
    with pytest.raises(ValueError, match="21,000,000"):
        btc_to_sats(21_000_001)
    with pytest.raises(ValueError, match="non-negative"):
        btc_to_sats(-1)
    with pytest.raises(ValueError, match="invalid BTC amount"):
        btc_to_sats("-1")
    with pytest.raises(ValueError, match="invalid BTC amount"):
        btc_to_sats("01")
    with pytest.raises(ValueError, match="invalid BTC amount"):
        btc_to_sats("1.")
    with pytest.raises(ValueError, match="invalid BTC amount"):
        btc_to_sats(".1")
    with pytest.raises(TypeError, match="expected str, int or Decimal"):
        btc_to_sats(1.5)
    with pytest.raises(TypeError, match="expected str, int or Decimal"):
        btc_to_sats(True)
    with pytest.raises(TypeError, match="expected int"):
        sats_to_btc(True)
    with pytest.raises(TypeError, match="expected int"):
        sats_to_btc("1")
    with pytest.raises(ValueError, match="non-negative"):
        sats_to_btc(-1)
    with pytest.raises(ValueError, match="21,000,000"):
        sats_to_btc(MAX_MONEY + 1)


def test_format_btc():
    assert format_btc(0) == "0"
    assert format_btc(1) == "0.00000001"
    assert format_btc(150_000_000) == "1.5"
    assert format_btc(5_000_000_000) == "50"
    assert format_btc(MAX_MONEY) == "21000000"
