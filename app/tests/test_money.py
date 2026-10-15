import pytest

from money import fmt, to_cents


@pytest.mark.parametrize("raw,cents", [
    ("12,50", 1250), ("12.50", 1250), ("1.234,56", 123456), ("1,234.56", 123456),
    ("300", 30000), ("€ 5", 500), (135.3, 13530), ("0,1", 10),
])
def test_to_cents(raw, cents):
    assert to_cents(raw) == cents


@pytest.mark.parametrize("raw", ["", "abc", "-5", "nan", "inf"])
def test_to_cents_rejects(raw):
    with pytest.raises(ValueError):
        to_cents(raw)


def test_fmt():
    assert fmt(123456) == "1.234,56 €"
    assert fmt(-10600) == "-106,00 €"
