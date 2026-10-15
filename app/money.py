"""Money parsing/formatting. Amounts are integer cents everywhere."""


def to_cents(value):
    """Parse '12,50' / '12.50' / '1.234,50' / 12.5 into integer cents. Raises ValueError."""
    if isinstance(value, (int, float)):
        cents = round(value * 100)
    else:
        s = str(value).strip().replace("€", "").replace(" ", "")
        if not s:
            raise ValueError("empty amount")
        if "," in s and "." in s:
            if s.rfind(",") > s.rfind("."):
                s = s.replace(".", "").replace(",", ".")
            else:
                s = s.replace(",", "")
        else:
            s = s.replace(",", ".")
        f = float(s)
        if f != f or f in (float("inf"), float("-inf")):
            raise ValueError("not a number")
        cents = round(f * 100)
    if cents < 0:
        raise ValueError("negative amount")
    return int(cents)


def fmt(cents, currency="€"):
    """Greek-style money: 1.234,50 €"""
    neg = cents < 0
    cents = abs(int(cents))
    whole, frac = divmod(cents, 100)
    s = f"{whole:,}".replace(",", ".") + f",{frac:02d}"
    return f"{'-' if neg else ''}{s} {currency}"
