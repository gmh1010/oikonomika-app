"""Security helpers: hashing identifiers, password rules (incl. breached-password check), Turnstile, 2FA codes."""
import base64
import hashlib
import io
import re
import secrets

import requests

HIBP_URL = "https://api.pwnedpasswords.com/range/"
TURNSTILE_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")


def key_hash(*parts):
    """sha256 hex of joined parts — used for rate-limit keys and IP hashes (no raw emails/IPs stored)."""
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


def pwned(password, timeout=3, http=requests):
    """Have I Been Pwned k-anonymity check: only the first 5 hex chars of the SHA-1 leave this server.
    True = breached, False = not found, None = service unreachable (caller decides)."""
    sha = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha[:5], sha[5:]
    try:
        r = http.get(HIBP_URL + prefix, headers={"Add-Padding": "true"}, timeout=timeout)
        r.raise_for_status()
    except requests.RequestException:
        return None
    for line in r.text.splitlines():
        h, _, count = line.strip().partition(":")
        if h == suffix and count.strip() not in ("", "0"):
            return True
    return False


def password_problem(password, pwned_check=pwned):
    """Greek error message, or None if the password is acceptable."""
    if len(password) < 10:
        return "Ο κωδικός θέλει τουλάχιστον 10 χαρακτήρες"
    if len(password.encode()) > 72:
        return "Ο κωδικός είναι πολύ μεγάλος (έως 72 χαρακτήρες)"
    if not (any(ch.isalpha() for ch in password) and any(ch.isdigit() for ch in password)):
        return "Ο κωδικός θέλει και γράμματα και αριθμούς"
    if pwned_check(password) is True:
        return "Αυτός ο κωδικός έχει διαρρεύσει σε παραβιάσεις άλλων sites — διάλεξε άλλον"
    return None


def valid_email(email):
    return bool(EMAIL_RE.match(email or "")) and len(email) <= 254


def turnstile_ok(secret, token, ip, timeout=5, http=requests):
    """Cloudflare Turnstile server check. Disabled (always True) when no secret is configured."""
    if not secret:
        return True
    if not token:
        return False
    try:
        r = http.post(TURNSTILE_URL, data={"secret": secret, "response": token, "remoteip": ip}, timeout=timeout)
        return bool(r.json().get("success"))
    except (requests.RequestException, ValueError):
        return False


def new_recovery_codes(n=8):
    """Human-friendly single-use codes like 'k7q2m-x9p4d' (~50 bits each)."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    codes = []
    for _ in range(n):
        raw = "".join(secrets.choice(alphabet) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def normalize_code(code):
    return re.sub(r"[^a-z0-9]", "", (code or "").lower())


def digits(code):
    return re.sub(r"\D", "", code or "")[:6]


def totp_qr_data_uri(otpauth_uri):
    """SVG QR code as a data: URI, generated locally (the secret never goes to a third party)."""
    import qrcode
    import qrcode.image.svg

    img = qrcode.make(otpauth_uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()
