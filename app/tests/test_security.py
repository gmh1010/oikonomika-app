import base64
import hashlib

import pytest
import requests

import security
from gotrue import has_password, jwt_claims, verified_factors


class FakeResp:
    def __init__(self, text="", json_data=None, status=200):
        self.text, self._json, self.status_code = text, json_data, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError("x")

    def json(self):
        return self._json


class FakeHTTP:
    def __init__(self, resp=None, exc=None):
        self.resp, self.exc, self.calls = resp, exc, []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        if self.exc:
            raise self.exc
        return self.resp

    post = get


def test_pwned_sends_only_prefix_and_matches_suffix():
    pw = "hunter2hunter2"
    sha = hashlib.sha1(pw.encode()).hexdigest().upper()
    http = FakeHTTP(FakeResp(f"0000000000000000000000000000000000A:0\n{sha[5:]}:42\n"))
    assert security.pwned(pw, http=http) is True
    url, kw = http.calls[0]
    assert url.endswith(sha[:5]) and pw not in url and sha[5:] not in url
    assert kw["headers"] == {"Add-Padding": "true"}
    assert security.pwned(pw, http=FakeHTTP(FakeResp(f"{sha[5:]}:0\n"))) is False  # padding entries
    assert security.pwned(pw, http=FakeHTTP(exc=requests.ConnectionError())) is None


@pytest.mark.parametrize("pw,ok", [("short1", False), ("onlyletterslong", False), ("1234567890123", False),
                                   ("x" * 70 + "1ψψ", False), ("goodpass2026", True)])
def test_password_rules(pw, ok):
    assert (security.password_problem(pw, lambda p: False) is None) == ok


def test_breached_password_rejected():
    assert "διαρρεύσει" in security.password_problem("goodpass2026", lambda p: True)
    assert security.password_problem("goodpass2026", lambda p: None) is None  # HIBP down -> allow


def test_turnstile():
    assert security.turnstile_ok(None, "", "1.2.3.4") is True
    assert security.turnstile_ok("s", "", "1.2.3.4") is False
    assert security.turnstile_ok("s", "tok", "1.2.3.4", http=FakeHTTP(FakeResp(json_data={"success": True}))) is True
    assert security.turnstile_ok("s", "tok", "1.2.3.4", http=FakeHTTP(FakeResp(json_data={"success": False}))) is False
    assert security.turnstile_ok("s", "tok", "1.2.3.4", http=FakeHTTP(exc=requests.Timeout())) is False


def test_recovery_codes_and_normalize():
    codes = security.new_recovery_codes()
    assert len(codes) == 8 and len(set(codes)) == 8
    assert all(len(c) == 11 and c[5] == "-" for c in codes)
    assert security.normalize_code(" K7Q2M-X9P4D ") == "k7q2mx9p4d"
    assert security.digits("12 34-56 99") == "123456"


def test_totp_qr_is_local_svg():
    uri = security.totp_qr_data_uri("otpauth://totp/Oikonomika:me@x?secret=JBSWY3DPEHPK3PXP&issuer=Oikonomika")
    assert uri.startswith("data:image/svg+xml;base64,")
    assert b"<svg" in base64.b64decode(uri.split(",", 1)[1])


def test_valid_email():
    assert security.valid_email("a.b@example.gr")
    assert not security.valid_email("no-at-sign") and not security.valid_email("a@b") and not security.valid_email("")


def test_gotrue_helpers():
    payload = base64.urlsafe_b64encode(b'{"aal":"aal2","sub":"u1"}').decode().rstrip("=")
    assert jwt_claims(f"h.{payload}.s")["aal"] == "aal2" and jwt_claims("garbage") == {}
    user = {"factors": [{"id": "1", "status": "verified", "factor_type": "totp"},
                        {"id": "2", "status": "unverified", "factor_type": "totp"}],
            "identities": [{"provider": "google"}]}
    assert [f["id"] for f in verified_factors(user)] == ["1"] and verified_factors({}) == []
    assert not has_password(user) and has_password({"identities": [{"provider": "email"}]})
