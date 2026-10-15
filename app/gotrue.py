"""Server-side client for Supabase Auth (GoTrue). The browser never talks to Auth and never sees a token."""
import base64
import json
from urllib.parse import urlencode

import requests


class AuthError(Exception):
    def __init__(self, status, code="", message=""):
        super().__init__(f"{status} {code} {message}")
        self.status = status
        self.code = code or ""
        self.message = message or ""


def jwt_claims(token):
    """Read claims from a JWT we just received from Auth over our own server call (not from a browser)."""
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError, AttributeError):
        return {}


def verified_factors(user):
    return [f for f in (user or {}).get("factors") or []
            if f.get("status") == "verified" and f.get("factor_type") == "totp"]


def has_password(user):
    return any(i.get("provider") == "email" for i in (user or {}).get("identities") or [])


class GoTrue:
    def __init__(self, url, publishable_key, secret_key=None, timeout=10, http=None):
        self.base = url.rstrip("/")
        self.url = self.base + "/auth/v1"
        self.pub = publishable_key
        self.sec = secret_key
        self.timeout = timeout
        self.http = http or requests.Session()

    def _call(self, method, path, token=None, admin=False, **kw):
        headers = {"apikey": self.sec if admin else self.pub}
        if admin:
            headers["Authorization"] = f"Bearer {self.sec}"
        elif token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            r = self.http.request(method, self.url + path, headers=headers, timeout=self.timeout, **kw)
        except requests.RequestException:
            raise AuthError(503, "unavailable", "Auth service unavailable")
        if r.status_code >= 400:
            try:
                j = r.json()
            except ValueError:
                j = {}
            raise AuthError(r.status_code, j.get("error_code") or j.get("error") or "",
                            j.get("msg") or j.get("error_description") or j.get("message") or "")
        return r.json() if r.content else {}

    # --- sign-up / sign-in ---
    def signup(self, email, password):
        return self._call("POST", "/signup", json={"email": email, "password": password})

    def password_login(self, email, password):
        return self._call("POST", "/token?grant_type=password", json={"email": email, "password": password})

    def refresh(self, refresh_token):
        return self._call("POST", "/token?grant_type=refresh_token", json={"refresh_token": refresh_token})

    def verify_token_hash(self, token_hash, type_):
        return self._call("POST", "/verify", json={"type": type_, "token_hash": token_hash})

    def recover(self, email):
        return self._call("POST", "/recover", json={"email": email})

    def authorize_url(self, provider, redirect_to, code_challenge):
        q = urlencode({"provider": provider, "redirect_to": redirect_to, "code_challenge": code_challenge,
                       "code_challenge_method": "s256"})
        return f"{self.url}/authorize?{q}"

    def exchange_pkce(self, code, verifier):
        return self._call("POST", "/token?grant_type=pkce", json={"auth_code": code, "code_verifier": verifier})

    # --- signed-in user ---
    def get_user(self, access):
        return self._call("GET", "/user", token=access)

    def update_password(self, access, password):
        return self._call("PUT", "/user", token=access, json={"password": password})

    def logout(self, access, scope="local"):
        return self._call("POST", f"/logout?scope={scope}", token=access)

    # --- TOTP 2FA ---
    def mfa_enroll(self, access, name):
        return self._call("POST", "/factors", token=access, json={"factor_type": "totp", "friendly_name": name})

    def mfa_unenroll(self, access, factor_id):
        return self._call("DELETE", f"/factors/{factor_id}", token=access)

    def mfa_challenge_verify(self, access, factor_id, code):
        ch = self._call("POST", f"/factors/{factor_id}/challenge", token=access)
        return self._call("POST", f"/factors/{factor_id}/verify", token=access,
                          json={"challenge_id": ch["id"], "code": code})

    # --- admin (secret key, server only) ---
    def admin_delete_factor(self, user_id, factor_id):
        return self._call("DELETE", f"/admin/users/{user_id}/factors/{factor_id}", admin=True)
