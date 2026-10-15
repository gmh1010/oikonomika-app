"""End-to-end auth flows against the real local Supabase Auth + Mailpit."""
import re
import time
import uuid
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
import requests

MAILPIT = "http://127.0.0.1:55324/api/v1"
PW = "goodpass2026x"
INVITE = "beta-invite"


@pytest.fixture
def authapp(pool, admin):
    from cryptography.fernet import Fernet

    from app import create_app
    from conftest import APP_URL, LOCAL_AUTH

    def _make(**over):
        cfg = {"DATABASE_URL": APP_URL, "POOL": pool, "SECRET_KEY": "test", "TESTING": True,
               "SESSION_ENC_KEY": Fernet.generate_key().decode(), "INVITE_CODE": INVITE, "IP_SALT": "salt",
               "COOKIE_SECURE": False, "PWNED_CHECK": lambda pw: pw.startswith("pwned"), **LOCAL_AUTH}
        cfg.update(over)
        return create_app(cfg)
    yield _make
    admin.execute("delete from oiko.budgets b where exists (select 1 from oiko.budget_members m join auth.users u "
                  "on u.id = m.user_id where m.budget_id = b.id and u.email like 'auth-%%@test.oiko')")
    admin.execute("delete from auth.users where email like 'auth-%%@test.oiko'")
    admin.execute("delete from oiko.rate_limits")


def new_email():
    return f"auth-{uuid.uuid4().hex[:10]}@test.oiko"


def mail_link(email, subject_part, timeout=10):
    """Newest email to `email` whose subject contains subject_part -> (path, query dict)."""
    end = time.time() + timeout
    while time.time() < end:
        msgs = requests.get(f"{MAILPIT}/search", params={"query": f"to:{email}"}).json().get("messages", [])
        for m in msgs:
            if subject_part in m["Subject"]:
                html = requests.get(f"{MAILPIT}/message/{m['ID']}").json()["HTML"]
                u = urlparse(re.search(r'href="([^"]+)"', html).group(1).replace("&amp;", "&"))
                return u.path, {k: v[0] for k, v in parse_qs(u.query).items()}
        time.sleep(0.3)
    raise AssertionError(f"no mail '{subject_part}' for {email}")


def signup(c, email, pw=PW, invite=INVITE):
    return c.post("/auth/signup", data={"email": email, "password": pw, "password2": pw, "invite": invite})


def confirm(c, email):
    path, q = mail_link(email, "Επιβεβαίωση")
    return c.post(path, data=q)


def registered(app, email=None):
    """A confirmed, logged-in client."""
    c = app.test_client()
    email = email or new_email()
    assert signup(c, email).status_code == 302
    r = confirm(c, email)
    assert r.status_code == 302
    return c, email


def login(c, email, pw=PW):
    return c.post("/auth/login", data={"email": email, "password": pw})


def text(r):
    return r.get_data(as_text=True)


# ---------- access control ----------

def test_anonymous_is_sent_to_login(authapp):
    c = authapp().test_client()
    r = c.get("/tx?m=2026-09")
    assert r.status_code == 302 and "/auth/login" in r.headers["Location"] and "next=" in r.headers["Location"]
    assert c.post("/tx/add", data={"amount": "1"}).status_code == 401
    assert c.get("/auth/login").status_code == 200 and c.get("/auth/signup").status_code == 200


def test_head_requests_behave_like_get(authapp):
    """Uptime monitors send HEAD; it must never be treated as a form submission."""
    c = authapp().test_client()
    for path in ("/auth/login", "/auth/signup", "/auth/forgot", "/healthz"):
        assert c.head(path).status_code == 200, path
    assert c.head("/tx").status_code == 302                          # anonymous -> login, like GET


# ---------- sign-up ----------

def test_signup_requires_invite_and_strong_password(authapp, admin):
    c = authapp().test_client()
    email = new_email()
    assert "Λάθος κωδικός πρόσκλησης" in text(signup(c, email, invite="nope"))
    assert "10 χαρακτήρες" in text(signup(c, email, pw="short1"))
    assert "αριθμούς" in text(signup(c, email, pw="onlylettersxx"))
    assert "διαρρεύσει" in text(signup(c, email, pw="pwned12345678"))
    r = c.post("/auth/signup", data={"email": email, "password": PW, "password2": PW + "x", "invite": INVITE})
    assert "δεν ταιριάζουν" in text(r)
    assert admin.execute("select count(*) n from auth.users where email = %s", (email,)).fetchone()["n"] == 0


def test_signup_confirm_login_flow(authapp):
    app = authapp()
    c = app.test_client()
    email = new_email()
    r = signup(c, email)
    assert r.status_code == 302 and r.headers["Location"].endswith("/auth/check-email")
    assert "Επιβεβαίωσε πρώτα" in text(login(c, email))
    path, q = mail_link(email, "Επιβεβαίωση")
    assert path == "/auth/confirm" and q["type"] == "email"
    page = c.get(path, query_string=q)            # link scanners only GET: nothing is consumed
    assert page.status_code == 200 and "Συνέχεια" in text(page)
    r = c.post(path, data=q)
    assert r.status_code == 302
    dash = c.get("/")
    assert dash.status_code == 200 and "🛒 Σούπερ μάρκετ" in text(dash)
    assert c.post(path, data=q, follow_redirects=True).status_code == 200   # re-use -> expired message
    c.post("/auth/logout")
    assert c.get("/").status_code == 302
    r = login(c, email)
    assert r.status_code == 302 and c.get("/").status_code == 200


def test_existing_email_signup_looks_identical(authapp):
    app = authapp()
    _, email = registered(app)
    fresh = app.test_client()
    a = signup(fresh, email)
    b = signup(fresh, new_email())
    assert (a.status_code, a.headers["Location"]) == (b.status_code, b.headers["Location"])


def test_bad_confirm_token(authapp):
    c = authapp().test_client()
    r = c.post("/auth/confirm", data={"token_hash": "ab" * 28, "type": "email"}, follow_redirects=True)
    assert "έληξε" in text(r)
    evil = "<script>alert(7331)</script>"
    r = c.get("/auth/confirm", query_string={"token_hash": evil, "type": "email"}, follow_redirects=True)
    assert "Μη έγκυρος" in text(r) and "7331" not in text(r)


# ---------- login protection ----------

def test_wrong_password_is_generic_then_locked(authapp):
    app = authapp()
    _, email = registered(app)
    c = app.test_client()
    for _ in range(5):
        r = login(c, email, "wrongpass999")
        assert r.status_code == 400 and "Λάθος email ή κωδικός" in text(r)
    r = login(c, email)                               # right password, but locked
    assert r.status_code == 429 and "15 λεπτά" in text(r)
    r = login(c, new_email(), "whatever123")          # unknown account: same generic answer
    assert "Λάθος email ή κωδικός" in text(r)


# ---------- password reset ----------

def test_forgot_and_reset_password(authapp):
    app = authapp()
    other, email = registered(app)                   # a second, older session of the same user
    c = app.test_client()
    unknown = c.post("/auth/forgot", data={"email": new_email()})
    known = c.post("/auth/forgot", data={"email": email})
    assert text(unknown) == text(known) and "Αν υπάρχει λογαριασμός" in text(known)
    path, q = mail_link(email, "Αλλαγή κωδικού")
    assert q["type"] == "recovery"
    r = c.post(path, data=q)
    assert r.status_code == 302 and r.headers["Location"].endswith("/account/password")
    r = c.post("/account/password", data={"password": "brandnew2027x", "password2": "brandnew2027x"})
    assert r.status_code == 302
    assert other.get("/").status_code == 302          # other sessions were signed out
    fresh = app.test_client()
    assert login(fresh, email).status_code == 400
    assert login(fresh, email, "brandnew2027x").status_code == 302


# ---------- 2FA ----------

def enroll(c):
    page = text(c.get("/account/2fa"))
    assert "data:image/svg+xml;base64," in page
    secret = re.search(r'id="totp-secret">([A-Z2-7]+)<', page).group(1)
    r = c.post("/account/2fa", data={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200
    codes = re.findall(r'class="rcode">([a-z2-9]{5}-[a-z2-9]{5})<', text(r))
    assert len(codes) == 8
    return secret, codes


def fresh_code(secret, used):
    """TOTP code not used before (Auth may refuse a replayed code within the same 30 s window)."""
    code = pyotp.TOTP(secret).now()
    while code in used:
        time.sleep(1)
        code = pyotp.TOTP(secret).now()
    used.add(code)
    return code


def test_2fa_enroll_login_and_recovery_code(authapp):
    app = authapp()
    c, email = registered(app)
    secret, codes = enroll(c)
    used = {pyotp.TOTP(secret).now()}
    assert "Ενεργό" in text(c.get("/account"))
    c.post("/auth/logout")

    r = login(c, email)
    assert r.status_code == 302 and "/auth/mfa" in r.headers["Location"]
    assert "/auth/mfa" in c.get("/tx").headers["Location"]          # data locked until the code
    assert c.post("/tx/add", data={"amount": "1"}).status_code in (302, 401)
    assert c.post("/auth/mfa", data={"code": "000000"}).status_code == 400
    r = c.post("/auth/mfa", data={"code": fresh_code(secret, used)})
    assert r.status_code == 302 and c.get("/").status_code == 200
    c.post("/auth/logout")

    login(c, email)
    r = c.post("/auth/recovery-code", data={"code": codes[0].upper()})
    assert r.status_code == 302 and c.get("/").status_code == 200
    assert "Ανενεργό" in text(c.get("/account"))                     # recovery code turned 2FA off
    c.post("/auth/logout")
    assert login(c, email).headers["Location"].endswith("/")        # no 2FA prompt any more


def test_account_pages_keep_the_chosen_theme(authapp):
    c, _ = registered(authapp())
    c.post("/settings", data={"title": "X", "currency": "€", "accent": "#2563eb", "opening_balance": "0",
                              "theme": "light"})
    assert '<html lang="el" class="light">' in text(c.get("/"))
    assert '<html lang="el" class="light">' in text(c.get("/account"))
    assert '<html lang="el" class="light">' in text(c.get("/account/password", follow_redirects=True))


def test_disable_2fa_needs_fresh_reauth(authapp):
    app = authapp()
    c, email = registered(app)
    secret, _ = enroll(c)
    used = {pyotp.TOTP(secret).now()}
    c.post("/auth/logout")
    login(c, email)
    c.post("/auth/mfa", data={"code": fresh_code(secret, used)})
    r = c.post("/account/2fa/disable")
    assert r.status_code == 302 and "/account/reauth" in r.headers["Location"]
    assert "Ενεργό" in text(c.get("/account"))
    bad = c.post("/account/reauth", data={"password": "wrongpass999", "code": fresh_code(secret, used)})
    assert bad.status_code == 400
    ok = c.post("/account/reauth?next=/account", data={"password": PW, "code": fresh_code(secret, used)})
    assert ok.status_code == 302
    c.post("/account/2fa/disable")
    assert "Ανενεργό" in text(c.get("/account"))


def test_password_change_needs_reauth(authapp):
    app = authapp()
    c, email = registered(app)
    r = c.get("/account/password")
    assert r.status_code == 302 and "/account/reauth" in r.headers["Location"]
    c.post("/account/reauth", data={"password": PW})
    r = c.post("/account/password", data={"password": "another2028y", "password2": "another2028y"})
    assert r.status_code == 302
    assert login(app.test_client(), email, "another2028y").status_code == 302


# ---------- sessions ----------

def test_logout_everywhere(authapp):
    app = authapp()
    a, email = registered(app)
    b = app.test_client()
    assert login(b, email).status_code == 302 and b.get("/").status_code == 200
    a.post("/auth/logout-all")
    assert a.get("/").status_code == 302 and b.get("/").status_code == 302


def test_idle_session_expires(authapp, admin):
    app = authapp()
    c, email = registered(app)
    admin.execute("update oiko.app_sessions s set last_seen_at = now() - interval '13 hours' "
                  "from auth.users u where u.id = s.user_id and u.email = %s", (email,))
    assert c.get("/").status_code == 302


def test_revoked_session_dropped_at_revalidation(authapp, admin):
    app = authapp()
    a, email = registered(app)
    assert a.get("/").status_code == 200
    # Revoke on the Auth side only (e.g. user deleted/banned, or signed out via another app):
    admin.execute("delete from auth.sessions s using auth.users u where u.id = s.user_id and u.email = %s", (email,))
    assert a.get("/").status_code == 200              # still inside the 15-minute validation window
    admin.execute("update oiko.app_sessions s set validated_at = now() - interval '20 minutes' "
                  "from auth.users u where u.id = s.user_id and u.email = %s", (email,))
    assert a.get("/").status_code == 302              # re-validation with Auth fails -> signed out


def test_session_cookie_flags(authapp):
    app = authapp(COOKIE_SECURE=True)
    c = app.test_client()
    email = new_email()
    signup(c, email)
    path, q = mail_link(email, "Επιβεβαίωση")
    r = c.post(path, data=q, base_url="https://localhost")
    cookie = [h for h in r.headers.getlist("Set-Cookie") if h.startswith("__Host-oiko=")][0]
    for flag in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
        assert flag in cookie
    assert "Domain" not in cookie


def test_csrf_enforced_on_login(authapp):
    c = authapp(TESTING=False).test_client()
    assert c.post("/auth/login", data={"email": "a@b.cd", "password": "x"}).status_code == 400


def test_google_start_uses_pkce(authapp):
    c = authapp(GOOGLE_ENABLED=True).test_client()
    r = c.get("/auth/google")
    loc = urlparse(r.headers["Location"])
    q = parse_qs(loc.query)
    assert loc.path == "/auth/v1/authorize" and q["provider"] == ["google"]
    assert q["code_challenge_method"] == ["s256"] and len(q["code_challenge"][0]) == 43
    assert q["redirect_to"][0].endswith("/auth/callback")
    r = c.get("/auth/callback?code=fake", follow_redirects=True)
    assert "Google" in text(r) and "/auth/login" in r.request.path
    assert authapp().test_client().get("/auth/google").status_code == 404   # off unless configured


def test_security_events_logged(authapp, admin):
    app = authapp()
    c, email = registered(app)
    c.post("/auth/logout")
    login(c, email, "wrongpass999")
    login(c, email)
    events = [r["event"] for r in admin.execute(
        "select e.event from oiko.security_events e join auth.users u on u.id = e.user_id "
        "where u.email = %s order by e.id", (email,)).fetchall()]
    assert events[:1] == ["email_confirmed"] and "logout" in events and "login_ok" in events
