"""Sign-up, login, 2FA, password reset, Google sign-in, re-authentication.

Everything runs server-side against Supabase Auth. The browser only ever holds one HttpOnly session cookie;
refresh tokens stay encrypted in oiko.app_sessions and never reach the browser.
"""
import base64
import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import (Blueprint, abort, after_this_request, current_app, flash, g, redirect,
                   render_template, request, session, url_for)

import security
from gotrue import AuthError, has_password, jwt_claims, verified_factors

bp = Blueprint("auth", __name__)

# Reachable without a session. Everything else needs a full (2FA-complete) login.
PUBLIC = {"auth.login", "auth.signup", "auth.check_email", "auth.confirm", "auth.forgot",
          "auth.google", "auth.callback"}
MFA_PENDING_OK = {"auth.mfa", "auth.recovery_code", "auth.logout"}

REVALIDATE_AFTER = timedelta(minutes=15)
REAUTH_WINDOW = timedelta(minutes=10)
SESSION_MAX_AGE = 30 * 24 * 3600
LIMITS = {                       # (max attempts, window seconds)
    "login-acct": (5, 15 * 60),  # failed logins per account -> lockout
    "login-ip": (20, 15 * 60),
    "signup-ip": (5, 3600),
    "forgot-ip": (10, 3600),
    "forgot-email": (3, 3600),
    "mfa": (5, 5 * 60),
    "reauth": (5, 5 * 60),
}
TOKEN_HASH_RE = re.compile(r"^[0-9a-f]{20,128}$")


# ---------- plumbing ----------

def ctx():
    return current_app.extensions["oiko"]


def cookie_name():
    return "__Host-oiko" if current_app.config["COOKIE_SECURE"] else "oiko_sid"


def now():
    return datetime.now(timezone.utc)


def client_ip():
    return request.remote_addr or ""


def ip_hash():
    return security.key_hash("ip", client_ip(), current_app.config["IP_SALT"])[:32]


def user_agent():
    return (request.user_agent.string or "")[:300]


def log(event, user_id=None):
    ctx().store.log_event(user_id, event, ip_hash(), user_agent())


def rkey(kind, ident):
    return security.key_hash(kind, str(ident).lower())


def rate_hit(kind, ident):
    n, window = LIMITS[kind]
    return ctx().store.rate_hit(rkey(kind, ident), window, n)


def rate_blocked(kind, ident):
    n, window = LIMITS[kind]
    return not ctx().store.rate_check(rkey(kind, ident), window, n)


def safe_next(value):
    value = value or ""
    if value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return ""


def turnstile_passed():
    return security.turnstile_ok(current_app.config.get("TURNSTILE_SECRET"),
                                 request.form.get("cf-turnstile-response"), client_ip())


def aal_of(tokens):
    return jwt_claims(tokens.get("access_token", "")).get("aal", "aal1")


def fresh_reauth():
    r = g.user.get("reauth_at")
    return bool(r) and now() - r < REAUTH_WINDOW


def set_cookie_after(sid):
    secure = current_app.config["COOKIE_SECURE"]

    @after_this_request
    def _set(resp):
        resp.set_cookie(cookie_name(), sid, max_age=SESSION_MAX_AGE, secure=secure, httponly=True,
                        samesite="Lax", path="/")
        return resp


def clear_cookie(resp):
    resp.delete_cookie(cookie_name(), path="/", secure=current_app.config["COOKIE_SECURE"], samesite="Lax")
    return resp


def start_session(tokens, reauth=False):
    """Create our session from Auth tokens. Returns True if a 2FA code is still required."""
    user = tokens["user"]
    aal = aal_of(tokens)
    pending = bool(verified_factors(user)) and aal != "aal2"
    old = request.cookies.get(cookie_name())
    if old:
        ctx().store.delete(old)                      # no session fixation: always a brand-new id
    session.clear()                                  # new CSRF token for the new session
    sid = ctx().store.create(user["id"], user.get("email", ""), tokens["refresh_token"], aal, pending,
                             user_agent(), ip_hash(), reauth)
    set_cookie_after(sid)
    g.user = {"sid": sid, "user_id": user["id"], "email": user.get("email", ""), "mfa_pending": pending,
              "refresh": tokens["refresh_token"], "aal": aal, "reauth_at": now() if reauth else None}
    return pending


def load_user():
    """Current session or None. Re-validates with Auth every 15 minutes (revoked users drop out)."""
    sid = request.cookies.get(cookie_name())
    if not sid:
        return None
    s = ctx().store.get(sid)
    if not s:
        return None
    if not s["mfa_pending"] and now() - s["validated_at"] > REVALIDATE_AFTER:
        try:
            tokens = ctx().gotrue.refresh(s["refresh"])
        except AuthError as e:
            if e.status == 503:
                return s                             # Auth briefly down: keep the session
            ctx().store.delete(sid)
            return None
        ctx().store.update(sid, refresh=tokens["refresh_token"], validated=True)
        s["refresh"] = tokens["refresh_token"]
    return s


def access_token():
    """Fresh access token + current Auth user for this session (rotates the refresh token)."""
    tokens = ctx().gotrue.refresh(g.user["refresh"])
    ctx().store.update(g.user["sid"], refresh=tokens["refresh_token"], validated=True)
    g.user["refresh"] = tokens["refresh_token"]
    return tokens["access_token"], tokens["user"]


def auth_down():
    flash("Η υπηρεσία σύνδεσης δεν απαντά αυτή τη στιγμή — δοκίμασε ξανά σε λίγο", "err")


# ---------- login / logout ----------

@bp.route("/auth/login", methods=["GET", "POST"])
def login():
    if g.get("user") and not g.user["mfa_pending"]:
        return redirect(url_for("dashboard"))
    nxt = safe_next(request.values.get("next"))
    if request.method in ("GET", "HEAD"):
        return render_template("auth/login.html", email="", next=nxt)
    email = (request.form.get("email") or "").strip().lower()[:254]
    password = request.form.get("password") or ""
    if not turnstile_passed():
        flash("Επιβεβαίωσε ότι δεν είσαι ρομπότ", "err")
        return render_template("auth/login.html", email=email, next=nxt), 400
    if not rate_hit("login-ip", client_ip()) or rate_blocked("login-acct", email):
        log("login_locked")
        flash("Πολλές αποτυχημένες προσπάθειες — δοκίμασε ξανά σε 15 λεπτά", "err")
        return render_template("auth/login.html", email=email, next=nxt), 429
    try:
        tokens = ctx().gotrue.password_login(email, password)
    except AuthError as e:
        if e.code == "email_not_confirmed":
            flash("Επιβεβαίωσε πρώτα το email σου — δες τα εισερχόμενά σου", "err")
        elif e.status in (429, 503):
            auth_down()
        else:
            rate_hit("login-acct", email)
            log("login_fail")
            flash("Λάθος email ή κωδικός", "err")
        return render_template("auth/login.html", email=email, next=nxt), 400
    ctx().store.rate_reset(rkey("login-acct", email))
    pending = start_session(tokens)
    log("login_ok", tokens["user"]["id"])
    if pending:
        return redirect(url_for("auth.mfa", next=nxt or None))
    return redirect(nxt or url_for("dashboard"))


@bp.route("/auth/logout", methods=["POST"])
def logout():
    if g.get("user"):
        try:
            access, _ = access_token()
            ctx().gotrue.logout(access, "local")
        except AuthError:
            pass
        ctx().store.delete(g.user["sid"])
        log("logout", g.user["user_id"])
    session.clear()
    return clear_cookie(redirect(url_for("auth.login")))


@bp.route("/auth/logout-all", methods=["POST"])
def logout_all():
    try:
        access, _ = access_token()
        ctx().gotrue.logout(access, "global")
    except AuthError:
        pass
    ctx().store.delete_all(g.user["sid"])
    log("logout_all", g.user["user_id"])
    session.clear()
    flash("Αποσυνδέθηκες από όλες τις συσκευές", "ok")
    return clear_cookie(redirect(url_for("auth.login")))


# ---------- sign-up / email confirmation ----------

@bp.route("/auth/signup", methods=["GET", "POST"])
def signup():
    if request.method in ("GET", "HEAD"):
        return render_template("auth/signup.html", email="")
    email = (request.form.get("email") or "").strip().lower()[:254]
    password = request.form.get("password") or ""
    invite_required = current_app.config.get("INVITE_CODE")

    def fail(msg, code=400):
        flash(msg, "err")
        return render_template("auth/signup.html", email=email), code

    if not rate_hit("signup-ip", client_ip()):
        return fail("Πολλές εγγραφές από εδώ — δοκίμασε ξανά αργότερα", 429)
    if not turnstile_passed():
        return fail("Επιβεβαίωσε ότι δεν είσαι ρομπότ")
    if invite_required and not secrets.compare_digest(
            (request.form.get("invite") or "").strip().encode(), invite_required.encode()):
        return fail("Λάθος κωδικός πρόσκλησης")
    if not security.valid_email(email):
        return fail("Μη έγκυρο email")
    if password != (request.form.get("password2") or ""):
        return fail("Οι κωδικοί δεν ταιριάζουν")
    problem = security.password_problem(password, current_app.config["PWNED_CHECK"])
    if problem:
        return fail(problem)
    try:
        ctx().gotrue.signup(email, password)
    except AuthError as e:
        if e.code in ("user_already_exists", "email_exists"):
            pass                                     # identical answer: no way to probe who has an account
        elif e.code == "weak_password":
            return fail("Ο κωδικός δεν είναι αρκετά ισχυρός")
        elif e.status in (429, 503):
            return fail("Η υπηρεσία εγγραφής δεν απαντά — δοκίμασε ξανά σε λίγο", 503)
        else:
            return fail("Η εγγραφή απέτυχε — δοκίμασε ξανά")
    log("signup")
    return redirect(url_for("auth.check_email"))


@bp.route("/auth/check-email")
def check_email():
    return render_template("auth/check_email.html")


@bp.route("/auth/confirm", methods=["GET", "POST"])
def confirm():
    """Email links land here. GET only shows a button (mail scanners pre-fetch links); POST verifies."""
    token_hash = request.values.get("token_hash", "")
    type_ = request.values.get("type", "")
    if type_ not in ("email", "recovery") or not TOKEN_HASH_RE.match(token_hash):
        flash("Μη έγκυρος σύνδεσμος", "err")
        return redirect(url_for("auth.login"))
    if request.method in ("GET", "HEAD"):
        return render_template("auth/confirm.html", token_hash=token_hash, type=type_)
    try:
        tokens = ctx().gotrue.verify_token_hash(token_hash, type_)
    except AuthError as e:
        if e.status == 503:
            auth_down()
        else:
            flash("Ο σύνδεσμος έληξε ή χρησιμοποιήθηκε ήδη — ζήτησε νέο", "err")
        return redirect(url_for("auth.login"))
    uid = tokens["user"]["id"]
    if type_ == "recovery":
        pending = start_session(tokens, reauth=True)
        log("password_reset_link", uid)
        target = url_for("auth.password")
        return redirect(url_for("auth.mfa", next=target) if pending else target)
    pending = start_session(tokens)
    log("email_confirmed", uid)
    flash("Το email επιβεβαιώθηκε — καλώς ήρθες!", "ok")
    return redirect(url_for("auth.mfa") if pending else url_for("dashboard"))


# ---------- forgot password ----------

@bp.route("/auth/forgot", methods=["GET", "POST"])
def forgot():
    if request.method in ("GET", "HEAD"):
        return render_template("auth/forgot.html")
    email = (request.form.get("email") or "").strip().lower()[:254]
    if not turnstile_passed():
        flash("Επιβεβαίωσε ότι δεν είσαι ρομπότ", "err")
        return render_template("auth/forgot.html"), 400
    if security.valid_email(email) and rate_hit("forgot-ip", client_ip()) and rate_hit("forgot-email", email):
        try:
            ctx().gotrue.recover(email)
        except AuthError:
            pass
        log("password_reset_requested")
    # Same page whether or not the account exists (and whether or not we were rate limited).
    return render_template("auth/check_email.html", reset=True)


# ---------- 2FA at login ----------

@bp.route("/auth/mfa", methods=["GET", "POST"])
def mfa():
    if not g.get("user"):
        return redirect(url_for("auth.login"))
    nxt = safe_next(request.values.get("next"))
    if not g.user["mfa_pending"]:
        return redirect(nxt or url_for("dashboard"))
    if request.method in ("GET", "HEAD"):
        return render_template("auth/mfa.html", next=nxt)
    uid = g.user["user_id"]
    if not rate_hit("mfa", uid):
        flash("Πολλές προσπάθειες — περίμενε 5 λεπτά", "err")
        return render_template("auth/mfa.html", next=nxt), 429
    try:
        access, user = access_token()
        factor = verified_factors(user)[0]
        tokens = ctx().gotrue.mfa_challenge_verify(access, factor["id"], security.digits(request.form.get("code")))
    except (AuthError, IndexError):
        log("mfa_fail", uid)
        flash("Λάθος κωδικός — δοκίμασε τον τρέχοντα 6ψήφιο κωδικό", "err")
        return render_template("auth/mfa.html", next=nxt), 400
    ctx().store.update(g.user["sid"], refresh=tokens["refresh_token"], aal="aal2", mfa_pending=False,
                       validated=True)
    ctx().store.rate_reset(rkey("mfa", uid))
    log("mfa_ok", uid)
    return redirect(nxt or url_for("dashboard"))


@bp.route("/auth/recovery-code", methods=["POST"])
def recovery_code():
    if not g.get("user") or not g.user["mfa_pending"]:
        return redirect(url_for("auth.login"))
    uid = g.user["user_id"]
    if not rate_hit("mfa", uid):
        flash("Πολλές προσπάθειες — περίμενε 5 λεπτά", "err")
        return redirect(url_for("auth.mfa"))
    code = security.normalize_code(request.form.get("code"))
    if len(code) != 10 or not ctx().store.recovery_use(uid, security.key_hash("rc", code)):
        log("recovery_code_fail", uid)
        flash("Λάθος ή ήδη χρησιμοποιημένος κωδικός ανάκτησης", "err")
        return redirect(url_for("auth.mfa"))
    try:
        _, user = access_token()
        for f in verified_factors(user):
            ctx().gotrue.admin_delete_factor(uid, f["id"])
    except AuthError:
        auth_down()
        return redirect(url_for("auth.mfa"))
    ctx().store.recovery_clear(uid)
    ctx().store.update(g.user["sid"], mfa_pending=False, validated=True)
    log("recovery_code_used", uid)
    flash("Μπήκες με κωδικό ανάκτησης και το 2FA απενεργοποιήθηκε. Ενεργοποίησέ το ξανά τώρα.", "err")
    return redirect(url_for("auth.account"))


# ---------- Google ----------

@bp.route("/auth/google")
def google():
    if not current_app.config.get("GOOGLE_ENABLED"):
        abort(404)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    session["pkce"] = verifier
    session["pkce_reauth"] = request.args.get("reauth") == "1" and bool(g.get("user"))
    session["pkce_next"] = safe_next(request.args.get("next"))
    return redirect(ctx().gotrue.authorize_url("google", url_for("auth.callback", _external=True), challenge))


@bp.route("/auth/callback")
def callback():
    verifier = session.pop("pkce", None)
    reauth = session.pop("pkce_reauth", False)
    nxt = session.pop("pkce_next", "")
    code = request.args.get("code")
    if request.args.get("error") or not verifier or not code:
        flash("Η σύνδεση με Google ακυρώθηκε ή απέτυχε", "err")
        return redirect(url_for("auth.login"))
    try:
        tokens = ctx().gotrue.exchange_pkce(code, verifier)
    except AuthError:
        flash("Η σύνδεση με Google ακυρώθηκε ή απέτυχε", "err")
        return redirect(url_for("auth.login"))
    uid = tokens["user"]["id"]
    if reauth and g.get("user") and str(g.user["user_id"]) == uid:
        ctx().store.update(g.user["sid"], refresh=tokens["refresh_token"], aal=aal_of(tokens),
                           validated=True, reauth=True)
        log("reauth_ok", uid)
        return redirect(nxt or url_for("auth.account"))
    pending = start_session(tokens)
    log("login_ok", uid)
    return redirect(url_for("auth.mfa", next=nxt or None) if pending else (nxt or url_for("dashboard")))


# ---------- account & security ----------

@bp.route("/account")
def account():
    try:
        _, user = access_token()
    except AuthError:
        auth_down()
        return redirect(url_for("dashboard"))
    return render_template("auth/account.html", email=user.get("email", ""),
                           mfa_on=bool(verified_factors(user)),
                           codes_left=ctx().store.recovery_left(g.user["user_id"]),
                           has_password=has_password(user))


@bp.route("/account/reauth", methods=["GET", "POST"])
def reauth():
    nxt = safe_next(request.values.get("next")) or url_for("auth.account")
    try:
        _, user = access_token()
    except AuthError:
        auth_down()
        return redirect(url_for("dashboard"))
    mfa_on, pw_user = bool(verified_factors(user)), has_password(user)
    if request.method in ("GET", "HEAD"):
        return render_template("auth/reauth.html", next=nxt, mfa_on=mfa_on, has_password=pw_user)
    uid = g.user["user_id"]
    if not rate_hit("reauth", uid):
        flash("Πολλές προσπάθειες — περίμενε 5 λεπτά", "err")
        return render_template("auth/reauth.html", next=nxt, mfa_on=mfa_on, has_password=pw_user), 429
    if not pw_user:
        return redirect(url_for("auth.google", reauth=1, next=nxt))
    try:
        tokens = ctx().gotrue.password_login(user["email"], request.form.get("password") or "")
        if mfa_on:
            tokens = ctx().gotrue.mfa_challenge_verify(tokens["access_token"], verified_factors(user)[0]["id"],
                                                       security.digits(request.form.get("code")))
    except AuthError:
        log("reauth_fail", uid)
        flash("Λάθος κωδικός" + (" ή κωδικός 2FA" if mfa_on else ""), "err")
        return render_template("auth/reauth.html", next=nxt, mfa_on=mfa_on, has_password=pw_user), 400
    ctx().store.update(g.user["sid"], refresh=tokens["refresh_token"], aal=aal_of(tokens),
                       validated=True, reauth=True)
    ctx().store.rate_reset(rkey("reauth", uid))
    log("reauth_ok", uid)
    return redirect(nxt)


@bp.route("/account/password", methods=["GET", "POST"])
def password():
    if not fresh_reauth():
        return redirect(url_for("auth.reauth", next=url_for("auth.password")))
    if request.method in ("GET", "HEAD"):
        return render_template("auth/password.html")
    new = request.form.get("password") or ""
    if new != (request.form.get("password2") or ""):
        flash("Οι κωδικοί δεν ταιριάζουν", "err")
        return render_template("auth/password.html"), 400
    problem = security.password_problem(new, current_app.config["PWNED_CHECK"])
    if problem:
        flash(problem, "err")
        return render_template("auth/password.html"), 400
    try:
        access, _ = access_token()
        ctx().gotrue.update_password(access, new)
    except AuthError as e:
        flash("Διάλεξε διαφορετικό κωδικό από τον τωρινό" if e.code == "same_password"
              else "Η αλλαγή κωδικού απέτυχε — δοκίμασε ξανά", "err")
        return render_template("auth/password.html"), 400
    try:
        ctx().gotrue.logout(access, "others")
    except AuthError:
        pass
    ctx().store.delete_others(g.user["sid"])
    log("password_changed", g.user["user_id"])
    flash("Ο κωδικός άλλαξε. Αποσυνδέθηκες από τις άλλες συσκευές.", "ok")
    return redirect(url_for("auth.account"))


@bp.route("/account/2fa", methods=["GET", "POST"])
def enroll():
    try:
        access, user = access_token()
    except AuthError:
        auth_down()
        return redirect(url_for("auth.account"))
    if verified_factors(user):
        return redirect(url_for("auth.account"))
    if request.method in ("GET", "HEAD"):
        for f in (user.get("factors") or []):
            if f.get("status") != "verified":
                try:
                    ctx().gotrue.mfa_unenroll(access, f["id"])
                except AuthError:
                    pass
        try:
            factor = ctx().gotrue.mfa_enroll(access, f"Οικονομικά {secrets.token_hex(2)}")
        except AuthError:
            auth_down()
            return redirect(url_for("auth.account"))
        # The pending secret rides in the (signed, readable) Flask cookie only in encrypted form.
        session["enroll"] = ctx().store.fernet.encrypt(json.dumps(
            [factor["id"], factor["totp"]["uri"], factor["totp"]["secret"]]).encode()).decode()
    try:
        fid, uri, secret = json.loads(ctx().store.fernet.decrypt(session["enroll"].encode()))
    except Exception:
        return redirect(url_for("auth.enroll"))
    page = dict(qr=security.totp_qr_data_uri(uri), secret=secret)
    if request.method in ("GET", "HEAD"):
        return render_template("auth/enroll.html", **page)
    uid = g.user["user_id"]
    if not rate_hit("mfa", uid):
        flash("Πολλές προσπάθειες — περίμενε 5 λεπτά", "err")
        return render_template("auth/enroll.html", **page), 429
    try:
        tokens = ctx().gotrue.mfa_challenge_verify(access, fid, security.digits(request.form.get("code")))
    except AuthError:
        flash("Λάθος κωδικός — γράψε τον 6ψήφιο κωδικό που δείχνει τώρα η εφαρμογή", "err")
        return render_template("auth/enroll.html", **page), 400
    session.pop("enroll", None)
    ctx().store.update(g.user["sid"], refresh=tokens["refresh_token"], aal="aal2", validated=True)
    codes = security.new_recovery_codes()
    ctx().store.recovery_set(uid, [security.key_hash("rc", security.normalize_code(c)) for c in codes])
    log("2fa_enabled", uid)
    return render_template("auth/recovery_codes.html", codes=codes)


@bp.route("/account/2fa/disable", methods=["POST"])
def disable_2fa():
    if not fresh_reauth():
        return redirect(url_for("auth.reauth", next=url_for("auth.account")))
    uid = g.user["user_id"]
    try:
        access, user = access_token()
        for f in verified_factors(user):
            ctx().gotrue.mfa_unenroll(access, f["id"])
    except AuthError:
        flash("Η απενεργοποίηση απέτυχε — ξανακάνε επιβεβαίωση ταυτότητας", "err")
        return redirect(url_for("auth.reauth", next=url_for("auth.account")))
    ctx().store.recovery_clear(uid)
    log("2fa_disabled", uid)
    flash("Το 2FA απενεργοποιήθηκε", "ok")
    return redirect(url_for("auth.account"))
