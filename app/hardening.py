"""Response headers (strict CSP etc.), reverse-proxy handling, generic error pages, privacy-safe request logs."""
import json
import logging
import time

from flask import g, render_template, request
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

TURNSTILE = "https://challenges.cloudflare.com"

# script-src is strict: our own static files + Cloudflare Turnstile only (no inline, no eval).
# style-src keeps 'unsafe-inline' for per-row colour/width style attributes; CSS cannot execute code.
CSP = "; ".join([
    "default-src 'self'",
    f"script-src 'self' {TURNSTILE}",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    f"frame-src {TURNSTILE}",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
])

ERRORS = {
    400: ("Μη έγκυρο αίτημα", "Η φόρμα έληξε ή κάτι δεν ήταν σωστό. Ανανέωσε τη σελίδα και δοκίμασε ξανά."),
    401: ("Χρειάζεται σύνδεση", "Συνδέσου για να συνεχίσεις."),
    403: ("Δεν επιτρέπεται", "Δεν έχεις πρόσβαση σε αυτή τη σελίδα."),
    404: ("Δεν βρέθηκε", "Η σελίδα ή η εγγραφή δεν υπάρχει."),
    405: ("Μη επιτρεπτή ενέργεια", "Αυτή η ενέργεια δεν γίνεται έτσι."),
    413: ("Πολύ μεγάλο αρχείο", "Το αρχείο είναι πολύ μεγάλο. Ανέβασε μικρότερα αρχεία (έως 10 MB το καθένα)."),
    429: ("Πολλές προσπάθειες", "Περίμενε λίγο και δοκίμασε ξανά."),
    500: ("Κάτι πήγε στραβά", "Έγινε ένα απρόσμενο σφάλμα. Δοκίμασε ξανά σε λίγο."),
}

req_log = logging.getLogger("oiko.request")
err_log = logging.getLogger("oiko.error")


def init_app(app):
    if app.config.get("TRUST_PROXY"):
        # Behind exactly one reverse proxy (Caddy): trust its X-Forwarded-For / -Proto only.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    @app.before_request
    def _start_timer():
        g._t0 = time.perf_counter()

    @app.after_request
    def _headers(resp):
        h = resp.headers
        h["Content-Security-Policy"] = CSP
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "strict-origin-when-cross-origin"
        h["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        if app.config.get("COOKIE_SECURE"):
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "static":
            # Financial pages must not stay in shared/back-button caches.
            h["Cache-Control"] = "no-store, max-age=0"
            h["Pragma"] = "no-cache"
        return resp

    @app.after_request
    def _log(resp):
        # Path only: never the query string (search terms, email tokens), never bodies, users or amounts.
        ms = (time.perf_counter() - g.get("_t0", time.perf_counter())) * 1000
        req_log.info(json.dumps({"method": request.method, "path": request.path, "status": resp.status_code,
                                 "ms": round(ms, 1)}, ensure_ascii=False))
        return resp

    def _page(code):
        title, text = ERRORS.get(code, ERRORS[500])
        return render_template("error.html", code=code, title=title, text=text), code

    @app.errorhandler(HTTPException)
    def _http_error(e):
        if e.code is None or 300 <= e.code < 400:
            return e
        if e.code == 500:
            # Unhandled crash (Flask wraps it; in tests it propagates instead so failures stay visible).
            # Full detail goes to the server log only; the visitor sees a generic page.
            orig = getattr(e, "original_exception", None) or e
            err_log.error("unhandled error on %s %s", request.method, request.path,
                          exc_info=(type(orig), orig, orig.__traceback__))
        return _page(e.code if e.code in ERRORS else 500)
