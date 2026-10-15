"""Production entry point (gunicorn wsgi:app). All configuration comes from environment variables,
which the server fills from a root-only secrets file."""
import logging
import os
import sys

from app import create_app

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")


def _env(name, default=None, required=True):
    v = os.environ.get(name, default)
    if required and not v:
        raise RuntimeError(f"missing environment variable {name}")
    return v


def _flag(name, default="false"):
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


app = create_app({
    "DATABASE_URL": _env("DATABASE_URL"),
    "SECRET_KEY": _env("SECRET_KEY"),
    "SUPABASE_URL": _env("SUPABASE_URL"),
    "SUPABASE_PUBLISHABLE_KEY": _env("SUPABASE_PUBLISHABLE_KEY"),
    "SUPABASE_SECRET_KEY": _env("SUPABASE_SECRET_KEY"),
    "SESSION_ENC_KEY": _env("SESSION_ENC_KEY"),
    "IP_SALT": _env("IP_SALT"),
    "INVITE_CODE": _env("INVITE_CODE", required=False) or None,
    "TURNSTILE_SITE_KEY": _env("TURNSTILE_SITE_KEY", required=False) or None,
    "TURNSTILE_SECRET": _env("TURNSTILE_SECRET", required=False) or None,
    "GOOGLE_ENABLED": _flag("GOOGLE_ENABLED"),
    "COOKIE_SECURE": _flag("COOKIE_SECURE", "true"),
    "TRUST_PROXY": _flag("TRUST_PROXY", "true"),
    "SCAN_QUOTA": int(_env("SCAN_QUOTA", "30", required=False)),
    "PREFERRED_URL_SCHEME": "https" if _flag("COOKIE_SECURE", "true") else "http",
})
