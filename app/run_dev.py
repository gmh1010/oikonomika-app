"""Local development only: the app against the local Supabase stack (DB + Auth + Mailpit) with real login.

Sign up at http://127.0.0.1:5080/auth/signup with invite code "dev-invite";
confirmation emails arrive in Mailpit at http://127.0.0.1:55324."""
import os
import secrets

from app import create_app

LOCAL = {
    "DATABASE_URL": "postgresql://app_user:change-me-local-only@127.0.0.1:55322/postgres",
    "SUPABASE_URL": "http://127.0.0.1:55321",
    # Local keys printed by `supabase status`; set them in your shell before running.
    "SUPABASE_PUBLISHABLE_KEY": os.environ.get("SUPABASE_PUBLISHABLE_KEY", ""),
    "SUPABASE_SECRET_KEY": os.environ.get("SUPABASE_SECRET_KEY", ""),
}

if __name__ == "__main__":
    from cryptography.fernet import Fernet

    app = create_app({
        **LOCAL,
        "SECRET_KEY": secrets.token_hex(32),
        "SESSION_ENC_KEY": Fernet.generate_key().decode(),   # new key per run: dev sessions don't survive restarts
        "IP_SALT": secrets.token_hex(8),
        "COOKIE_SECURE": False,                               # plain http on localhost
        "INVITE_CODE": os.environ.get("OIKO_DEV_INVITE", "dev-invite"),
    })
    app.run(host="127.0.0.1", port=int(os.environ.get("OIKO_DEV_PORT", "5080")), debug=False)
