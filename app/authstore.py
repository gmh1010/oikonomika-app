"""Sessions, rate limits, security events and recovery codes — only through oiko.* SECURITY DEFINER functions."""
import hashlib
import secrets

from cryptography.fernet import Fernet, InvalidToken


def hash_sid(sid):
    return hashlib.sha256(sid.encode()).hexdigest()


class AuthStore:
    def __init__(self, pool, enc_key):
        self.pool = pool
        self.fernet = Fernet(enc_key)

    def _one(self, sql, args=()):
        with self.pool.connection() as c:
            return c.execute(sql, args).fetchone()

    def _run(self, sql, args=()):
        with self.pool.connection() as c:
            c.execute(sql, args)

    # ---------- sessions ----------
    def create(self, user_id, email, refresh, aal, mfa_pending, ua, ip_hash, reauth=False):
        sid = secrets.token_urlsafe(32)
        enc = self.fernet.encrypt(refresh.encode()).decode()
        self._run("select oiko.session_create(%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                  (hash_sid(sid), user_id, email or "", enc, aal, mfa_pending, ua, ip_hash, reauth))
        return sid

    def get(self, sid):
        if not sid or len(sid) > 128:
            return None
        row = self._one("select * from oiko.session_get(%s)", (hash_sid(sid),))
        if not row:
            return None
        row = dict(row)
        try:
            row["refresh"] = self.fernet.decrypt(row.pop("refresh_enc").encode()).decode()
        except InvalidToken:
            self.delete(sid)
            return None
        row["sid"] = sid
        return row

    def update(self, sid, refresh=None, aal=None, mfa_pending=None, validated=False, reauth=False):
        enc = self.fernet.encrypt(refresh.encode()).decode() if refresh else None
        self._run("select oiko.session_update(%s, %s, %s, %s, %s, %s)",
                  (hash_sid(sid), enc, aal, mfa_pending, validated, reauth))

    def delete(self, sid):
        self._run("select oiko.session_delete(%s)", (hash_sid(sid),))

    def delete_all(self, sid):
        self._run("select oiko.session_delete_all(%s)", (hash_sid(sid),))

    def delete_others(self, sid):
        self._run("select oiko.session_delete_others(%s)", (hash_sid(sid),))

    # ---------- rate limits (keys are already hashed) ----------
    def rate_hit(self, key, window, limit):
        return self._one("select oiko.rate_hit(%s, %s, %s) ok", (key, window, limit))["ok"]

    def rate_check(self, key, window, limit):
        return self._one("select oiko.rate_check(%s, %s, %s) ok", (key, window, limit))["ok"]

    def rate_reset(self, key):
        self._run("select oiko.rate_reset(%s)", (key,))

    # ---------- events ----------
    def log_event(self, user_id, event, ip_hash, ua):
        self._run("select oiko.log_event(%s, %s, %s, %s)", (user_id, event, ip_hash, ua))

    # ---------- recovery codes ----------
    def recovery_set(self, user_id, hashes):
        self._run("select oiko.recovery_set(%s, %s)", (user_id, list(hashes)))

    def recovery_use(self, user_id, code_hash):
        return self._one("select oiko.recovery_use(%s, %s) ok", (user_id, code_hash))["ok"]

    def recovery_left(self, user_id):
        return self._one("select oiko.recovery_left(%s) n", (user_id,))["n"]

    def recovery_clear(self, user_id):
        self._run("select oiko.recovery_clear(%s)", (user_id,))
