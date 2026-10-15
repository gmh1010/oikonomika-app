"""Database wall: Row-Level Security, grants and roles, tested directly in SQL."""
import pytest
from psycopg import errors

import repo
from conftest import cat_id

OIKO_TABLES = ["budgets", "budget_members", "categories", "recurring", "transactions",
               "scan_usage", "security_events", "app_sessions", "rate_limits", "recovery_codes"]
AUTH_TABLES = ["app_sessions", "rate_limits", "recovery_codes"]
OIKO_FUNCTIONS = [
    "oiko.provision_budget()", "oiko.is_member(uuid)", "oiko.current_user_id()",
    "oiko.session_create(text,uuid,text,text,text,boolean,text,text,boolean)", "oiko.session_get(text)",
    "oiko.session_update(text,text,text,boolean,boolean,boolean)", "oiko.session_delete(text)",
    "oiko.session_delete_all(text)", "oiko.session_delete_others(text)",
    "oiko.rate_hit(text,integer,integer)", "oiko.rate_check(text,integer,integer)", "oiko.rate_reset(text)",
    "oiko.log_event(uuid,text,text,text)", "oiko.recovery_set(uuid,text[])", "oiko.recovery_use(uuid,text)",
    "oiko.recovery_left(uuid)", "oiko.recovery_clear(uuid)",
]


def test_every_table_has_forced_rls(admin):
    rows = admin.execute(
        "select c.relname, c.relrowsecurity, c.relforcerowsecurity from pg_class c "
        "join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'oiko' and c.relkind = 'r'").fetchall()
    assert sorted(r["relname"] for r in rows) == sorted(OIKO_TABLES)
    assert all(r["relrowsecurity"] and r["relforcerowsecurity"] for r in rows)


def test_app_user_is_restricted(admin):
    r = admin.execute("select rolsuper, rolbypassrls, rolcreaterole, rolcreatedb from pg_roles "
                      "where rolname = 'app_user'").fetchone()
    assert r is not None and not any(r.values())
    for table, priv in [("auth.users", "select"), ("oiko.budget_members", "insert"),
                        ("oiko.budgets", "insert"), ("oiko.budgets", "delete")]:
        assert not admin.execute("select has_table_privilege('app_user', %s, %s) p",
                                 (table, priv)).fetchone()["p"], (table, priv)


@pytest.mark.parametrize("role", ["anon", "authenticated"])
def test_supabase_api_roles_cannot_touch_oiko(admin, role):
    assert not admin.execute("select has_schema_privilege(%s, 'oiko', 'usage') p", (role,)).fetchone()["p"]
    for t in OIKO_TABLES:
        for priv in ("select", "insert", "update", "delete"):
            assert not admin.execute("select has_table_privilege(%s, %s, %s) p",
                                     (role, f"oiko.{t}", priv)).fetchone()["p"], (t, priv)
    for fn in OIKO_FUNCTIONS:
        assert not admin.execute("select has_function_privilege(%s, %s, 'execute') p",
                                 (role, fn)).fetchone()["p"], fn


def test_nothing_granted_to_public(admin):
    rows = admin.execute(
        "select table_name, privilege_type from information_schema.role_table_grants "
        "where grantee = 'PUBLIC' and table_schema = 'oiko'").fetchall()
    assert rows == []
    for fn in OIKO_FUNCTIONS:
        acl = admin.execute("select proacl::text a from pg_proc where oid = %s::regprocedure", (fn,)).fetchone()["a"]
        entries = acl.strip("{}").split(",") if acl else []
        grantees = {e.split("=", 1)[0] for e in entries}
        # an empty grantee ("=X/owner") means EXECUTE for PUBLIC; NULL acl means default (PUBLIC can execute)
        assert entries and "" not in grantees and not grantees & {"anon", "authenticated"}, (fn, acl)


def test_other_user_sees_and_changes_nothing(make_user, scope):
    a, b = make_user("a"), make_user("b")
    with scope(a) as (cx, bid_a):
        cat_a = cat_id(cx, bid_a, "Καφέδες")
        tx_a = repo.add_transaction(cx, bid_a, "2026-09-10", cat_a, 500, "secret-A")
    with scope(b) as (cx, bid_b):
        repo.add_transaction(cx, bid_b, "2026-09-10", cat_id(cx, bid_b, "Καφέδες"), 300, "mine-B")
        # No budget filter at all: RLS alone limits B to B's rows.
        notes = [r["note"] for r in cx.execute("select note from oiko.transactions").fetchall()]
        assert notes == ["mine-B"]
        assert cx.execute("select count(*) n from oiko.categories where budget_id = %s", (bid_a,)).fetchone()["n"] == 0
        assert cx.execute("select count(*) n from oiko.budgets").fetchone()["n"] == 1
        assert cx.execute("select count(*) n from oiko.budget_members").fetchone()["n"] == 1
        assert cx.execute("update oiko.transactions set amount_cents = 1 where id = %s", (tx_a,)).rowcount == 0
        assert cx.execute("delete from oiko.transactions where id = %s", (tx_a,)).rowcount == 0
        assert cx.execute("update oiko.budgets set name = 'x' where id = %s", (bid_a,)).rowcount == 0
        with pytest.raises(errors.InsufficientPrivilege):
            with cx.transaction():
                cx.execute("insert into oiko.transactions (budget_id, tdate, category_id, amount_cents) "
                           "values (%s, '2026-09-10', %s, 100)", (bid_a, cat_a))
    with scope(a) as (cx, bid):
        assert bid == bid_a
        assert repo.get_transaction(cx, bid_a, tx_a)["amount_cents"] == 500


def test_no_user_set_means_no_rows(make_user, scope, pool):
    a = make_user("a")
    with scope(a) as (cx, bid):
        repo.add_transaction(cx, bid, "2026-09-10", cat_id(cx, bid, "Καφέδες"), 500, "x")
    with pool.connection() as cx:
        assert cx.execute("select count(*) n from oiko.transactions").fetchone()["n"] == 0
        assert cx.execute("select count(*) n from oiko.categories").fetchone()["n"] == 0
        with pytest.raises(errors.RaiseException):
            cx.execute("select oiko.provision_budget()")


def test_cannot_point_at_another_budgets_category(make_user, scope):
    a, b = make_user("a"), make_user("b")
    with scope(a) as (cx, bid_a):
        cat_a = cat_id(cx, bid_a, "Καφέδες")
    with scope(b) as (cx, bid_b):
        with pytest.raises(ValueError):
            repo.add_transaction(cx, bid_b, "2026-09-10", cat_a, 100)
        assert cx.execute("select count(*) n from oiko.transactions").fetchone()["n"] == 0


def test_provision_is_idempotent_and_seeds_defaults(make_user, scope):
    a = make_user("a")
    with scope(a) as (cx, bid1):
        pass
    with scope(a) as (cx, bid2):
        assert bid1 == bid2
        cats = repo.list_categories(cx, bid2)
        names = {c["name"] for c in cats}
        assert {"Μισθός", "Άλλο έσοδο", "Σούπερ μάρκετ", "Καφέδες", "Άλλα"} <= names
        assert len(cats) == 15 and all(c["icon"] for c in cats)
        assert not any("Zita" in n or "TBI" in n for n in names)
        assert repo.list_recurring(cx, bid2) == []


def test_app_user_has_no_direct_access_to_auth_tables(admin):
    for t in AUTH_TABLES:
        for priv in ("select", "insert", "update", "delete"):
            assert not admin.execute("select has_table_privilege('app_user', %s, %s) p",
                                     (f"oiko.{t}", priv)).fetchone()["p"], (t, priv)


def test_session_functions_roundtrip_and_expiry(admin, make_user, pool):
    u = make_user("s")
    sid = "a" * 64
    with pool.connection() as c:
        c.execute("select oiko.session_create(%s, %s, 'e@x', 'enc', 'aal1', false, 'ua', 'ip', false)", (sid, u))
        row = c.execute("select * from oiko.session_get(%s)", (sid,)).fetchone()
        assert row["user_id"] == u and row["aal"] == "aal1" and row["refresh_enc"] == "enc"
        c.execute("select oiko.session_update(%s, 'enc2', 'aal2', null, true, true)", (sid,))
        row = c.execute("select * from oiko.session_get(%s)", (sid,)).fetchone()
        assert row["refresh_enc"] == "enc2" and row["aal"] == "aal2" and row["reauth_at"] is not None
        admin.execute("update oiko.app_sessions set last_seen_at = now() - interval '13 hours' where id_hash = %s", (sid,))
        assert c.execute("select * from oiko.session_get(%s)", (sid,)).fetchone() is None
        assert admin.execute("select count(*) n from oiko.app_sessions where id_hash = %s", (sid,)).fetchone()["n"] == 0


def test_pending_mfa_session_expires_after_10_minutes(admin, make_user, pool):
    u = make_user("p")
    sid = "b" * 64
    with pool.connection() as c:
        c.execute("select oiko.session_create(%s, %s, 'e@x', 'enc', 'aal1', true, 'ua', 'ip', false)", (sid, u))
        admin.execute("update oiko.app_sessions set created_at = now() - interval '11 minutes' where id_hash = %s", (sid,))
        assert c.execute("select * from oiko.session_get(%s)", (sid,)).fetchone() is None


def test_session_delete_all_only_touches_that_user(make_user, pool):
    a, b = make_user("a"), make_user("b")
    with pool.connection() as c:
        for sid, u in (("1" * 64, a), ("2" * 64, a), ("3" * 64, b)):
            c.execute("select oiko.session_create(%s, %s, 'e', 'enc', 'aal1', false, '', '', false)", (sid, u))
        c.execute("select oiko.session_delete_others(%s)", ("1" * 64,))
        assert c.execute("select * from oiko.session_get(%s)", ("1" * 64,)).fetchone() is not None
        assert c.execute("select * from oiko.session_get(%s)", ("2" * 64,)).fetchone() is None
        c.execute("select oiko.session_delete_all(%s)", ("1" * 64,))
        assert c.execute("select * from oiko.session_get(%s)", ("1" * 64,)).fetchone() is None
        assert c.execute("select * from oiko.session_get(%s)", ("3" * 64,)).fetchone() is not None
        c.execute("select oiko.session_delete(%s)", ("3" * 64,))


def test_rate_limit_functions(pool):
    k = "f" * 64  # the app always sends sha256 hex keys
    with pool.connection() as c:
        c.execute("select oiko.rate_reset(%s)", (k,))
        hits = [c.execute("select oiko.rate_hit(%s, 60, 3) ok", (k,)).fetchone()["ok"] for _ in range(4)]
        assert hits == [True, True, True, False]
        assert c.execute("select oiko.rate_check(%s, 60, 3) ok", (k,)).fetchone()["ok"] is False
        c.execute("select oiko.rate_reset(%s)", (k,))
        assert c.execute("select oiko.rate_check(%s, 60, 3) ok", (k,)).fetchone()["ok"] is True


def test_recovery_code_functions(make_user, pool):
    u = make_user("r")
    with pool.connection() as c:
        c.execute("select oiko.recovery_set(%s, %s)", (u, ["h1", "h2"]))
        assert c.execute("select oiko.recovery_left(%s) n", (u,)).fetchone()["n"] == 2
        assert c.execute("select oiko.recovery_use(%s, 'h1') ok", (u,)).fetchone()["ok"] is True
        assert c.execute("select oiko.recovery_use(%s, 'h1') ok", (u,)).fetchone()["ok"] is False
        assert c.execute("select oiko.recovery_left(%s) n", (u,)).fetchone()["n"] == 1
        c.execute("select oiko.recovery_clear(%s)", (u,))
        assert c.execute("select oiko.recovery_left(%s) n", (u,)).fetchone()["n"] == 0


def test_log_event_function(admin, make_user, pool):
    u = make_user("l")
    with pool.connection() as c:
        c.execute("select oiko.log_event(%s, 'login_ok', 'iphash', 'ua')", (u,))
        c.execute("select oiko.log_event(null, 'login_fail', 'iphash', 'ua')")
    assert admin.execute("select count(*) n from oiko.security_events where user_id = %s", (u,)).fetchone()["n"] == 1
    admin.execute("delete from oiko.security_events where user_id is null and ip_hash = 'iphash'")
