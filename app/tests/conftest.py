import os
import sys
import uuid
from contextlib import contextmanager
from types import SimpleNamespace

import psycopg
import pytest
from psycopg.rows import dict_row

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_DIR)

import db  # noqa: E402
import repo  # noqa: E402

ADMIN_URL = os.environ.get("OIKO_TEST_ADMIN_URL", "postgresql://postgres:postgres@127.0.0.1:55322/postgres")
APP_URL = os.environ.get("OIKO_TEST_APP_URL", "postgresql://app_user:change-me-local-only@127.0.0.1:55322/postgres")
# Local Supabase defaults (public, local-only values printed by `supabase start`).
LOCAL_AUTH = {
    "SUPABASE_URL": os.environ.get("OIKO_TEST_SUPABASE_URL", "http://127.0.0.1:55321"),
    "SUPABASE_PUBLISHABLE_KEY": os.environ.get("OIKO_TEST_PUB_KEY", ""),
    "SUPABASE_SECRET_KEY": os.environ.get("OIKO_TEST_SECRET_KEY", ""),
}


@pytest.fixture(scope="session")
def admin():
    try:
        conn = psycopg.connect(ADMIN_URL, autocommit=True, row_factory=dict_row)
    except psycopg.OperationalError:
        pytest.exit("Local Supabase is not running. Run `supabase start` in the repo root.", 2)
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def pool(admin):
    p = db.make_pool(APP_URL, max_size=4)
    yield p
    p.close()


@pytest.fixture
def make_user(admin):
    """make_user("a") -> uuid of a new auth.users row; everything it owns is deleted after the test."""
    created = []

    def _make(label="u"):
        email = f"{label}-{uuid.uuid4().hex[:8]}@test.oiko"
        uid = admin.execute(
            "insert into auth.users (id, instance_id, aud, role, email) values "
            "(gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', %s) "
            "returning id", (email,)).fetchone()["id"]
        created.append(uid)
        return uid

    yield _make
    if created:
        admin.execute(
            "delete from oiko.budgets b where exists (select 1 from oiko.budget_members m "
            "where m.budget_id = b.id and m.user_id = any(%s))", (created,))
        admin.execute("delete from auth.users where id = any(%s)", (created,))


@pytest.fixture
def scope(pool):
    """with scope(user_id) as (cx, budget_id): ... — one committed transaction as that user."""
    @contextmanager
    def _scope(user_id):
        with db.scoped(pool, user_id) as cx:
            yield cx, repo.provision_budget(cx)
    return _scope


@pytest.fixture
def web(pool):
    """web(user_id) -> Flask test client logged in as that user (CSRF off unless testing=False)."""
    from app import create_app

    def _client(user_id, csrf=False):
        app = create_app({"DATABASE_URL": APP_URL, "POOL": pool, "SECRET_KEY": "test-secret",
                          "TESTING": True, "CSRF": csrf, "USER_RESOLVER": lambda: user_id})
        return app.test_client()
    return _client


def cat_id(cx, bid, name):
    return cx.execute("select id from oiko.categories where budget_id=%s and name=%s",
                      (bid, name)).fetchone()["id"]


@pytest.fixture
def ns():
    return SimpleNamespace
