"""Postgres access. Every request uses exactly one transaction bound to one user (RLS reads app.user_id)."""
from contextlib import contextmanager

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


def make_pool(conninfo, max_size=5):
    # prepare_threshold=None: required behind Supabase's transaction-mode pooler.
    return ConnectionPool(
        conninfo, min_size=1, max_size=max_size, open=True,
        kwargs={"row_factory": dict_row, "prepare_threshold": None, "autocommit": True},
    )


@contextmanager
def scoped(pool, user_id):
    """Yield a connection inside a transaction where RLS sees `user_id`. Commits on success, rolls back on error."""
    with pool.connection() as conn:
        with conn.transaction():
            conn.execute("select set_config('app.user_id', %s, true)", (str(user_id),))
            yield conn
