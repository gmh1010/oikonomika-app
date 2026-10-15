"""Budget-scoped data access.

Every function takes (cx, bid): a connection from db.scoped() and the caller's budget id.
Each query also filters by budget_id (application wall); RLS in the database is the second wall.
Mutations run inside a savepoint (cx.transaction()) so a failed statement never poisons the request.
"""
import calendar
import uuid
from datetime import date

from psycopg import errors


def uid(value):
    """UUID from user input; ValueError for anything else."""
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Μη έγκυρο αναγνωριστικό")


def _date(value):
    try:
        return date.fromisoformat(str(value)[:10])
    except (ValueError, TypeError):
        raise ValueError("Μη έγκυρη ημερομηνία")


def _iso(row):
    """dict row with tdate as 'YYYY-MM-DD' (templates slice it as a string)."""
    if row is None:
        return None
    row = dict(row)
    if isinstance(row.get("tdate"), date):
        row["tdate"] = row["tdate"].isoformat()
    return row


def month_bounds(month):
    """'2026-09' -> ('2026-09-01', '2026-10-01')"""
    y, m = map(int, month.split("-"))
    start = date(y, m, 1)
    end = date(y + (m == 12), 1 if m == 12 else m + 1, 1)
    return start.isoformat(), end.isoformat()


# ---------- budget ----------

def provision_budget(cx):
    return cx.execute("select oiko.provision_budget() as id").fetchone()["id"]


def get_budget(cx, bid):
    return cx.execute("select * from oiko.budgets where id = %s", (bid,)).fetchone()


def update_budget(cx, bid, name, currency, accent, opening_balance_cents, theme=None):
    if theme is not None and theme not in ("auto", "light", "dark"):
        raise ValueError("Μη έγκυρο θέμα")
    with cx.transaction():
        cx.execute(
            "update oiko.budgets set name = %s, currency = %s, accent = %s, opening_balance_cents = %s, "
            "theme = coalesce(%s, theme) where id = %s", (name, currency, accent, opening_balance_cents, theme, bid))


# ---------- categories ----------

def list_categories(cx, bid, kind=None, include_inactive=False):
    sql = "select * from oiko.categories where budget_id = %s"
    args = [bid]
    if kind:
        sql += " and kind = %s"
        args.append(kind)
    if not include_inactive:
        sql += " and active"
    sql += " order by kind desc, sort, name"
    return cx.execute(sql, args).fetchall()


def save_category(cx, bid, name, kind, budget_cents=0, color="#6b7280", icon="", active=True, cat_id=None):
    name = (name or "").strip()
    icon = (icon or "").strip()[:8]
    if not name:
        raise ValueError("Το όνομα κατηγορίας είναι υποχρεωτικό")
    if kind not in ("income", "expense"):
        raise ValueError("Λάθος τύπος κατηγορίας")
    try:
        with cx.transaction():
            if cat_id:
                cur = cx.execute(
                    "update oiko.categories set name = %s, kind = %s, budget_cents = %s, color = %s, icon = %s, "
                    "active = %s where id = %s and budget_id = %s",
                    (name, kind, budget_cents, color, icon, bool(active), uid(cat_id), bid))
                if cur.rowcount == 0:
                    raise ValueError("Άγνωστη κατηγορία")
                return uid(cat_id)
            sort = cx.execute("select coalesce(max(sort), 0) + 1 as s from oiko.categories where budget_id = %s",
                              (bid,)).fetchone()["s"]
            return cx.execute(
                "insert into oiko.categories (budget_id, name, kind, budget_cents, color, icon, sort, active) "
                "values (%s, %s, %s, %s, %s, %s, %s, %s) returning id",
                (bid, name, kind, budget_cents, color, icon, sort, bool(active))).fetchone()["id"]
    except errors.UniqueViolation:
        raise ValueError("Υπάρχει ήδη κατηγορία με αυτό το όνομα")
    except errors.CheckViolation:
        raise ValueError("Μη έγκυρα στοιχεία κατηγορίας")


def delete_category(cx, bid, cat_id, move_to=None):
    """Delete a category of this budget; its transactions/recurring must be moved to `move_to` (same budget)."""
    cat_id = uid(cat_id)
    with cx.transaction():
        if not cx.execute("select 1 from oiko.categories where id = %s and budget_id = %s", (cat_id, bid)).fetchone():
            raise ValueError("Άγνωστη κατηγορία")
        used = cx.execute(
            "select (select count(*) from oiko.transactions where category_id = %s and budget_id = %s) + "
            "(select count(*) from oiko.recurring where category_id = %s and budget_id = %s) as n",
            (cat_id, bid, cat_id, bid)).fetchone()["n"]
        if used:
            if not move_to:
                raise ValueError("Η κατηγορία έχει κινήσεις — διάλεξε πού να μεταφερθούν")
            move_to = uid(move_to)
            ok = cx.execute("select 1 from oiko.categories where id = %s and budget_id = %s",
                            (move_to, bid)).fetchone()
            if move_to == cat_id or not ok:
                raise ValueError("Μη έγκυρη κατηγορία μεταφοράς")
            cx.execute("update oiko.transactions set category_id = %s where category_id = %s and budget_id = %s",
                       (move_to, cat_id, bid))
            cx.execute("update oiko.recurring set category_id = %s where category_id = %s and budget_id = %s",
                       (move_to, cat_id, bid))
        cx.execute("delete from oiko.categories where id = %s and budget_id = %s", (cat_id, bid))


# ---------- transactions ----------

def add_transaction(cx, bid, tdate, category_id, amount_cents, note="", recurring_id=None):
    if amount_cents <= 0:
        raise ValueError("Το ποσό πρέπει να είναι μεγαλύτερο από 0")
    d = _date(tdate)
    cat = uid(category_id)
    try:
        with cx.transaction():
            return cx.execute(
                "insert into oiko.transactions (budget_id, tdate, category_id, amount_cents, note, recurring_id) "
                "values (%s, %s, %s, %s, %s, %s) returning id",
                (bid, d, cat, amount_cents, (note or "").strip()[:200], recurring_id)).fetchone()["id"]
    except errors.ForeignKeyViolation:
        raise ValueError("Άγνωστη κατηγορία")


def update_transaction(cx, bid, tx_id, tdate, category_id, amount_cents, note=""):
    """Returns False if the transaction is not in this budget."""
    if amount_cents <= 0:
        raise ValueError("Το ποσό πρέπει να είναι μεγαλύτερο από 0")
    d = _date(tdate)
    try:
        with cx.transaction():
            cur = cx.execute(
                "update oiko.transactions set tdate = %s, category_id = %s, amount_cents = %s, note = %s "
                "where id = %s and budget_id = %s",
                (d, uid(category_id), amount_cents, (note or "").strip()[:200], uid(tx_id), bid))
            return cur.rowcount == 1
    except errors.ForeignKeyViolation:
        raise ValueError("Άγνωστη κατηγορία")


def delete_transaction(cx, bid, tx_id):
    with cx.transaction():
        return cx.execute("delete from oiko.transactions where id = %s and budget_id = %s",
                          (uid(tx_id), bid)).rowcount == 1


def get_transaction(cx, bid, tx_id):
    return _iso(cx.execute("select * from oiko.transactions where id = %s and budget_id = %s",
                           (uid(tx_id), bid)).fetchone())


def list_transactions(cx, bid, month=None, kind=None, category_id=None, q=None, limit=None):
    sql = ("select t.*, c.name as cat_name, c.kind as kind, c.color as color, c.icon as icon "
           "from oiko.transactions t join oiko.categories c on c.id = t.category_id and c.budget_id = t.budget_id "
           "where t.budget_id = %s")
    args = [bid]
    if month:
        start, end = month_bounds(month)
        sql += " and t.tdate >= %s and t.tdate < %s"
        args += [start, end]
    if kind:
        sql += " and c.kind = %s"
        args.append(kind)
    if category_id:
        sql += " and t.category_id = %s"
        args.append(uid(category_id))
    if q:
        sql += " and (t.note ilike %s or c.name ilike %s)"
        args += [f"%{q}%", f"%{q}%"]
    sql += " order by t.tdate desc, t.created_at desc"
    if limit:
        sql += " limit %s"
        args.append(int(limit))
    return [_iso(r) for r in cx.execute(sql, args).fetchall()]


def month_summary(cx, bid, month):
    start, end = month_bounds(month)
    rows = cx.execute(
        "select c.id, c.name, c.kind, c.color, c.icon, c.budget_cents, c.active, "
        "coalesce(sum(t.amount_cents), 0)::bigint as actual "
        "from oiko.categories c left join oiko.transactions t "
        "on t.category_id = c.id and t.budget_id = c.budget_id and t.tdate >= %s and t.tdate < %s "
        "where c.budget_id = %s group by c.id order by c.kind desc, c.sort, c.name",
        (start, end, bid)).fetchall()
    cats = [dict(r) for r in rows if r["active"] or r["actual"]]
    income = sum(c["actual"] for c in cats if c["kind"] == "income")
    expense = sum(c["actual"] for c in cats if c["kind"] == "expense")
    budget_income = sum(c["budget_cents"] for c in cats if c["kind"] == "income")
    budget_expense = sum(c["budget_cents"] for c in cats if c["kind"] == "expense")
    return {"month": month, "income": income, "expense": expense, "net": income - expense,
            "budget_income": budget_income, "budget_expense": budget_expense,
            "budget_net": budget_income - budget_expense, "categories": cats}


def balance_until(cx, bid, end_exclusive):
    opening = get_budget(cx, bid)["opening_balance_cents"]
    row = cx.execute(
        "select coalesce(sum(case when c.kind = 'income' then t.amount_cents else -t.amount_cents end), 0)::bigint as s "
        "from oiko.transactions t join oiko.categories c on c.id = t.category_id and c.budget_id = t.budget_id "
        "where t.budget_id = %s and t.tdate < %s", (bid, end_exclusive)).fetchone()
    return opening + row["s"]


def last_months(cx, bid, month, n=6):
    y, m = map(int, month.split("-"))
    out = []
    for _ in range(n):
        key = f"{y:04d}-{m:02d}"
        s = month_summary(cx, bid, key)
        out.append({"month": key, "income": s["income"], "expense": s["expense"], "net": s["net"]})
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return list(reversed(out))


# ---------- recurring ----------

def list_recurring(cx, bid):
    return cx.execute(
        "select r.*, c.name as cat_name, c.kind as kind from oiko.recurring r "
        "join oiko.categories c on c.id = r.category_id and c.budget_id = r.budget_id "
        "where r.budget_id = %s order by c.kind desc, r.day, r.name", (bid,)).fetchall()


def save_recurring(cx, bid, name, category_id, amount_cents, day, active=True, rec_id=None):
    if not (name or "").strip():
        raise ValueError("Το όνομα είναι υποχρεωτικό")
    if amount_cents <= 0:
        raise ValueError("Το ποσό πρέπει να είναι μεγαλύτερο από 0")
    day = min(max(int(day), 1), 31)
    try:
        with cx.transaction():
            if rec_id:
                cur = cx.execute(
                    "update oiko.recurring set name = %s, category_id = %s, amount_cents = %s, day = %s, active = %s "
                    "where id = %s and budget_id = %s",
                    (name.strip(), uid(category_id), amount_cents, day, bool(active), uid(rec_id), bid))
                if cur.rowcount == 0:
                    raise ValueError("Άγνωστο πάγιο")
                return uid(rec_id)
            return cx.execute(
                "insert into oiko.recurring (budget_id, name, category_id, amount_cents, day, active) "
                "values (%s, %s, %s, %s, %s, %s) returning id",
                (bid, name.strip(), uid(category_id), amount_cents, day, bool(active))).fetchone()["id"]
    except errors.ForeignKeyViolation:
        raise ValueError("Άγνωστη κατηγορία")


def due_date(month, day):
    """The date a recurring item falls on in `month`: its day, or the month's last day if shorter."""
    y, m = map(int, month.split("-"))
    return date(y, m, min(day, calendar.monthrange(y, m)[1]))


def make_recurring_from_tx(cx, bid, tx_id):
    """Turn an existing transaction into a monthly recurring item (same name, amount, category, day of month).
    The transaction is linked to it, so this month counts as already paid."""
    tx = get_transaction(cx, bid, tx_id)
    if not tx:
        raise ValueError("Άγνωστη κίνηση")
    if tx["recurring_id"]:
        raise ValueError("Η κίνηση είναι ήδη πάγιο")
    name = (tx["note"] or "").strip()
    if not name:
        name = cx.execute("select name from oiko.categories where id = %s and budget_id = %s",
                          (tx["category_id"], bid)).fetchone()["name"]
    with cx.transaction():
        rid = save_recurring(cx, bid, name[:60], tx["category_id"], tx["amount_cents"],
                             int(tx["tdate"][8:10]))
        cx.execute("update oiko.transactions set recurring_id = %s where id = %s and budget_id = %s",
                   (rid, uid(tx_id), bid))
    return rid


def delete_recurring(cx, bid, rec_id):
    with cx.transaction():
        return cx.execute("delete from oiko.recurring where id = %s and budget_id = %s",
                          (uid(rec_id), bid)).rowcount == 1


def recurring_posted(cx, bid, month):
    """{recurring_id: 'YYYY-MM-DD'} for items already posted in `month`."""
    start, end = month_bounds(month)
    rows = cx.execute(
        "select recurring_id, min(tdate) as d from oiko.transactions where budget_id = %s and recurring_id is not null "
        "and tdate >= %s and tdate < %s group by recurring_id", (bid, start, end)).fetchall()
    return {r["recurring_id"]: r["d"].isoformat() for r in rows}


def pending_recurring(cx, bid, month):
    start, end = month_bounds(month)
    rows = cx.execute(
        "select r.*, c.name as cat_name, c.kind as kind from oiko.recurring r "
        "join oiko.categories c on c.id = r.category_id and c.budget_id = r.budget_id "
        "where r.budget_id = %s and r.active and not exists (select 1 from oiko.transactions t "
        "where t.recurring_id = r.id and t.budget_id = r.budget_id and t.tdate >= %s and t.tdate < %s) "
        "order by r.day", (bid, start, end)).fetchall()
    return [dict(r, due_day=due_date(month, r["day"]).day) for r in rows]


def post_recurring(cx, bid, month, ids=None):
    """Post pending recurring items for `month` (all, or only `ids`). Idempotent. Returns count."""
    y, m = map(int, month.split("-"))
    wanted = {uid(i) for i in ids} if ids is not None else None
    n = 0
    with cx.transaction():
        for r in pending_recurring(cx, bid, month):
            if wanted is not None and r["id"] not in wanted:
                continue
            cx.execute(
                "insert into oiko.transactions (budget_id, tdate, category_id, amount_cents, note, recurring_id) "
                "values (%s, %s, %s, %s, %s, %s)",
                (bid, due_date(month, r["day"]), r["category_id"], r["amount_cents"], r["name"], r["id"]))
            n += 1
    return n


# ---------- scan helpers ----------

def find_duplicate(cx, bid, tdate, amount_cents, kind, note="", exclude=()):
    """Existing transaction that is the SAME one: same shop name, same date, same amount and direction.
    Anything less (e.g. same amount on the same day at another shop) is a different transaction.
    `exclude` = ids already matched to earlier rows of the same scan."""
    from scan import same_merchant
    if not (note or "").strip():
        return None
    rows = cx.execute(
        "select t.*, c.name as cat_name from oiko.transactions t "
        "join oiko.categories c on c.id = t.category_id and c.budget_id = t.budget_id "
        "where t.budget_id = %s and t.amount_cents = %s and c.kind = %s and t.tdate = %s "
        "order by t.created_at",
        (bid, amount_cents, kind, _date(tdate))).fetchall()
    for r in rows:
        if r["id"] not in exclude and same_merchant(r["note"], note):
            return _iso(r)
    return None


def learned_categories(cx, bid, limit=5000):
    """{shop fingerprint: category_id} from the user's own past choices, most recent first.
    Transactions left in the catch-all categories teach nothing."""
    from scan import FALLBACK_NAMES, merchant_key
    rows = cx.execute(
        "select t.note, t.category_id from oiko.transactions t "
        "join oiko.categories c on c.id = t.category_id and c.budget_id = t.budget_id "
        "where t.budget_id = %s and t.note <> '' and c.active and not (c.name = any(%s)) "
        "order by t.tdate desc, t.created_at desc limit %s",
        (bid, list(FALLBACK_NAMES), limit)).fetchall()
    learned = {}
    for r in rows:
        key = merchant_key(r["note"])
        if key and key not in learned:
            learned[key] = r["category_id"]
    return learned


def scans_used(cx, user_id, month):
    row = cx.execute("select count from oiko.scan_usage where user_id = %s and month = %s",
                     (user_id, month)).fetchone()
    return row["count"] if row else 0


def add_scans(cx, user_id, month, n):
    with cx.transaction():
        cx.execute(
            "insert into oiko.scan_usage (user_id, month, count) values (%s, %s, %s) "
            "on conflict (user_id, month) do update set count = oiko.scan_usage.count + excluded.count",
            (user_id, month, n))
