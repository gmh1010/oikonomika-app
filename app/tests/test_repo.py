import pytest

import repo
from conftest import cat_id


@pytest.fixture
def me(make_user, scope):
    """(cx, bid) for a fresh user, inside one transaction."""
    u = make_user("me")
    with scope(u) as ctx:
        yield ctx


def test_december_bounds():
    assert repo.month_bounds("2026-12") == ("2026-12-01", "2027-01-01")


def test_summary_and_balance(me):
    cx, bid = me
    b = repo.get_budget(cx, bid)
    repo.update_budget(cx, bid, b["name"], b["currency"], b["accent"], -5000)
    coffee = cat_id(cx, bid, "Καφέδες")
    repo.save_category(cx, bid, "Καφέδες", "expense", 3000, "#a16207", "☕", True, coffee)
    repo.add_transaction(cx, bid, "2026-09-01", cat_id(cx, bid, "Μισθός"), 160000)
    repo.add_transaction(cx, bid, "2026-09-10", coffee, 4550, "freddo")
    repo.add_transaction(cx, bid, "2026-10-02", coffee, 300)
    s = repo.month_summary(cx, bid, "2026-09")
    assert (s["income"], s["expense"], s["net"]) == (160000, 4550, 155450)
    c = next(c for c in s["categories"] if c["name"] == "Καφέδες")
    assert c["actual"] == 4550 and c["budget_cents"] == 3000
    assert repo.balance_until(cx, bid, "2026-10-01") == -5000 + 155450
    assert repo.balance_until(cx, bid, "2026-11-01") == -5000 + 155450 - 300


def _two_recurring(cx, bid):
    r1 = repo.save_recurring(cx, bid, "Μισθός", cat_id(cx, bid, "Μισθός"), 160000, 1)
    r2 = repo.save_recurring(cx, bid, "Ενοίκιο", cat_id(cx, bid, "Ενοίκιο"), 30000, 5)
    return r1, r2


def test_recurring_is_idempotent(me):
    cx, bid = me
    _two_recurring(cx, bid)
    assert len(repo.pending_recurring(cx, bid, "2026-09")) == 2
    assert repo.post_recurring(cx, bid, "2026-09") == 2
    assert repo.post_recurring(cx, bid, "2026-09") == 0
    s = repo.month_summary(cx, bid, "2026-09")
    assert (s["income"], s["expense"]) == (160000, 30000)
    assert len(repo.pending_recurring(cx, bid, "2026-10")) == 2


def test_recurring_selected_only(me):
    cx, bid = me
    r1, _ = _two_recurring(cx, bid)
    assert repo.post_recurring(cx, bid, "2026-09", [str(r1)]) == 1
    assert len(repo.pending_recurring(cx, bid, "2026-09")) == 1


def test_delete_recurring_keeps_posted_transactions(me):
    cx, bid = me
    r1, _ = _two_recurring(cx, bid)
    repo.post_recurring(cx, bid, "2026-09", [r1])
    assert repo.delete_recurring(cx, bid, r1)
    tx = repo.list_transactions(cx, bid, month="2026-09")
    assert len(tx) == 1 and tx[0]["recurring_id"] is None


def test_delete_category_requires_move(me):
    cx, bid = me
    coffee, other = cat_id(cx, bid, "Καφέδες"), cat_id(cx, bid, "Άλλα")
    repo.add_transaction(cx, bid, "2026-09-10", coffee, 300)
    with pytest.raises(ValueError):
        repo.delete_category(cx, bid, coffee)
    with pytest.raises(ValueError):
        repo.delete_category(cx, bid, coffee, move_to=coffee)
    repo.delete_category(cx, bid, coffee, move_to=other)
    assert repo.month_summary(cx, bid, "2026-09")["expense"] == 300
    assert repo.list_transactions(cx, bid)[0]["category_id"] == other


def test_delete_unused_category(me):
    cx, bid = me
    new = repo.save_category(cx, bid, "Γυμναστήριο", "expense", 3000, "#123456", "🏋️")
    repo.delete_category(cx, bid, new)
    assert "Γυμναστήριο" not in {c["name"] for c in repo.list_categories(cx, bid, include_inactive=True)}


def test_duplicate_category_name(me):
    cx, bid = me
    with pytest.raises(ValueError, match="Υπάρχει ήδη"):
        repo.save_category(cx, bid, "Καφέδες", "expense")
    # the savepoint kept the request usable
    assert repo.list_categories(cx, bid)


def test_inactive_category_still_counts_its_money(me):
    cx, bid = me
    coffee = cat_id(cx, bid, "Καφέδες")
    repo.add_transaction(cx, bid, "2026-09-10", coffee, 300)
    repo.save_category(cx, bid, "Καφέδες", "expense", 3000, "#a16207", "☕", False, coffee)
    assert repo.month_summary(cx, bid, "2026-09")["expense"] == 300


def test_add_rejects_bad_input(me):
    cx, bid = me
    other = cat_id(cx, bid, "Άλλα")
    for args in [("2026-09-10", other, 0), ("not-a-date", other, 100), ("2026-09-10", "garbage", 100),
                 ("2026-09-10", "00000000-0000-0000-0000-000000000000", 100)]:
        with pytest.raises(ValueError):
            repo.add_transaction(cx, bid, *args)
    assert repo.list_transactions(cx, bid) == []


def test_update_and_delete_return_false_for_unknown_ids(me):
    cx, bid = me
    ghost = "11111111-1111-1111-1111-111111111111"
    other = cat_id(cx, bid, "Άλλα")
    assert repo.update_transaction(cx, bid, ghost, "2026-09-10", other, 100) is False
    assert repo.delete_transaction(cx, bid, ghost) is False
    assert repo.delete_recurring(cx, bid, ghost) is False
    assert repo.get_transaction(cx, bid, ghost) is None


def test_duplicate_needs_same_name_date_and_amount(me):
    cx, bid = me
    bills, fuel = cat_id(cx, bid, "Λογαριασμοί (ρεύμα/νερό/τηλέφωνο)"), cat_id(cx, bid, "Μετακινήσεις / καύσιμα")
    cosmote = repo.add_transaction(cx, bid, "2026-09-22", bills, 2500, "Cosmote")
    shell = repo.add_transaction(cx, bid, "2026-09-22", fuel, 2500, "Shell Νίκαια")
    assert repo.find_duplicate(cx, bid, "2026-09-22", 2500, "expense", "SHELL ΝΙΚΑΙΑ 12")["id"] == shell
    assert repo.find_duplicate(cx, bid, "2026-09-22", 2500, "expense", "cosmote")["id"] == cosmote
    assert repo.find_duplicate(cx, bid, "2026-09-22", 2500, "expense", "Wolt") is None          # other name
    assert repo.find_duplicate(cx, bid, "2026-09-21", 2500, "expense", "Shell Νίκαια") is None  # other date
    assert repo.find_duplicate(cx, bid, "2026-09-22", 2600, "expense", "Shell Νίκαια") is None  # other amount
    assert repo.find_duplicate(cx, bid, "2026-09-22", 2500, "income", "Shell Νίκαια") is None   # other direction
    assert repo.find_duplicate(cx, bid, "2026-09-22", 2500, "expense", "") is None              # no name: unique
    assert repo.find_duplicate(cx, bid, "2026-09-22", 2500, "expense", "Shell Νίκαια", exclude={shell}) is None


def test_scan_usage_counter(make_user, scope):
    u = make_user("s")
    with scope(u) as (cx, bid):
        assert repo.scans_used(cx, u, "2026-09") == 0
        repo.add_scans(cx, u, "2026-09", 2)
        repo.add_scans(cx, u, "2026-09", 3)
        assert repo.scans_used(cx, u, "2026-09") == 5
        assert repo.scans_used(cx, u, "2026-10") == 0


def test_recurring_day_up_to_31_falls_on_month_end(me):
    cx, bid = me
    rent = cat_id(cx, bid, "Ενοίκιο")
    r31 = repo.save_recurring(cx, bid, "Τέλος μήνα", rent, 1000, 31)
    assert repo.save_recurring(cx, bid, "Clamp", rent, 1000, 45) and \
        {r["name"]: r["day"] for r in repo.list_recurring(cx, bid)}["Clamp"] == 31
    assert repo.post_recurring(cx, bid, "2026-02", [str(r31)]) == 1
    assert repo.post_recurring(cx, bid, "2026-04", [str(r31)]) == 1
    days = sorted(t["tdate"] for t in repo.list_transactions(cx, bid) if t["note"] == "Τέλος μήνα")
    assert [str(d) for d in days] == ["2026-02-28", "2026-04-30"]
    assert [r["due_day"] for r in repo.pending_recurring(cx, bid, "2026-02") if r["name"] == "Clamp"] == [28]


def test_make_recurring_from_transaction(me):
    cx, bid = me
    rent = cat_id(cx, bid, "Ενοίκιο")
    tx = repo.add_transaction(cx, bid, "2026-09-03", rent, 30000, "Μεταφορά προς ΖΗΚΟΥΛΗΣ ΑΝΑΣΤΑΣΙΟΣ")
    rid = repo.make_recurring_from_tx(cx, bid, tx)
    rec = {r["id"]: r for r in repo.list_recurring(cx, bid)}[rid]
    assert (rec["name"], rec["amount_cents"], rec["day"], rec["category_id"]) == \
        ("Μεταφορά προς ΖΗΚΟΥΛΗΣ ΑΝΑΣΤΑΣΙΟΣ", 30000, 3, rent)
    assert repo.get_transaction(cx, bid, tx)["recurring_id"] == rid
    assert rid not in {r["id"] for r in repo.pending_recurring(cx, bid, "2026-09")}   # this month already paid
    assert rid in {r["id"] for r in repo.pending_recurring(cx, bid, "2026-10")}
    with pytest.raises(ValueError, match="ήδη πάγιο"):
        repo.make_recurring_from_tx(cx, bid, tx)
