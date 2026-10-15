import io
from datetime import date

import repo
import scan
from conftest import cat_id

FAKE_RESULT = {"document_type": "bank_statement", "rows": [
    {"tdate": "2026-09-20", "amount": 48.9, "kind": "expense", "description": "Lidl", "category": "Σούπερ μάρκετ"},
    {"tdate": "2026-09-01", "amount": 1600, "kind": "income", "description": "ZITA", "category": "Μισθός"},
    {"tdate": "2026-09-18", "amount": 7.5, "kind": "expense", "description": "Κάτι", "category": "Ανύπαρκτη"},
    {"tdate": "bad", "amount": -3.2, "kind": "weird", "description": "x", "category": ""},
    {"tdate": "2026-09-18", "amount": 0, "kind": "expense", "description": "zero", "category": ""},
    {"tdate": "2026-09-18", "amount": "n/a", "kind": "expense", "description": "junk", "category": ""},
]}


def _png(size=(10, 10)):
    from PIL import Image
    b = io.BytesIO()
    Image.new("RGB", size, "white").save(b, "PNG")
    return b.getvalue()


def test_clean_rows(make_user, scope):
    with scope(make_user("s")) as (cx, bid):
        cats = [dict(c) for c in repo.list_categories(cx, bid)]
        rows = scan.clean_rows(FAKE_RESULT, cats, "a.jpg")
        assert len(rows) == 4
        lidl, salary, unknown, bad = rows
        assert lidl["category_id"] == cat_id(cx, bid, "Σούπερ μάρκετ") and lidl["guessed"]
        assert lidl["amount_cents"] == 4890
        assert salary["kind"] == "income" and salary["category_id"] == cat_id(cx, bid, "Μισθός")
        assert unknown["category_id"] == cat_id(cx, bid, "Άλλα") and not unknown["guessed"]
        assert bad["amount_cents"] == 320 and bad["kind"] == "expense"


def test_match_category_tolerant(make_user, scope):
    with scope(make_user("s")) as (cx, bid):
        cats = [dict(c) for c in repo.list_categories(cx, bid)]
        bills = cat_id(cx, bid, "Λογαριασμοί (ρεύμα/νερό/τηλέφωνο)")
        assert scan.match_category("Λογαριασμοί", "expense", cats) == bills
        assert scan.match_category("λογαριασμοι (ρευμα)", "expense", cats) == bills
        assert scan.match_category("Υγεία", "expense", cats) == cat_id(cx, bid, "Υγεία / φαρμακείο")
        assert scan.match_category("Λογαριασμοί", "income", cats) is None
        assert scan.match_category("", "expense", cats) is None


def test_scan_review_and_import(make_user, web, scope):
    u = make_user("s")
    c = web(u)
    calls = []
    c.application.config["EXTRACTOR"] = lambda data, mime, exp, inc: calls.append((mime, exp, inc)) or FAKE_RESULT
    with scope(u) as (cx, bid):
        sm, sal = cat_id(cx, bid, "Σούπερ μάρκετ"), cat_id(cx, bid, "Μισθός")
        repo.add_transaction(cx, bid, "2026-09-20", sm, 4890, "LIDL")               # same name/date/amount
        repo.add_transaction(cx, bid, "2026-09-01", sal, 160000, "Bonus")           # same date/amount, other name
    r = c.post("/scan", data={"files": (io.BytesIO(_png()), "bank.png", "image/png")},
               content_type="multipart/form-data")
    page = r.get_data(as_text=True)
    assert r.status_code == 200 and calls[0][0] == "image/jpeg"      # re-encoded, metadata-free
    assert "Σούπερ μάρκετ" in calls[0][1] and "Μισθός" in calls[0][2]
    assert page.count("υπάρχει ήδη:") == 1 and page.count('class="rrow') == 4   # Bonus is not ZITA
    assert page.count('value="1" checked') == 3
    r = c.post("/scan/import", data={
        "count": 3,
        "r0_use": "1", "r0_date": "2026-09-01", "r0_amount": "1.600,00", "r0_cat": sal, "r0_note": "ZITA",
        "r1_date": "2026-09-20", "r1_amount": "48,90", "r1_cat": sm, "r1_note": "not ticked",
        "r2_use": "1", "r2_date": "2026-09-18", "r2_amount": "abc", "r2_cat": sm, "r2_note": "bad",
    }, follow_redirects=True)
    assert "Καταχωρήθηκαν 1 κινήσεις" in r.get_data(as_text=True)
    with scope(u) as (cx, bid):
        s = repo.month_summary(cx, bid, "2026-09")
        assert s["income"] == 320000 and s["expense"] == 4890
        assert repo.scans_used(cx, u, date.today().strftime("%Y-%m")) == 1


def test_scan_quota(make_user, web, scope):
    u = make_user("q")
    c = web(u)
    calls = []
    c.application.config["EXTRACTOR"] = lambda *a: calls.append(1) or FAKE_RESULT
    month = date.today().strftime("%Y-%m")
    with scope(u) as (cx, bid):
        repo.add_scans(cx, u, month, 29)
    files = [(io.BytesIO(_png()), f"f{i}.png", "image/png") for i in range(3)]
    page = c.post("/scan", data={"files": files}, content_type="multipart/form-data").get_data(as_text=True)
    assert len(calls) == 1 and "όριο" in page
    page = c.post("/scan", data={"files": [(io.BytesIO(_png()), "x.png", "image/png")]},
                  content_type="multipart/form-data", follow_redirects=True).get_data(as_text=True)
    assert len(calls) == 1 and "όριο" in page


def _pdf(pages):
    from pypdf import PdfWriter
    w = PdfWriter()
    for _ in range(pages):
        w.add_blank_page(width=200, height=200)
    b = io.BytesIO()
    w.write(b)
    return b.getvalue()


def test_long_bank_statement_pdf(make_user, web, scope):
    u = make_user("p")
    c = web(u)
    calls = []

    def fake(data, mime, exp, inc):
        calls.append(mime)
        n = len(calls)
        return {"document_type": "bank_statement", "rows": [
            {"tdate": f"2026-09-{n:02d}", "amount": n, "kind": "expense", "description": f"shop{n}", "category": ""}]}
    c.application.config["EXTRACTOR"] = fake
    page = c.post("/scan", data={"files": (io.BytesIO(_pdf(32)), "statement.pdf", "application/pdf")},
                  content_type="multipart/form-data").get_data(as_text=True)
    assert calls == ["application/pdf"] * 7                        # 32 pages -> 7 chunks of <= 5 pages
    assert page.count('class="rrow') == 7                           # rows from every chunk merged
    month = date.today().strftime("%Y-%m")
    with scope(u) as (cx, bid):
        assert repo.scans_used(cx, u, month) == 4                   # 1 scan per started 10 pages
        repo.add_scans(cx, u, month, 23)                            # 27 used -> 3 left, the PDF needs 4
    calls.clear()
    page = c.post("/scan", data={"files": (io.BytesIO(_pdf(32)), "statement.pdf", "application/pdf")},
                  content_type="multipart/form-data").get_data(as_text=True)
    assert calls == [] and "χρειάζεται 4 σαρώσεις" in page and "σου μένουν 3" in page


def test_same_line_twice_in_one_scan_is_flagged(make_user, web):
    c = web(make_user("d"))
    line = {"tdate": "2026-09-14", "amount": 3.7, "kind": "expense", "description": "Periptero", "category": ""}
    c.application.config["EXTRACTOR"] = lambda *a: {"document_type": "bank_statement", "rows": [
        dict(line), dict(line), dict(line, amount=4.2)]}
    page = c.post("/scan", data={"files": (io.BytesIO(_png()), "b.png", "image/png")},
                  content_type="multipart/form-data").get_data(as_text=True)
    assert page.count('class="rrow') == 3 and page.count('value="1" checked') == 2
    assert "2η φορά σε αυτή τη σάρωση" in page
    assert "1 διπλή" in page and "ίδιο όνομα, ημερομηνία και ποσό" in page


def test_merchant_key():
    assert scan.merchant_key("Wolt 1234") == scan.merchant_key("WOLT") == "wolt"
    assert scan.merchant_key("ΣΚΛΑΒΕΝΙΤΗΣ #0452") == scan.merchant_key("Σκλαβενίτης") == "σκλαβενιτης"
    assert scan.merchant_key("D. ZIKOULIS A.P MITRAK ATHINA") == "d zikoulis a p mitrak athina"
    assert scan.merchant_key("123 45") == "" and scan.merchant_key("") == ""


def test_scan_remembers_my_category_choice(make_user, web, scope):
    u = make_user("m")
    c = web(u)
    with scope(u) as (cx, bid):
        fuel, other = cat_id(cx, bid, "Μετακινήσεις / καύσιμα"), cat_id(cx, bid, "Άλλα")
        coffee = cat_id(cx, bid, "Καφέδες")
        repo.add_transaction(cx, bid, "2026-08-02", other, 8200, "ERMIS AEMEE TAURUS")   # first time: left in Άλλα
        repo.add_transaction(cx, bid, "2026-08-20", fuel, 8200, "ERMIS AEMEE TAURUS")    # later corrected -> learn
        repo.add_transaction(cx, bid, "2026-08-21", other, 500, "Periptero 7")           # Άλλα alone: nothing to learn
        repo.add_transaction(cx, bid, "2026-08-22", coffee, 450, "CAFE GIANNIS LARISA")
        learned = repo.learned_categories(cx, bid)
        assert learned[scan.merchant_key("ERMIS AEMEE TAURUS")] == fuel
        assert scan.merchant_key("Periptero 7") not in learned
    c.application.config["EXTRACTOR"] = lambda *a: {"document_type": "bank_statement", "rows": [
        {"tdate": "2026-09-09", "amount": 82, "kind": "expense", "description": "Ermis Aemee Taurus", "category": "Άλλα"},
        {"tdate": "2026-09-14", "amount": 9, "kind": "expense", "description": "CAFE GIANNIS LARISA 22",
         "category": ""},
        {"tdate": "2026-09-15", "amount": 3, "kind": "expense", "description": "Unknown shop", "category": ""}]}
    page = c.post("/scan", data={"files": (io.BytesIO(_png()), "b.png", "image/png")},
                  content_type="multipart/form-data").get_data(as_text=True)
    assert f'<option value="{fuel}" selected' in page and f'<option value="{coffee}" selected' in page
    assert page.count("όπως την προηγούμενη φορά") == 2
    assert page.count("κατηγορία: έλεγξέ τη") == 1                      # only the truly unknown shop


def test_bank_spreadsheet_upload(make_user, web, scope):
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.append(["Category", "Transaction Narrative", "Posted date", "Amount", "Currency"])
    ws.append(["Services", "WOLT ATHENS", "03/09/2026", -12.4, "EUR"])
    b = io.BytesIO()
    wb.save(b)
    u = make_user("x")
    c = web(u)
    seen = []

    def fake(data, mime, exp, inc):
        seen.append((mime, data.decode("utf-8")))
        return {"document_type": "bank_statement", "rows": [
            {"tdate": "2026-09-03", "amount": 12.4, "kind": "expense", "description": "Wolt", "category": ""}]}
    c.application.config["EXTRACTOR"] = fake
    page = c.post("/scan", data={"files": (io.BytesIO(b.getvalue()), "Global Transaction List.xlsx",
                                           "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
                  content_type="multipart/form-data").get_data(as_text=True)
    assert seen and seen[0][0] == "text/csv" and "WOLT ATHENS" in seen[0][1]
    assert page.count('class="rrow') == 1
    with scope(u) as (cx, bid):
        assert repo.scans_used(cx, u, date.today().strftime("%Y-%m")) == 1


def test_transfers_between_own_accounts_are_skipped(make_user, web, scope):
    u = make_user("t")
    c = web(u)
    c.application.config["EXTRACTOR"] = lambda *a: {"document_type": "bank_statement", "rows": [
        {"tdate": "2026-09-02", "amount": 50, "kind": "transfer", "description": "Apple Pay top-up", "category": ""},
        {"tdate": "2026-09-02", "amount": 5, "kind": "transfer", "description": "To pocket Savings", "category": ""},
        {"tdate": "2026-09-03", "amount": 12.4, "kind": "expense", "description": "Wolt", "category": ""}]}
    with scope(u) as (cx, bid):
        assert [r["note"] for r in scan.clean_rows(c.application.config["EXTRACTOR"](), [
            dict(x) for x in repo.list_categories(cx, bid)])] == ["Wolt"]
    page = c.post("/scan", data={"files": (io.BytesIO(_png()), "rev.png", "image/png")},
                  content_type="multipart/form-data").get_data(as_text=True)
    assert page.count('class="rrow') == 1 and "2 μεταφορές" in page


def test_big_import_is_accepted(make_user, web, scope):
    u = make_user("b")
    c = web(u)
    with scope(u) as (cx, bid):
        sm = cat_id(cx, bid, "Σούπερ μάρκετ")
    form = {"count": 700}
    for i in range(700):
        form.update({f"r{i}_use": "1", f"r{i}_date": "2026-08-15", f"r{i}_amount": "1,00", f"r{i}_cat": sm,
                     f"r{i}_note": f"row {i}"})
    r = c.post("/scan/import", data=form, follow_redirects=True)
    assert "Καταχωρήθηκαν 700 κινήσεις" in r.get_data(as_text=True)


def test_scan_rejects_bad_files_and_errors(make_user, web):
    c = web(make_user("s"))

    def boom(*a):
        raise RuntimeError("Σφάλμα Gemini: quota")
    c.application.config["EXTRACTOR"] = boom
    r = c.post("/scan", data={"files": [(io.BytesIO(b"hi"), "x.bin", "application/octet-stream"),
                                        (io.BytesIO(_png()), "a.png", "image/png")]},
               content_type="multipart/form-data")
    page = r.get_data(as_text=True)
    assert "δεν είναι εικόνα" in page and "quota" in page
    r = c.post("/scan", data={}, content_type="multipart/form-data", follow_redirects=True)
    assert "Διάλεξε τουλάχιστον" in r.get_data(as_text=True)
