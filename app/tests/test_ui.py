"""Redesign (Stitch 'Calm Finance'): theme, navigation, status chips, self-hosted assets."""
import os
import re
from datetime import date

import pytest

import repo
import ui
from conftest import cat_id

STATIC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")


def test_theme_setting_sets_html_class(make_user, web):
    c = web(make_user("t"))
    assert '<html lang="el" class="">' in c.get("/").get_data(as_text=True)          # auto = follow the device
    for theme in ("dark", "light"):
        c.post("/settings", data={"title": "X", "currency": "€", "accent": "#2563eb", "opening_balance": "0",
                                  "theme": theme})
        assert f'<html lang="el" class="{theme}">' in c.get("/").get_data(as_text=True)
    c.post("/settings", data={"title": "X", "currency": "€", "accent": "#123abc", "opening_balance": "0",
                              "theme": "evil<script>"})
    page = c.get("/").get_data(as_text=True)
    assert '<html lang="el" class="">' in page and "--accent: 18 58 188;" in page


def test_more_page_and_nav(make_user, web):
    c = web(make_user("m"))
    page = c.get("/more").get_data(as_text=True)
    for label in ("Κατηγορίες", "Πάγια", "Ρυθμίσεις", "Λογαριασμός"):
        assert label in page
    assert 'aria-label="Κύρια πλοήγηση"' in page and "data-open-sheet" in page and 'id="add-sheet"' in page


def test_recurring_status_chips(make_user, web, scope):
    u = make_user("r")
    with scope(u) as (cx, bid):
        r1 = repo.save_recurring(cx, bid, "Ενοίκιο", cat_id(cx, bid, "Ενοίκιο"), 30000, 1)
        repo.save_recurring(cx, bid, "Netflix", cat_id(cx, bid, "Συνδρομές"), 999, 5)
        repo.post_recurring(cx, bid, date.today().strftime("%Y-%m"), [r1])
        assert list(repo.recurring_posted(cx, bid, date.today().strftime("%Y-%m"))) == [r1]
    page = web(u).get("/recurring").get_data(as_text=True)
    assert page.count("Περάστηκε 01/") == 1 and page.count("Εκκρεμεί") == 1


def test_scan_quota_meter(make_user, web, scope):
    u = make_user("q")
    with scope(u) as (cx, bid):
        repo.add_scans(cx, u, date.today().strftime("%Y-%m"), 7)
    assert re.search(r">7 <span[^>]*>/ 30<", web(u).get("/scan").get_data(as_text=True))


def test_transactions_grouped_by_day(make_user, web, scope):
    u = make_user("g")
    with scope(u) as (cx, bid):
        coffee = cat_id(cx, bid, "Καφέδες")
        repo.add_transaction(cx, bid, "2026-09-10", coffee, 300, "a")
        repo.add_transaction(cx, bid, "2026-09-10", coffee, 200, "b")
        repo.add_transaction(cx, bid, "2026-09-12", coffee, 100, "c")
    page = web(u).get("/tx?m=2026-09").get_data(as_text=True)
    assert page.index("12/09/2026") < page.index("10/09/2026")                       # newest day first
    assert "Σύνολο: − 5,00" in page


def test_icon_helper():
    svg = ui.icon("plus", "h-5 w-5")
    assert svg.startswith("<svg") and 'class="h-5 w-5"' in svg and 'aria-hidden="true"' in svg
    with pytest.raises(ValueError):
        ui.icon("../../etc/passwd")
    with pytest.raises(ValueError):
        ui.icon("plus", 'x" onload="alert(1)')
    assert ui.hex_to_rgb("#2563eb") == "37 99 235" and ui.hex_to_rgb("nope") == "37 99 235"


def test_every_icon_used_in_templates_exists():
    root = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    used = set()
    for dirpath, _, files in os.walk(root):
        for f in files:
            used |= set(re.findall(r"icon\('([a-z0-9-]+)'", open(os.path.join(dirpath, f), encoding="utf-8").read()))
    used |= {"shapes", "repeat", "settings", "shield-check"}                         # passed as variables in more.html
    missing = [n for n in sorted(used) if not os.path.exists(os.path.join(STATIC, "icons", f"{n}.svg"))]
    assert missing == []


def test_css_is_self_contained():
    css = open(os.path.join(STATIC, "app.css"), encoding="utf-8").read()
    # inline data: images carry the SVG namespace URI (a label, never fetched) — ignore them
    css = re.sub(r'url\("data:[^"]*"\)|url\(data:[^)]*\)', "url(data:)", css)
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)                                  # licence comments
    assert "@import" not in css and "fonts.googleapis" not in css and "cdn." not in css
    assert "http://" not in css and "https://" not in css                            # nothing fetched off-site
    for f in re.findall(r"url\(([^)]+)\)", css):
        f = f.strip("'\"")
        if f.startswith("data:"):
            continue
        assert os.path.exists(os.path.join(STATIC, f)), f
