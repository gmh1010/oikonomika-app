# Oikonomika

A multi-user personal finance tracker for expenses and income, with a Greek interface. Add
transactions by hand or **scan receipts, invoices and bank statements** and let AI turn them into
rows you can review before you import them.

![Python](https://img.shields.io/badge/Python-3.11-3776AB) ![Flask](https://img.shields.io/badge/Flask-3.1-000000) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Row--Level%20Security-336791) ![Tests](https://img.shields.io/badge/tests-121-brightgreen) ![License: MIT](https://img.shields.io/badge/License-MIT-green)

## Features

- **Transactions:** expenses, income and transfers, with categories, colours and emoji icons.
- **Monthly dashboard:** totals per month and per category, with a budget per category.
- **Recurring payments:** turn any transaction into a monthly one (day 1–31; day 31 falls on the
  last day of shorter months) and post the due ones in one click.
- **Scan with AI (Google Gemini):**
  - Photos of receipts and invoices.
  - PDF bank statements up to 40 pages, read in parallel chunks of 5 pages.
  - Bank exports in `.xlsx` / `.csv`, read as plain values only.
  - Duplicate detection (same name, date and amount) and a review screen before anything is saved.
  - Remembers the category you chose for each shop and suggests it next time.
  - Monthly scan quota per user.
- **Export** to CSV and Excel, protected against formula injection.
- **Light / dark theme**, installable as a web app (PWA).

## Security

- Every table is protected with **PostgreSQL Row-Level Security**. The app connects as a restricted
  role, so one user can never read another user's data, even if there is a bug in the code.
- Sign-in with Supabase Auth: email confirmation, **two-factor authentication (TOTP)** with recovery
  codes, re-authentication before sensitive changes, and sign-up by invite code.
- New passwords are checked against known leaked passwords (Have I Been Pwned, k-anonymity API).
- Cloudflare Turnstile on sign-up and login, rate limiting, CSRF protection and strict security headers.
- Session data is encrypted. Logs keep method, path and status only (no query strings, no IPs).
- The Docker image runs as a non-root user on a read-only filesystem.
- Dependencies are pinned and audited with `pip-audit`.

## Tech stack

| Layer | Tools |
|---|---|
| Backend | Python 3.11, Flask, psycopg 3, gunicorn |
| Database & auth | PostgreSQL with Row-Level Security, Supabase (Auth + migrations) |
| AI | Google Gemini (`google-genai`) for scanning |
| Frontend | Jinja templates, Tailwind CSS, Lucide icons, self-hosted Inter font |
| Tests | pytest (121 tests: auth, RLS, security, scanning, UI, web) |
| Deploy | Docker |

## Project layout

```
app/          Flask app (routes, auth, database access, scanning, security) and tests
supabase/     Database migrations, Row-Level Security policies, email templates, local config
ui/           Tailwind build that writes CSS, fonts and icons into app/static
Dockerfile    Production image
```

## Run locally

Requirements: Python 3.11, Node.js, Docker and the [Supabase CLI](https://supabase.com/docs/guides/local-development/cli/getting-started).

```bash
# 1. Start the local database, auth and mail server, and apply the migrations
supabase start
supabase db reset

# 2. Build the CSS and icons
cd ui && npm install && npm run build && cd ..

# 3. Install Python packages
pip install -r app/requirements.txt -r app/requirements-dev.txt

# 4. Copy the local keys that `supabase status` prints
export SUPABASE_PUBLISHABLE_KEY=...
export SUPABASE_SECRET_KEY=...

# 5. Run the app
cd app && python run_dev.py
```

Open http://127.0.0.1:5080/auth/signup and sign up with the invite code `dev-invite`. Confirmation
emails arrive in the local mail viewer at http://127.0.0.1:55324.

To scan documents, put a Google Gemini key in `app/.env`:

```
GEMINI_API_KEY=your-key
```

## Tests

With the local Supabase stack running:

```bash
export OIKO_TEST_PUB_KEY=...      # from `supabase status`
export OIKO_TEST_SECRET_KEY=...
cd app && python -m pytest
```

## Production configuration

All settings come from environment variables:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Postgres connection for the restricted app role |
| `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY` | Supabase Auth |
| `SECRET_KEY`, `SESSION_ENC_KEY`, `IP_SALT` | Flask session, session encryption, IP hashing |
| `INVITE_CODE` | Code needed to sign up |
| `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET` | Cloudflare Turnstile |
| `SCAN_QUOTA` | Scans per user per month |
| `COOKIE_SECURE`, `TRUST_PROXY`, `GOOGLE_ENABLED` | Flags |
| `GEMINI_API_KEY` | Google Gemini, for scanning |

Never commit `.env` files or real keys. `.gitignore` already excludes them, together with local
databases and spreadsheets.

## License

MIT © 2026 Majdinel Hima
