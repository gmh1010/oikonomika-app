-- Oikonomika core schema. Lives in its own schema so Supabase's REST API (which exposes `public`) never sees it.
create schema if not exists oiko;

create table oiko.budgets (
  id uuid primary key default gen_random_uuid(),
  name text not null default 'Οικονομικά' check (length(name) between 1 and 60),
  currency text not null default '€' check (length(currency) between 1 and 4),
  accent text not null default '#0f766e' check (accent ~ '^#[0-9a-fA-F]{6}$'),
  opening_balance_cents bigint not null default 0,
  created_at timestamptz not null default now()
);

create table oiko.budget_members (
  budget_id uuid not null references oiko.budgets(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'owner' check (role in ('owner', 'member')),
  created_at timestamptz not null default now(),
  primary key (budget_id, user_id)
);
create index budget_members_user_idx on oiko.budget_members(user_id);

create table oiko.categories (
  id uuid primary key default gen_random_uuid(),
  budget_id uuid not null references oiko.budgets(id) on delete cascade,
  name text not null check (length(name) between 1 and 60),
  kind text not null check (kind in ('income', 'expense')),
  budget_cents bigint not null default 0 check (budget_cents >= 0),
  color text not null default '#6b7280' check (color ~ '^#[0-9a-fA-F]{6}$'),
  icon text not null default '' check (length(icon) <= 8),
  active boolean not null default true,
  sort int not null default 0,
  unique (budget_id, name, kind),
  unique (budget_id, id)
);

create table oiko.recurring (
  id uuid primary key default gen_random_uuid(),
  budget_id uuid not null references oiko.budgets(id) on delete cascade,
  category_id uuid not null,
  name text not null check (length(name) between 1 and 60),
  amount_cents bigint not null check (amount_cents > 0),
  day int not null default 1 check (day between 1 and 28),
  active boolean not null default true,
  unique (budget_id, id),
  foreign key (budget_id, category_id) references oiko.categories(budget_id, id)
);
create index recurring_budget_idx on oiko.recurring(budget_id);

create table oiko.transactions (
  id uuid primary key default gen_random_uuid(),
  budget_id uuid not null references oiko.budgets(id) on delete cascade,
  tdate date not null,
  category_id uuid not null,
  amount_cents bigint not null check (amount_cents > 0),
  note text not null default '' check (length(note) <= 200),
  recurring_id uuid,
  created_at timestamptz not null default now(),
  foreign key (budget_id, category_id) references oiko.categories(budget_id, id),
  foreign key (budget_id, recurring_id) references oiko.recurring(budget_id, id) on delete set null (recurring_id)
);
create index transactions_budget_date_idx on oiko.transactions(budget_id, tdate);

create table oiko.scan_usage (
  user_id uuid not null references auth.users(id) on delete cascade,
  month text not null check (month ~ '^\d{4}-\d{2}$'),
  count int not null default 0 check (count >= 0),
  primary key (user_id, month)
);

create table oiko.security_events (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users(id) on delete cascade,
  event text not null check (length(event) <= 40),
  ip_hash text,
  user_agent text check (length(user_agent) <= 300),
  created_at timestamptz not null default now()
);
create index security_events_user_idx on oiko.security_events(user_id, created_at);
