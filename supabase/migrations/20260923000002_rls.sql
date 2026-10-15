-- Restricted application role: can only do what the policies below allow.
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'app_user') then
    create role app_user nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls;
  end if;
end $$;

-- Nobody but app_user gets into schema oiko (Supabase API roles explicitly shut out).
revoke all on schema oiko from public, anon, authenticated;
revoke all on all tables in schema oiko from public, anon, authenticated;
revoke all on all sequences in schema oiko from public, anon, authenticated;
alter default privileges in schema oiko revoke all on tables from public, anon, authenticated;
alter default privileges in schema oiko revoke all on functions from public, anon, authenticated;

grant usage on schema oiko to app_user;
grant select, update on oiko.budgets to app_user;
grant select on oiko.budget_members to app_user;
grant select, insert, update, delete on oiko.categories, oiko.recurring, oiko.transactions to app_user;
grant select, insert, update on oiko.scan_usage to app_user;
grant select, insert on oiko.security_events to app_user;

-- Who is asking? Set per transaction by the app: select set_config('app.user_id', '<uuid>', true)
create or replace function oiko.current_user_id() returns uuid
language sql stable set search_path = '' as $$
  select nullif(current_setting('app.user_id', true), '')::uuid
$$;

create or replace function oiko.is_member(b uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from oiko.budget_members m
                 where m.budget_id = b and m.user_id = oiko.current_user_id())
$$;

-- First request of a user: create their budget with default categories. Returns the budget id.
create or replace function oiko.provision_budget() returns uuid
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := oiko.current_user_id();
  bid uuid;
begin
  if uid is null then
    raise exception 'provision_budget: no user in context';
  end if;
  select m.budget_id into bid from oiko.budget_members m where m.user_id = uid order by m.created_at limit 1;
  if bid is not null then
    return bid;
  end if;
  perform pg_advisory_xact_lock(hashtext(uid::text));
  select m.budget_id into bid from oiko.budget_members m where m.user_id = uid order by m.created_at limit 1;
  if bid is not null then
    return bid;
  end if;
  insert into oiko.budgets default values returning id into bid;
  insert into oiko.budget_members (budget_id, user_id, role) values (bid, uid, 'owner');
  insert into oiko.categories (budget_id, name, kind, color, icon, sort)
  select bid, d.name, d.kind, d.color, d.icon, d.sort
  from (values
    ('Μισθός', 'income', '#15803d', '💼', 1),
    ('Άλλο έσοδο', 'income', '#65a30d', '💰', 2),
    ('Ενοίκιο', 'expense', '#7c3aed', '🏠', 10),
    ('Λογαριασμοί (ρεύμα/νερό/τηλέφωνο)', 'expense', '#2563eb', '💡', 11),
    ('Σούπερ μάρκετ', 'expense', '#ea580c', '🛒', 12),
    ('Καφέδες', 'expense', '#a16207', '☕', 13),
    ('Φαγητό έξω / delivery', 'expense', '#dc2626', '🍔', 14),
    ('Μετακινήσεις / καύσιμα', 'expense', '#475569', '⛽', 15),
    ('Συνδρομές', 'expense', '#db2777', '📺', 16),
    ('Ρούχα', 'expense', '#9333ea', '👕', 17),
    ('Υγεία / φαρμακείο', 'expense', '#0891b2', '💊', 18),
    ('Δάνεια / κάρτες', 'expense', '#b91c1c', '💳', 19),
    ('Ταξίδια', 'expense', '#0284c7', '✈️', 20),
    ('Δώρα / έκτακτα', 'expense', '#c2410c', '🎁', 21),
    ('Άλλα', 'expense', '#6b7280', '📦', 99)
  ) as d(name, kind, color, icon, sort);
  return bid;
end
$$;

revoke all on function oiko.current_user_id() from public, anon, authenticated;
revoke all on function oiko.is_member(uuid) from public, anon, authenticated;
revoke all on function oiko.provision_budget() from public, anon, authenticated;
grant execute on function oiko.current_user_id() to app_user;
grant execute on function oiko.is_member(uuid) to app_user;
grant execute on function oiko.provision_budget() to app_user;

-- Row-Level Security: on, and forced even for the table owner.
alter table oiko.budgets enable row level security;
alter table oiko.budgets force row level security;
alter table oiko.budget_members enable row level security;
alter table oiko.budget_members force row level security;
alter table oiko.categories enable row level security;
alter table oiko.categories force row level security;
alter table oiko.recurring enable row level security;
alter table oiko.recurring force row level security;
alter table oiko.transactions enable row level security;
alter table oiko.transactions force row level security;
alter table oiko.scan_usage enable row level security;
alter table oiko.scan_usage force row level security;
alter table oiko.security_events enable row level security;
alter table oiko.security_events force row level security;

create policy members_self on oiko.budget_members
  for select to app_user using (user_id = oiko.current_user_id());

create policy budgets_read on oiko.budgets
  for select to app_user using (oiko.is_member(id));
create policy budgets_update on oiko.budgets
  for update to app_user using (oiko.is_member(id)) with check (oiko.is_member(id));

create policy categories_member on oiko.categories
  for all to app_user using (oiko.is_member(budget_id)) with check (oiko.is_member(budget_id));
create policy recurring_member on oiko.recurring
  for all to app_user using (oiko.is_member(budget_id)) with check (oiko.is_member(budget_id));
create policy transactions_member on oiko.transactions
  for all to app_user using (oiko.is_member(budget_id)) with check (oiko.is_member(budget_id));

create policy scan_usage_self on oiko.scan_usage
  for all to app_user using (user_id = oiko.current_user_id()) with check (user_id = oiko.current_user_id());

create policy security_events_read_own on oiko.security_events
  for select to app_user using (user_id = oiko.current_user_id());
create policy security_events_insert_own on oiko.security_events
  for insert to app_user with check (user_id = oiko.current_user_id());
