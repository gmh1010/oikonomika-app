-- Auth support: server-side sessions, rate limits, 2FA recovery codes.
-- app_user gets NO table privileges here: everything goes through the SECURITY DEFINER functions below,
-- so even an SQL-injection bug in the app could not list sessions or codes.

create table oiko.app_sessions (
  id_hash text primary key check (length(id_hash) = 64),          -- sha256 of the random cookie value
  user_id uuid not null references auth.users(id) on delete cascade,
  email text not null default '',
  refresh_enc text not null,                                      -- Fernet-encrypted refresh token
  aal text not null default 'aal1' check (aal in ('aal1', 'aal2')),
  mfa_pending boolean not null default false,
  user_agent text not null default '' check (length(user_agent) <= 300),
  ip_hash text not null default '',
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  validated_at timestamptz not null default now(),
  reauth_at timestamptz
);
create index app_sessions_user_idx on oiko.app_sessions(user_id);

create table oiko.rate_limits (
  key text primary key check (length(key) = 64),                  -- sha256 of kind|identifier
  window_start timestamptz not null default now(),
  count int not null default 0
);

create table oiko.recovery_codes (
  user_id uuid not null references auth.users(id) on delete cascade,
  code_hash text not null check (length(code_hash) <= 64),
  used_at timestamptz,
  primary key (user_id, code_hash)
);

alter table oiko.app_sessions enable row level security;
alter table oiko.app_sessions force row level security;
alter table oiko.rate_limits enable row level security;
alter table oiko.rate_limits force row level security;
alter table oiko.recovery_codes enable row level security;
alter table oiko.recovery_codes force row level security;
revoke all on oiko.app_sessions, oiko.rate_limits, oiko.recovery_codes from public, anon, authenticated, app_user;

-- ---------- sessions ----------

create or replace function oiko.session_create(p_id text, p_user uuid, p_email text, p_refresh text, p_aal text,
                                               p_mfa boolean, p_ua text, p_ip text, p_reauth boolean)
returns void language sql security definer set search_path = '' as $$
  insert into oiko.app_sessions (id_hash, user_id, email, refresh_enc, aal, mfa_pending, user_agent, ip_hash, reauth_at)
  values (p_id, p_user, coalesce(p_email, ''), p_refresh, p_aal, p_mfa, left(coalesce(p_ua, ''), 300), coalesce(p_ip, ''),
          case when p_reauth then now() end)
$$;

-- Returns the live session (and touches it) or nothing. Expired sessions are deleted on sight:
-- idle > 12 h, older than 30 days, or a pending-2FA login older than 10 minutes.
create or replace function oiko.session_get(p_id text)
returns table (user_id uuid, email text, refresh_enc text, aal text, mfa_pending boolean,
               created_at timestamptz, validated_at timestamptz, reauth_at timestamptz)
language plpgsql security definer set search_path = '' as $$
begin
  delete from oiko.app_sessions s
  where s.id_hash = p_id
    and (s.last_seen_at < now() - interval '12 hours'
         or s.created_at < now() - interval '30 days'
         or (s.mfa_pending and s.created_at < now() - interval '10 minutes'));
  return query
    update oiko.app_sessions s set last_seen_at = now()
    where s.id_hash = p_id
    returning s.user_id, s.email, s.refresh_enc, s.aal, s.mfa_pending, s.created_at, s.validated_at, s.reauth_at;
end
$$;

create or replace function oiko.session_update(p_id text, p_refresh text, p_aal text, p_mfa boolean,
                                               p_validated boolean, p_reauth boolean)
returns void language sql security definer set search_path = '' as $$
  update oiko.app_sessions set
    refresh_enc = coalesce(p_refresh, refresh_enc),
    aal = coalesce(p_aal, aal),
    mfa_pending = coalesce(p_mfa, mfa_pending),
    validated_at = case when p_validated then now() else validated_at end,
    reauth_at = case when p_reauth then now() else reauth_at end
  where id_hash = p_id
$$;

create or replace function oiko.session_delete(p_id text)
returns void language sql security definer set search_path = '' as $$
  delete from oiko.app_sessions where id_hash = p_id
$$;

-- "Sign out everywhere": only ever the sessions of the user who owns p_id.
create or replace function oiko.session_delete_all(p_id text)
returns void language sql security definer set search_path = '' as $$
  delete from oiko.app_sessions
  where user_id = (select s.user_id from oiko.app_sessions s where s.id_hash = p_id)
$$;

create or replace function oiko.session_delete_others(p_id text)
returns void language sql security definer set search_path = '' as $$
  delete from oiko.app_sessions
  where user_id = (select s.user_id from oiko.app_sessions s where s.id_hash = p_id) and id_hash <> p_id
$$;

-- ---------- rate limits (fixed window) ----------

create or replace function oiko.rate_hit(p_key text, p_window int, p_limit int)
returns boolean language plpgsql security definer set search_path = '' as $$
declare n int;
begin
  insert into oiko.rate_limits as r (key, window_start, count) values (p_key, now(), 1)
  on conflict (key) do update set
    count = case when r.window_start < now() - make_interval(secs => p_window) then 1 else r.count + 1 end,
    window_start = case when r.window_start < now() - make_interval(secs => p_window) then now() else r.window_start end
  returning r.count into n;
  return n <= p_limit;
end
$$;

-- True while the key is still under its limit (does not count as a hit).
create or replace function oiko.rate_check(p_key text, p_window int, p_limit int)
returns boolean language sql stable security definer set search_path = '' as $$
  select not exists (select 1 from oiko.rate_limits r
                     where r.key = p_key and r.count >= p_limit
                       and r.window_start >= now() - make_interval(secs => p_window))
$$;

create or replace function oiko.rate_reset(p_key text)
returns void language sql security definer set search_path = '' as $$
  delete from oiko.rate_limits where key = p_key
$$;

-- ---------- security events (also for not-yet-identified visitors) ----------

create or replace function oiko.log_event(p_user uuid, p_event text, p_ip text, p_ua text)
returns void language sql security definer set search_path = '' as $$
  insert into oiko.security_events (user_id, event, ip_hash, user_agent)
  values (p_user, left(p_event, 40), p_ip, left(coalesce(p_ua, ''), 300))
$$;

-- ---------- 2FA recovery codes (stored hashed, single use) ----------

create or replace function oiko.recovery_set(p_user uuid, p_hashes text[])
returns void language sql security definer set search_path = '' as $$
  delete from oiko.recovery_codes where user_id = p_user;
  insert into oiko.recovery_codes (user_id, code_hash) select p_user, h from unnest(p_hashes) as h;
$$;

create or replace function oiko.recovery_use(p_user uuid, p_hash text)
returns boolean language plpgsql security definer set search_path = '' as $$
begin
  update oiko.recovery_codes set used_at = now()
  where user_id = p_user and code_hash = p_hash and used_at is null;
  return found;
end
$$;

create or replace function oiko.recovery_left(p_user uuid)
returns int language sql stable security definer set search_path = '' as $$
  select count(*)::int from oiko.recovery_codes where user_id = p_user and used_at is null
$$;

create or replace function oiko.recovery_clear(p_user uuid)
returns void language sql security definer set search_path = '' as $$
  delete from oiko.recovery_codes where user_id = p_user
$$;

-- Execute only for app_user.
do $$
declare f text;
begin
  foreach f in array array[
    'oiko.session_create(text,uuid,text,text,text,boolean,text,text,boolean)', 'oiko.session_get(text)',
    'oiko.session_update(text,text,text,boolean,boolean,boolean)', 'oiko.session_delete(text)',
    'oiko.session_delete_all(text)', 'oiko.session_delete_others(text)',
    'oiko.rate_hit(text,integer,integer)', 'oiko.rate_check(text,integer,integer)', 'oiko.rate_reset(text)',
    'oiko.log_event(uuid,text,text,text)', 'oiko.recovery_set(uuid,text[])', 'oiko.recovery_use(uuid,text)',
    'oiko.recovery_left(uuid)', 'oiko.recovery_clear(uuid)']
  loop
    execute format('revoke all on function %s from public, anon, authenticated', f);
    execute format('grant execute on function %s to app_user', f);
  end loop;
end $$;
