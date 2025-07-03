-- ============================================================
--  Habitua – Schema v0  (multi-tenant, role-based)
--  Copia questo blocco intero nel Supabase SQL editor.
-- ============================================================

-- 1. Abilita l'estensione pgcrypto (UUID v4)
create extension if not exists pgcrypto;

-- 2. Tabelle di base ----------------------------------------

-- ~~~ Aziende / Tenant ~~~
create table companies (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  plan          text not null default 'starter',   -- starter | growth | enterprise
  created_at    timestamptz default now()
);

-- ~~~ Utenti (collegati a Supabase auth.users) ~~~
create table users (
  id              uuid primary key,               -- stesso id di auth.users.id
  company_id      uuid references companies(id) on delete cascade,
  role            text check (role in ('employee','hr','admin')) not null,
  full_name       text,
  email           text,
  created_at      timestamptz default now()
);

-- ~~~ Attività / Micro-azioni completate ~~~
create table activities (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid references users(id) on delete cascade,
  type            text,              -- es. 'walking-snack', 'breathing-break'
  duration_min    int,
  evidence_level  text,              -- meta-info (A, B, C…)
  completed_at    timestamptz default now()
);

-- ~~~ Punti accumulati ~~~
create table points (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid references users(id) on delete cascade,
  amount          int          not null,
  source          text,        -- 'activity' | 'bonus' | ...
  created_at      timestamptz default now()
);

-- ~~~ Redemption premi ~~~
create table redemptions (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid references users(id) on delete cascade,
  item            text,        -- nome premio (es. 'Buono Amazon 10€')
  points_spent    int,
  redeemed_at     timestamptz default now()
);

-- 3. Row-Level Security (RLS) -------------------------------

alter table companies   enable row level security;
alter table users       enable row level security;
alter table activities  enable row level security;
alter table points      enable row level security;
alter table redemptions enable row level security;

-- Policy di default: NESSUN accesso, si apre granularmente.
-- -----------------------------------------------------------

-- Helper: ottieni il ruolo dall'header JWT
create or replace function auth_role() returns text
language sql stable as $$
  select coalesce(current_setting('request.jwt.claims', true)::json->>'role', 'anon');
$$;

-- ~~~ company isolation: dipendenti della stessa azienda ~~~
create policy "Users can see themselves"
on users
for select using ( id = auth.uid() );

create policy "HR/Admin can see company users"
on users
for select using (
  (role in ('hr','admin')) and (company_id = ( select company_id from users where id = auth.uid() ))
);

-- applichiamo la stessa logica alle altre tabelle -----------------

-- Attività
create policy "Employee vede le proprie attività"
on activities
for select using ( user_id = auth.uid() );

create policy "HR/Admin vede attività della propria azienda"
on activities
for select using (
  ( select role from users where id = auth.uid() ) in ('hr','admin')
  and
  user_id in ( select id from users where company_id = ( select company_id from users where id = auth.uid() ) )
);

-- Punti
create policy "Employee vede i propri punti"
on points
for select using ( user_id = auth.uid() );

create policy "HR/Admin vede punti dell'azienda"
on points
for select using (
  ( select role from users where id = auth.uid() ) in ('hr','admin')
  and
  user_id in ( select id from users where company_id = ( select company_id from users where id = auth.uid() ) )
);

-- Redemptions
create policy "Employee vede i propri redemptions"
on redemptions
for select using ( user_id = auth.uid() );

create policy "HR/Admin vede redemptions dell'azienda"
on redemptions
for select using (
  ( select role from users where id = auth.uid() ) in ('hr','admin')
  and
  user_id in ( select id from users where company_id = ( select company_id from users where id = auth.uid() ) )
);

-- 4. Seeds minimi (facoltativo) ------------------------------
--  Crea una company di test e tre utenti fittizi
insert into companies (id, name, plan)
values ('00000000-0000-0000-0000-000000000001', 'DemoCorp', 'starter');

insert into auth.users (id, email, raw_user_meta_data)
values
 ('10000000-0000-0000-0000-000000000001', 'alice@democorp.com', '{"role":"employee"}'),
 ('10000000-0000-0000-0000-000000000002', 'bob@democorp.com',   '{"role":"hr"}'),
 ('10000000-0000-0000-0000-000000000003', 'carol@habitua.dev',  '{"role":"admin"}');

insert into users (id, company_id, role, full_name, email)
select id,
       '00000000-0000-0000-0000-000000000001',
       (raw_user_meta_data->>'role')::text,
       split_part(email,'@',1),
       email
from auth.users;
