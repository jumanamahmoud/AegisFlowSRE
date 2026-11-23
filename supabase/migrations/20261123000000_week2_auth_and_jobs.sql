-- =============================================================================
-- AegisFlow — Week 2: user roles (FR-32) and background analysis status
-- =============================================================================
-- Adds:
--   * public.user_roles     — one role per Supabase Auth user
--                             (viewer < responder < admin)
--   * trigger: every new auth user gets the 'viewer' role automatically
--   * incidents.analysis_status — lets the API return immediately while the
--                             pipeline runs in the background (and lets the
--                             backend resume queued work after a restart)
--
-- Apply after the Week 1 migrations:
--   supabase db push      or paste into Dashboard → SQL Editor → Run
--
-- Make yourself an administrator afterwards (replace the email):
--   update public.user_roles set role = 'admin'
--    where user_id = (select id from auth.users where email = 'you@example.com');
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Roles
-- -----------------------------------------------------------------------------
do $$
begin
    if not exists (select 1 from pg_type where typname = 'app_role') then
        create type public.app_role as enum ('viewer', 'responder', 'admin');
    end if;
end$$;

create table if not exists public.user_roles (
    user_id     uuid primary key references auth.users (id) on delete cascade,
    role        public.app_role not null default 'viewer',
    updated_at  timestamptz not null default now(),
    updated_by  text
);

drop trigger if exists user_roles_touch_updated_at on public.user_roles;
create trigger user_roles_touch_updated_at
    before update on public.user_roles
    for each row execute function public.touch_updated_at();

-- New sign-ups start as read-only viewers; an admin promotes them.
create or replace function public.grant_default_role()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    insert into public.user_roles (user_id, role, updated_by)
    values (new.id, 'viewer', 'system:signup')
    on conflict (user_id) do nothing;
    return new;
end$$;

drop trigger if exists on_auth_user_created_grant_role on auth.users;
create trigger on_auth_user_created_grant_role
    after insert on auth.users
    for each row execute function public.grant_default_role();

-- Users who already existed before this migration.
insert into public.user_roles (user_id, role, updated_by)
select id, 'viewer', 'system:backfill' from auth.users
on conflict (user_id) do nothing;

-- Only the backend (secret key) reads or changes roles.
alter table public.user_roles enable row level security;
revoke all on public.user_roles from anon, authenticated;
revoke execute on function public.grant_default_role() from public, anon, authenticated;

-- -----------------------------------------------------------------------------
-- 2. Background analysis status
-- -----------------------------------------------------------------------------
--   none      : never analysed
--   queued    : accepted, waiting for a worker (resumed after a restart)
--   running   : a worker is executing the pipeline
--   completed : latest run saved an analysis
--   failed    : latest run failed (see analysis_error and the timeline)
alter table public.incidents
    add column if not exists analysis_status     text not null default 'none',
    add column if not exists analysis_error      text,
    add column if not exists analysis_updated_at timestamptz;

do $$
begin
    if not exists (select 1 from pg_constraint where conname = 'incidents_analysis_status_check') then
        alter table public.incidents
            add constraint incidents_analysis_status_check
            check (analysis_status in ('none', 'queued', 'running', 'completed', 'failed'));
    end if;
end$$;

-- Incidents analysed before this migration.
update public.incidents i
   set analysis_status = 'completed'
 where analysis_status = 'none'
   and exists (select 1 from public.incident_analyses a where a.incident_id = i.id);

create index if not exists incidents_analysis_pending_idx
    on public.incidents (analysis_status)
    where analysis_status in ('queued', 'running');
