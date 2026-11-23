-- =============================================================================
-- AegisFlow — Week 1 (Foundation) schema
-- =============================================================================
-- Adds:
--   * incident lifecycle status (FR-15) on the existing `incidents` table
--   * `incident_analyses`   — every triage/AI analysis result, with model metadata
--   * `audit_events`        — append-only, immutable incident timeline (FR-17)
--
-- Safe to run against a project that already has the prototype `incidents`
-- table (id, service_id, alert, metadata, created_at): everything uses
-- IF NOT EXISTS / ADD COLUMN IF NOT EXISTS.
--
-- Apply with either:
--   supabase db push                       (Supabase CLI, linked project)
--   or paste into Dashboard → SQL Editor → Run
-- =============================================================================

create extension if not exists pgcrypto;

-- -----------------------------------------------------------------------------
-- 1. Incident lifecycle status (FR-15)
-- -----------------------------------------------------------------------------
-- Allowed transitions are enforced by the backend (models/incident.py), using
-- a compare-and-set update so two concurrent requests cannot both move the
-- incident out of the same state.
do $$
begin
    if not exists (select 1 from pg_type where typname = 'incident_status') then
        create type public.incident_status as enum (
            'open', 'acknowledged', 'mitigating', 'resolved', 'closed'
        );
    end if;
end$$;

create table if not exists public.incidents (
    id          uuid primary key default gen_random_uuid(),
    service_id  text        not null,
    alert       text        not null,
    metadata    jsonb       not null default '{}'::jsonb,
    created_at  timestamptz not null default now()
);

alter table public.incidents
    add column if not exists status            public.incident_status not null default 'open',
    add column if not exists incident_category text,
    add column if not exists severity          text,
    add column if not exists updated_at        timestamptz not null default now(),
    add column if not exists acknowledged_at   timestamptz,
    add column if not exists resolved_at       timestamptz,
    add column if not exists closed_at         timestamptz;

create index if not exists incidents_status_idx     on public.incidents (status);
create index if not exists incidents_created_at_idx on public.incidents (created_at desc);

create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin
    new.updated_at := now();
    return new;
end$$;

drop trigger if exists incidents_touch_updated_at on public.incidents;
create trigger incidents_touch_updated_at
    before update on public.incidents
    for each row execute function public.touch_updated_at();

-- -----------------------------------------------------------------------------
-- 2. Persisted analyses
-- -----------------------------------------------------------------------------
create table if not exists public.incident_analyses (
    id                 uuid primary key default gen_random_uuid(),
    incident_id        uuid not null references public.incidents (id) on delete cascade,

    -- System 1 (Jev triage)
    incident_category  text    not null,
    severity_score     smallint not null check (severity_score between 0 and 3),
    severity           text    not null,
    escalation_noul    double precision not null check (escalation_noul between 0 and 1),
    needs_escalation   boolean not null,

    -- System 2 (LLM) — analysis_source says which path produced llm_reasoning:
    --   'llm'      : a Groq model answered
    --   'fallback' : every model failed, rule-based summary used
    --   'skipped'  : low-risk alert, System 2 never ran
    analysis_source    text not null check (analysis_source in ('llm', 'fallback', 'skipped')),
    llm_reasoning      text,
    model_name         text,
    prompt_tokens      integer,
    completion_tokens  integer,
    total_tokens       integer,
    llm_latency_ms     integer,

    -- Graph context at the time of analysis
    service_context    jsonb not null default '[]'::jsonb,
    blast_radius       jsonb not null default '[]'::jsonb,

    started_at         timestamptz not null,
    completed_at       timestamptz not null,
    created_at         timestamptz not null default now()
);

create index if not exists incident_analyses_incident_idx
    on public.incident_analyses (incident_id, created_at desc);

-- -----------------------------------------------------------------------------
-- 3. Immutable audit timeline (FR-17)
-- -----------------------------------------------------------------------------
create table if not exists public.audit_events (
    id           bigint generated always as identity primary key,
    incident_id  uuid references public.incidents (id) on delete restrict,
    event_type   text        not null,
    actor        text        not null default 'system',
    payload      jsonb       not null default '{}'::jsonb,
    occurred_at  timestamptz not null default now(),  -- when it happened
    recorded_at  timestamptz not null default now()   -- when it was written
);

create index if not exists audit_events_incident_idx
    on public.audit_events (incident_id, occurred_at, id);

-- Append-only: block UPDATE / DELETE / TRUNCATE for every role, including the
-- service-role key the backend uses (triggers are not bypassed by RLS bypass).
create or replace function public.audit_events_immutable()
returns trigger language plpgsql as $$
begin
    raise exception 'audit_events is append-only (% blocked)', tg_op
        using errcode = 'insufficient_privilege';
end$$;

drop trigger if exists audit_events_no_update on public.audit_events;
create trigger audit_events_no_update
    before update or delete on public.audit_events
    for each row execute function public.audit_events_immutable();

drop trigger if exists audit_events_no_truncate on public.audit_events;
create trigger audit_events_no_truncate
    before truncate on public.audit_events
    for each statement execute function public.audit_events_immutable();

-- Incidents that have audit history cannot be deleted (on delete restrict
-- above), so the timeline can never be orphaned or silently removed.

-- -----------------------------------------------------------------------------
-- 4. Row Level Security
-- -----------------------------------------------------------------------------
-- The backend uses the secret (service-role) key, which bypasses RLS.
-- With RLS on and no policies, the public/publishable key can read or write
-- nothing. Week 2 (login + roles, FR-32) adds read policies for signed-in users.
alter table public.incidents         enable row level security;
alter table public.incident_analyses enable row level security;
alter table public.audit_events      enable row level security;

revoke all on public.incidents, public.incident_analyses, public.audit_events from anon, authenticated;
