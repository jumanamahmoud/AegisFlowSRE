-- =============================================================================
-- AegisFlow — Week 3: alert intake (FR-1 to FR-4)
-- =============================================================================
-- Adds:
--   * public.api_keys            — secret keys for monitoring tools (machine access)
--   * public.maintenance_windows — planned work: alerts are recorded, nobody is notified
--   * public.alerts              — every alert received, stored BEFORE processing
--   * incidents.source / fingerprint + a partial unique index, so at most one
--     active incident exists per alert fingerprint (duplicate detection, FR-3)
--
-- Apply after the Week 2 migration:
--   supabase db push      or paste into Dashboard → SQL Editor → Run
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Machine access keys
-- -----------------------------------------------------------------------------
-- Only a SHA-256 hash of each key is stored. Keys are 256-bit random values,
-- so a fast hash is safe here (no password-style stretching is needed).
create table if not exists public.api_keys (
    id            uuid primary key default gen_random_uuid(),
    name          text        not null check (length(name) between 1 and 100),
    key_prefix    text        not null,                 -- first characters, for display only
    key_hash      text        not null unique,          -- sha256 hex of the full key
    source        text check (source in ('alertmanager', 'grafana', 'datadog', 'cloudwatch')),
                                                        -- null = may post to any source
    created_by    text        not null,
    created_at    timestamptz not null default now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz,
    revoked_by    text
);

-- -----------------------------------------------------------------------------
-- 2. Maintenance windows (FR-4)
-- -----------------------------------------------------------------------------
create table if not exists public.maintenance_windows (
    id            uuid primary key default gen_random_uuid(),
    service_id    text        not null,
    starts_at     timestamptz not null,
    ends_at       timestamptz not null,
    reason        text,
    created_by    text        not null,
    created_at    timestamptz not null default now(),
    cancelled_at  timestamptz,
    cancelled_by  text,
    constraint maintenance_windows_valid_range check (ends_at > starts_at)
);

create index if not exists maintenance_windows_active_idx
    on public.maintenance_windows (service_id, starts_at, ends_at)
    where cancelled_at is null;

-- -----------------------------------------------------------------------------
-- 3. Incidents: where they came from + duplicate detection (FR-3)
-- -----------------------------------------------------------------------------
alter table public.incidents
    add column if not exists source      text,
    add column if not exists fingerprint text;

-- At most ONE active incident per fingerprint. This is what makes duplicate
-- detection safe when a monitoring tool retries the same alert concurrently:
-- the second insert fails and the backend attaches the alert to the first.
-- Once the incident is resolved or closed the fingerprint is free again, so a
-- recurrence opens a new incident.
create unique index if not exists incidents_active_fingerprint_uidx
    on public.incidents (fingerprint)
    where fingerprint is not null
      and status in ('open', 'acknowledged', 'mitigating');

-- -----------------------------------------------------------------------------
-- 4. Alerts — every alert received, in the common format (FR-1, FR-2)
-- -----------------------------------------------------------------------------
--   disposition
--     received      : stored, not yet processed (resumed on restart)
--     created       : opened a new incident
--     deduplicated  : repeat of an active incident's alert; attached to it
--     suppressed    : service was in a maintenance window; nobody notified
--     resolved      : the source reported recovery; attached to the incident
--     ignored       : informational, or a recovery with no active incident
create table if not exists public.alerts (
    id                     uuid primary key default gen_random_uuid(),
    source                 text        not null,
    external_id            text,
    fingerprint            text        not null,
    status                 text        not null check (status in ('firing', 'resolved', 'info')),
    service_id             text        not null,
    title                  text        not null,
    description            text,
    source_severity        text,
    labels                 jsonb       not null default '{}'::jsonb,
    url                    text,
    starts_at              timestamptz,
    raw                    jsonb       not null default '{}'::jsonb,
    disposition            text        not null default 'received'
        check (disposition in ('received', 'created', 'deduplicated', 'suppressed', 'resolved', 'ignored')),
    incident_id            uuid references public.incidents (id) on delete restrict,
    maintenance_window_id  uuid references public.maintenance_windows (id),
    api_key_id             uuid references public.api_keys (id),
    received_by            text        not null,
    received_at            timestamptz not null default now(),
    processed_at           timestamptz
);

create index if not exists alerts_received_at_idx  on public.alerts (received_at desc);
create index if not exists alerts_incident_idx     on public.alerts (incident_id, received_at);
create index if not exists alerts_fingerprint_idx  on public.alerts (fingerprint, received_at desc);
create index if not exists alerts_unprocessed_idx  on public.alerts (received_at) where disposition = 'received';

-- -----------------------------------------------------------------------------
-- 5. Row Level Security — only the backend (secret key) may touch these
-- -----------------------------------------------------------------------------
alter table public.api_keys            enable row level security;
alter table public.maintenance_windows enable row level security;
alter table public.alerts              enable row level security;

revoke all on public.api_keys, public.maintenance_windows, public.alerts from anon, authenticated;
