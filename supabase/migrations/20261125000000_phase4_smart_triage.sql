-- =============================================================================
-- AegisFlow — Phase 4: smart triage (FR-13, FR-14)
-- =============================================================================
-- Adds:
--   * alert grouping: incidents.probable_cause / grouped_services, alerts
--     disposition 'grouped' + alerts.grouped_via (FR-13)
--   * human review of uncertain triage: confidence scores on every analysis,
--     incidents.needs_review / review_reasons / reviewed_* (FR-14)
--
-- The service map itself (FR-29) lives in Neo4j and needs no SQL changes.
--
-- Apply after the Phase 3 migration:
--   supabase db push      or paste into Dashboard → SQL Editor → Run
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Grouping related alerts (FR-13)
-- -----------------------------------------------------------------------------
alter table public.incidents
    -- The shared component the grouped alerts point to, e.g.
    -- {"id": "payment-db", "name": "payment-db", "type": "database", "kind": "ExternalSystem"}
    add column if not exists probable_cause   jsonb,
    -- Services whose alerts were grouped into this incident (besides service_id).
    add column if not exists grouped_services text[] not null default '{}';

alter table public.alerts
    add column if not exists grouped_via jsonb;   -- why this alert joined its incident

alter table public.alerts drop constraint if exists alerts_disposition_check;
alter table public.alerts add constraint alerts_disposition_check
    check (disposition in ('received', 'created', 'deduplicated', 'grouped',
                           'suppressed', 'resolved', 'ignored'));

-- Recent active incidents are the grouping candidates.
create index if not exists incidents_active_recent_idx
    on public.incidents (created_at desc)
    where status in ('open', 'acknowledged', 'mitigating');

-- -----------------------------------------------------------------------------
-- 2. Human review of uncertain triage (FR-14)
-- -----------------------------------------------------------------------------
alter table public.incident_analyses
    add column if not exists category_confidence double precision
        check (category_confidence is null or category_confidence between 0 and 1),
    add column if not exists severity_confidence double precision
        check (severity_confidence is null or severity_confidence between 0 and 1),
    add column if not exists needs_review   boolean not null default false,
    add column if not exists review_reasons jsonb   not null default '[]'::jsonb;

alter table public.incidents
    add column if not exists needs_review   boolean not null default false,
    add column if not exists review_reasons jsonb   not null default '[]'::jsonb,
    add column if not exists reviewed_at    timestamptz,
    add column if not exists reviewed_by    text;

create index if not exists incidents_needs_review_idx
    on public.incidents (created_at desc)
    where needs_review;
