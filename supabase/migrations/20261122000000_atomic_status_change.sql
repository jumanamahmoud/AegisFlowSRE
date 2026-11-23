-- =============================================================================
-- AegisFlow — atomic incident status change (FR-15 + FR-17)
-- =============================================================================
-- Before this, the backend changed incidents.status and then inserted the
-- `incident.status_changed` audit event as two separate HTTP calls. If the
-- second call failed, the incident moved with no timeline record.
--
-- This function does both in ONE transaction: the compare-and-set update and
-- the audit insert either both commit or both roll back.
--
-- Transition rules stay in the backend (models/incident.py), which validates
-- before calling. The function enforces the compare-and-set: it only updates
-- when the row is still in p_from, and returns no row otherwise.
--
-- Apply after 20261120000000_week1_foundation.sql:
--   supabase db push      or paste into Dashboard → SQL Editor → Run
-- =============================================================================

create or replace function public.change_incident_status(
    p_incident_id uuid,
    p_from        public.incident_status,
    p_to          public.incident_status,
    p_actor       text,
    p_note        text default null
)
returns setof public.incidents
language plpgsql
set search_path = public
as $$
declare
    v_row public.incidents;
begin
    update public.incidents
       set status          = p_to,
           -- first-time timestamps: never overwritten on a later re-entry
           acknowledged_at = coalesce(acknowledged_at, case when p_to = 'acknowledged' then now() end),
           resolved_at     = coalesce(resolved_at,     case when p_to = 'resolved'     then now() end),
           closed_at       = coalesce(closed_at,       case when p_to = 'closed'       then now() end)
     where id = p_incident_id
       and status = p_from
    returning * into v_row;

    if not found then
        return;  -- status changed concurrently (or incident gone): caller gets 0 rows
    end if;

    insert into public.audit_events (incident_id, event_type, actor, payload)
    values (
        p_incident_id,
        'incident.status_changed',
        p_actor,
        jsonb_strip_nulls(jsonb_build_object('from', p_from, 'to', p_to, 'note', p_note))
    );

    return next v_row;
end;
$$;

-- Functions are executable by PUBLIC by default; restrict to the backend's key.
revoke execute on function public.change_incident_status(uuid, public.incident_status, public.incident_status, text, text)
    from public, anon, authenticated;
grant execute on function public.change_incident_status(uuid, public.incident_status, public.incident_status, text, text)
    to service_role;
