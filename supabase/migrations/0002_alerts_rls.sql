-- =====================================================================
-- AI-SOC : Day 2 — alert dedup ("detection API" transform) + RLS
-- =====================================================================
-- The read "API" is PostgREST auto-generated over these RLS'd tables
-- (queried from the browser with the *publishable* key). Server-side
-- writes (Day 4 agents) go through Edge Functions using the secret key,
-- which bypasses RLS. So here we (1) turn raw detector `signals` into
-- deduplicated, analyst-facing `alerts` with per-detector contributions,
-- and (2) lock every table to read-only for the browser role.
-- Re-runnable: paste into the SQL editor or `psql -f`.
-- =====================================================================

-- ---------- (1) signals -> alerts : dedup + contribution fusion ------
-- Grouping key = (primary entity, source_type). Multiple detectors that
-- fire on the same entity/stream collapse into ONE alert whose
-- `contributions` records each detector's max score. Confidence is a
-- transparent noisy-OR over those per-detector scores. Campaign-level
-- merging across sources is Day 3 (correlation -> incidents), not here.
create or replace function build_alerts() returns int language plpgsql as $$
declare n int;
begin
  -- rebuild only auto-generated alerts; never clobber correlated ones
  delete from alerts where incident_id is null;

  with sig as (
    select s.event_id, s.detector, s.detector_ref, s.score, s.reason,
           e.source_type,
           coalesce(host(e.src_ip), e.host, e.domain, e.process, e."user", 'unknown') as entity
    from signals s join events e on e.event_id = s.event_id
  ),
  per_ref as (                       -- one row per detector rule on an entity
    select entity, source_type, detector_ref,
           max(score) as ref_score,
           (array_agg(detector order by score desc))[1] as detector
    from sig group by entity, source_type, detector_ref
  ),
  grp as (                           -- fuse detectors per (entity, source)
    select entity, source_type,
           jsonb_object_agg(detector_ref, round(ref_score::numeric, 3)) as contributions,
           1 - exp(sum(ln(greatest(1e-6, 1 - ref_score)))) as confidence
    from per_ref group by entity, source_type
  ),
  agg as (                           -- source events + human-readable headline
    select entity, source_type,
           array_agg(distinct event_id) as event_ids,
           count(distinct event_id) as corr_count,
           (array_agg(reason   order by score desc))[1] as top_reason,
           (array_agg(detector order by score desc))[1] as primary_detector
    from sig group by entity, source_type
  )
  insert into alerts(title, severity, confidence, detector, contributions,
                     entity, event_ids, correlation_count, status)
  select initcap(g.source_type) || ': ' || a.top_reason,
         (case when g.confidence >= 0.85 then 'high'
               when g.confidence >= 0.60 then 'medium'
               when g.confidence >= 0.35 then 'low'
               else 'info' end)::severity_t,
         round(g.confidence::numeric, 3),
         a.primary_detector,
         g.contributions,
         g.entity,
         a.event_ids,
         a.corr_count,
         'new'
  from grp g join agg a using (entity, source_type);

  get diagnostics n = row_count;
  return n;
end $$;

select build_alerts() as alerts_built;

-- ---------- (2) Row Level Security : browser role is read-only -------
-- NOTE: a permissive read policy means anyone holding the publishable
-- key + project URL can SELECT every row (normal for a public dashboard;
-- the data here is synthetic). Writes are blocked for anon/authenticated
-- because no INSERT/UPDATE/DELETE policy exists.
do $$
declare t text;
begin
  foreach t in array array[
    'events','signals','detection_rules','alerts','incidents',
    'incident_entities','evidence','agent_runs','incident_timeline',
    'attack_kb','feedback'
  ] loop
    execute format('alter table %I enable row level security', t);
    execute format('drop policy if exists %I on %I', 'read_'||t, t);
    execute format(
      'create policy %I on %I for select to anon, authenticated using (true)',
      'read_'||t, t);
  end loop;
end $$;

-- the view must respect the caller's RLS, not the definer's
alter view v_ingest_rate set (security_invoker = on);
