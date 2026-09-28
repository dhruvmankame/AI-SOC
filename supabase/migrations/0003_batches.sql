-- =====================================================================
-- AI-SOC : Day 6 — upload BATCH namespacing (upload -> detect -> record)
-- =====================================================================
-- Each UI upload becomes one `ingest_batches` row; every row it produces
-- (events/signals/alerts/incidents/incident_entities) is stamped with its
-- batch_id. The seeded CICIDS demo predates batches, so its rows keep
-- batch_id = NULL and the UI shows them as "CICIDS Seed (baseline)".
--
-- Incident-scoped tables (evidence / agent_runs / incident_timeline) are
-- NOT stamped: they reach a batch by joining `incidents`, so a batch_id
-- there would only duplicate that edge.
--
-- RLS: the browser (anon key) is read-only. Existing table policies are
-- `for select using (true)` and are table-level, so the new columns are
-- already covered; only the new `ingest_batches` table needs its own
-- read policy. All writes stay server-side (secret DATABASE_URL / server.ts).
--
-- Idempotent + re-runnable: paste into the SQL editor or `psql -f`.
-- =====================================================================

-- ---------- (1) the batch registry -----------------------------------
create table if not exists ingest_batches (
  batch_id        uuid primary key default gen_random_uuid(),
  label           text,                 -- human label (defaults to filename)
  source_filename text,
  created_at      timestamptz not null default now(),
  event_count     int,                  -- stored events (sampled), not raw flow count
  incident_count  int,
  status          text default 'detected'  -- detected|investigating|complete
);
create index if not exists idx_batches_created on ingest_batches (created_at desc);

-- ---------- (2) stamp batch_id onto the produced rows ----------------
-- Nullable FK: seeded rows stay NULL. on delete cascade so deleting a
-- batch cleans up everything it produced (incidents cascade further to
-- evidence/agent_runs/timeline/entities via their own FKs).
alter table events            add column if not exists batch_id uuid references ingest_batches(batch_id) on delete cascade;
alter table signals           add column if not exists batch_id uuid references ingest_batches(batch_id) on delete cascade;
alter table alerts            add column if not exists batch_id uuid references ingest_batches(batch_id) on delete cascade;
alter table incidents         add column if not exists batch_id uuid references ingest_batches(batch_id) on delete cascade;
alter table incident_entities add column if not exists batch_id uuid references ingest_batches(batch_id) on delete cascade;

create index if not exists idx_events_batch    on events (batch_id);
create index if not exists idx_signals_batch   on signals (batch_id);
create index if not exists idx_alerts_batch    on alerts (batch_id);
create index if not exists idx_incidents_batch on incidents (batch_id);

-- ---------- (3) RLS : new table is read-only for the browser role ----
alter table ingest_batches enable row level security;
drop policy if exists read_ingest_batches on ingest_batches;
create policy read_ingest_batches on ingest_batches
  for select to anon, authenticated using (true);
