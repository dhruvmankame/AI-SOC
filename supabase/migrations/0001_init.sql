-- =====================================================================
-- AI-SOC : initial schema (Day 1)
-- Target: Supabase Postgres. Run with: supabase db reset  (local)
--         or paste into the Supabase SQL editor (cloud).
-- Implements the OCSF-subset event model + detection/correlation/agent
-- tables from the blueprint (sections 8, 10.2, 13).
-- =====================================================================

create extension if not exists pgcrypto;   -- gen_random_uuid()
create extension if not exists vector;      -- pgvector, for ATT&CK / case RAG

-- ---------- enums -----------------------------------------------------
do $$ begin
  create type severity_t as enum ('info','low','medium','high','critical');
exception when duplicate_object then null; end $$;

do $$ begin
  create type incident_status_t as enum ('open','investigating','contained','closed','false_positive');
exception when duplicate_object then null; end $$;

do $$ begin
  create type approval_state_t as enum ('none','human_required','approved','rejected');
exception when duplicate_object then null; end $$;

-- ---------- Layer C: normalized telemetry (OCSF subset) ---------------
-- One immutable row per parsed+normalized event. §10.1 canonical fields.
create table if not exists events (
  event_id      uuid primary key default gen_random_uuid(),
  ts            timestamptz not null,              -- event time
  ingested_at   timestamptz not null default now(),
  source_type   text not null,                     -- auth|process|network|firewall|web|cloud
  vendor        text,
  product       text,
  -- classification
  class_uid     int,
  category      text,
  activity      text,
  severity      severity_t not null default 'info',
  outcome       text,                              -- success|failure|unknown
  -- entities
  "user"        text,
  host          text,
  src_ip        inet,
  dst_ip        inet,
  domain        text,
  process       text,
  file_hash     text,
  -- parsing
  template_id   text,
  template_text text,
  parser_confidence real,
  -- enrichment
  asset_criticality real default 0,
  ioc_matches   jsonb default '[]'::jsonb,
  mitre_tags    text[] default '{}',
  geo           jsonb,
  -- integrity / forensics
  raw           text,                              -- original line
  raw_hash      text,
  collector_id  text,
  -- ground truth (evaluation only; NULL in "production")
  gt_label      text,                              -- benign|attack
  gt_scenario   text                               -- e.g. password_spray
);
create index if not exists idx_events_ts        on events (ts);
create index if not exists idx_events_user       on events ("user");
create index if not exists idx_events_host       on events (host);
create index if not exists idx_events_src_ip     on events (src_ip);
create index if not exists idx_events_source_type on events (source_type);
create index if not exists idx_events_template   on events (template_id);

-- ---------- Layer D: raw detector outputs ----------------------------
-- Every detector (rule/ioc/stat/ml/ueba) writes a signal here.
create table if not exists signals (
  signal_id    uuid primary key default gen_random_uuid(),
  event_id     uuid references events(event_id) on delete cascade,
  detector     text not null,                      -- rule|ioc|statistical|supervised|deep_seq|ueba
  detector_ref text,                               -- rule name / model version
  score        real not null,                      -- 0..1 contribution
  reason       text,
  created_at   timestamptz not null default now()
);
create index if not exists idx_signals_event on signals (event_id);
create index if not exists idx_signals_detector on signals (detector);

-- ---------- Layer D: versioned detection rules -----------------------
create table if not exists detection_rules (
  rule_id     text primary key,                    -- e.g. R-AUTH-BRUTEFORCE
  title       text not null,
  detector    text not null default 'rule',
  logic       jsonb not null,                      -- portable predicate (compiled to SQL at runtime)
  mitre_tags  text[] default '{}',
  severity    severity_t not null default 'medium',
  enabled     boolean not null default true,
  version     int not null default 1,
  created_at  timestamptz not null default now()
);

-- ---------- Layer E: analyst-facing alerts (deduplicated) ------------
create table if not exists alerts (
  alert_id     uuid primary key default gen_random_uuid(),
  title        text not null,
  severity     severity_t not null default 'low',
  confidence   real not null default 0,
  detector     text,                               -- primary detector
  contributions jsonb default '{}'::jsonb,         -- {rule:.., deep:.., ueba:..} for "why"
  entity       text,                               -- primary affected entity
  event_ids    uuid[] default '{}',                -- source events
  correlation_count int default 1,
  status       text not null default 'new',        -- new|triaged|escalated|closed
  incident_id  uuid,                                -- set when correlated
  created_at   timestamptz not null default now()
);
create index if not exists idx_alerts_severity on alerts (severity);
create index if not exists idx_alerts_incident on alerts (incident_id);

-- ---------- Layer E: correlated incidents (cases) --------------------
-- Mirrors the shared incident-state contract in §8.
create table if not exists incidents (
  incident_id   uuid primary key default gen_random_uuid(),
  code          text unique,                        -- INC-2026-0042
  title         text,
  risk_score    real not null default 0,            -- 0..100 (risk fusion §9.3)
  risk_factors  jsonb default '{}'::jsonb,           -- per-component contributions
  status        incident_status_t not null default 'open',
  approval_state approval_state_t not null default 'none',
  mitre_techniques text[] default '{}',
  summary       text,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create table if not exists incident_entities (
  incident_id  uuid references incidents(incident_id) on delete cascade,
  entity_type  text not null,                       -- user|host|ip|domain|process
  entity_value text not null,
  role         text,                                -- source|target|actor
  primary key (incident_id, entity_type, entity_value)
);

-- ---------- Evidence (the core evidence-first contract §10.3) --------
create table if not exists evidence (
  evidence_id  text primary key,                    -- EV-81
  incident_id  uuid references incidents(incident_id) on delete cascade,
  kind         text not null,                       -- event|intel|derived
  source_event_ids uuid[] default '{}',
  fact         text not null,                       -- compact factual statement
  provenance   text,                                -- where it came from
  confidence   real default 1.0,
  created_at   timestamptz not null default now()
);
create index if not exists idx_evidence_incident on evidence (incident_id);

-- ---------- Layer F: agent audit (§8, §13.1) -------------------------
create table if not exists agent_runs (
  run_id       uuid primary key default gen_random_uuid(),
  incident_id  uuid references incidents(incident_id) on delete cascade,
  agent        text not null,                       -- orchestrator|evidence|timeline|...
  prompt_version text,
  tools_used   jsonb default '[]'::jsonb,
  citations    text[] default '{}',                 -- evidence_ids cited
  input_hash   text,
  output       jsonb,
  status       text,                                -- ok|rejected|error
  unsupported_claims jsonb default '[]'::jsonb,      -- verifier rejections
  latency_ms   int,
  tokens       int,
  created_at   timestamptz not null default now()
);
create index if not exists idx_agent_runs_incident on agent_runs (incident_id);

-- ---------- Timeline items (denormalized for the workbench) ----------
create table if not exists incident_timeline (
  id           bigserial primary key,
  incident_id  uuid references incidents(incident_id) on delete cascade,
  ts           timestamptz not null,
  label        text not null,
  event_id     uuid,
  evidence_id  text
);
create index if not exists idx_timeline_incident on incident_timeline (incident_id, ts);

-- ---------- ATT&CK knowledge base (pgvector RAG for agents) ----------
create table if not exists attack_kb (
  technique_id text primary key,                    -- T1110
  name         text not null,
  tactic       text,
  description  text,
  embedding    vector(384)                          -- filled offline (MiniLM etc.)
);

-- ---------- analyst feedback loop ------------------------------------
create table if not exists feedback (
  id          bigserial primary key,
  alert_id    uuid references alerts(alert_id) on delete cascade,
  label       text not null,                        -- tp|fp|correction
  note        text,
  created_at  timestamptz not null default now()
);

-- ---------- convenience view: events/sec per source -----------------
create or replace view v_ingest_rate as
select date_trunc('minute', ingested_at) as minute,
       source_type,
       count(*) as events
from events
group by 1,2
order by 1 desc;
