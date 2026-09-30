// Row shapes for the tables/views the dashboard reads. Kept to the columns
// the UI actually uses — not a full mirror of the schema.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface AlertRow {
  alert_id: string
  title: string
  severity: Severity
  confidence: number
  detector: string | null
  contributions: Record<string, number>
  entity: string | null
  event_ids: string[]
  correlation_count: number
  status: string
  incident_id: string | null
  batch_id: string | null
  created_at: string
}

export interface EventRow {
  event_id: string
  ts: string
  source_type: string
  severity: Severity
  outcome: string | null
  user: string | null
  host: string | null
  src_ip: string | null
  mitre_tags: string[]
}

export interface OverviewStats {
  events: number
  signals: number
  alerts: number
  incidents: number
  rules: number
  sourceCounts: { source_type: string; count: number }[]
  severityCounts: { severity: Severity; count: number }[]
  ingest: { minute: string; count: number }[]
}

// ===========================================================================
// FROZEN READ CONTRACT — Incident Record (upload → detect → identify → record)
// These row shapes are the interface between the agent/analyze write path and
// the frontend read path; both sides build against them. Columns mirror the
// schema (0001_init.sql) + the batch_id added in 0003_batches.sql. Only the
// columns the UI reads are listed. agent_runs.output shapes match what each
// agent records (evidence.ts / hypothesis.ts / verifier.ts / report.ts).
// ===========================================================================

export type IncidentStatus =
  | 'open'
  | 'investigating'
  | 'contained'
  | 'closed'
  | 'false_positive'

// Each upload is one batch; seeded CICIDS rows have batch_id = NULL.
export interface BatchRow {
  batch_id: string
  label: string | null
  source_filename: string | null
  created_at: string
  event_count: number | null
  incident_count: number | null
  status: string | null
}

export interface IncidentRow {
  incident_id: string
  code: string | null
  title: string | null
  risk_score: number
  status: IncidentStatus
  approval_state: string
  mitre_techniques: string[]
  summary: string | null
  batch_id: string | null
  created_at: string
  updated_at: string
}

export interface IncidentEntityRow {
  incident_id: string
  entity_type: string // user|host|ip|domain|process
  entity_value: string
  role: string | null // source|target|actor|victim
}

export interface EvidenceRow {
  evidence_id: string // EV-<code>-<n>
  incident_id: string
  kind: string // event|intel|derived
  source_event_ids: string[] // cited event_ids (grounding)
  fact: string
  provenance: string | null
  confidence: number
  created_at: string
}

export interface TimelineRow {
  id: number
  incident_id: string
  ts: string
  label: string
  event_id: string | null
  evidence_id: string | null
}

export interface AttackKbRow {
  technique_id: string // T1110
  name: string
  tactic: string | null
  description: string | null
}

// ---- agent_runs (the audit trail) + its per-agent output payloads ---------

export interface VerifierVerdict {
  hypothesis_id: string
  supported: boolean
  reason: string
}

// One entry per rejected hypothesis, from verifier agent_runs.unsupported_claims.
export interface RejectedClaim {
  hypothesis_id: string
  statement: string
  reason: string
}

export interface ReportOutput {
  summary: string
  narrative: string
  recommended_actions: string[]
}

export interface AgentRunRow {
  run_id: string
  incident_id: string
  agent: string // evidence-collector|hypothesis-attack|verifier|report-writer
  tools_used: string[]
  citations: string[]
  output: unknown // shape depends on `agent` (see ReportOutput / verdicts / hypotheses)
  status: string // ok|partial|rejected|error
  unsupported_claims: unknown[] // verifier: RejectedClaim[]
  latency_ms: number | null
  tokens: number | null
  created_at: string
}
