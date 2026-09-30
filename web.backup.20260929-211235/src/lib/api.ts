import { supabase } from './supabase'
import type {
  AgentRunRow, AlertRow, AttackKbRow, BatchRow, EventRow, EvidenceRow,
  IncidentEntityRow, IncidentRow, OverviewStats, Severity, TimelineRow,
} from './types'

// ---------------------------------------------------------------------------
// Batch filter. Each upload is a batch; the seeded CICIDS demo has batch_id
// NULL. The UI selector passes one of: 'all' (no filter), 'seed' (batch_id IS
// NULL), or a batch uuid (batch_id = uuid). Applied to any query builder that
// exposes .eq/.is on batch_id.
// ---------------------------------------------------------------------------
export type BatchFilter = 'all' | 'seed' | (string & {})

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function applyBatch<T extends { eq: any; is: any }>(qb: T, batchId?: BatchFilter): T {
  if (!batchId || batchId === 'all') return qb
  if (batchId === 'seed') return qb.is('batch_id', null)
  return qb.eq('batch_id', batchId)
}

// ---- Batches ---------------------------------------------------------------
export async function fetchBatches(): Promise<BatchRow[]> {
  const { data, error } = await supabase
    .from('ingest_batches')
    .select('batch_id,label,source_filename,created_at,event_count,incident_count,status')
    .order('created_at', { ascending: false })
  if (error) throw error
  return (data ?? []) as BatchRow[]
}

// ---- Alert Queue -----------------------------------------------------------
export async function fetchAlerts(batchId?: BatchFilter): Promise<AlertRow[]> {
  const { data, error } = await applyBatch(
    supabase
      .from('alerts')
      .select('alert_id,title,severity,confidence,detector,contributions,entity,event_ids,correlation_count,status,incident_id,batch_id,created_at'),
    batchId,
  ).order('confidence', { ascending: false })
  if (error) throw error
  return (data ?? []) as AlertRow[]
}

// The source events behind one alert (evidence drill-down for the queue).
export async function fetchEventsByIds(ids: string[]): Promise<EventRow[]> {
  if (ids.length === 0) return []
  const { data, error } = await supabase
    .from('events')
    .select('event_id,ts,source_type,severity,outcome,user,host,src_ip,mitre_tags')
    .in('event_id', ids)
    .order('ts', { ascending: true })
  if (error) throw error
  return (data ?? []) as EventRow[]
}

// ---- Incidents -------------------------------------------------------------
export async function fetchIncidents(batchId?: BatchFilter): Promise<IncidentRow[]> {
  const { data, error } = await applyBatch(
    supabase
      .from('incidents')
      .select('incident_id,code,title,risk_score,status,approval_state,mitre_techniques,summary,batch_id,created_at,updated_at'),
    batchId,
  ).order('risk_score', { ascending: false })
  if (error) throw error
  return (data ?? []) as IncidentRow[]
}

export async function fetchIncident(id: string): Promise<IncidentRow | null> {
  const { data, error } = await supabase
    .from('incidents')
    .select('incident_id,code,title,risk_score,status,approval_state,mitre_techniques,summary,batch_id,created_at,updated_at')
    .eq('incident_id', id)
    .maybeSingle()
  if (error) throw error
  return (data as IncidentRow) ?? null
}

export async function fetchIncidentEntities(id: string): Promise<IncidentEntityRow[]> {
  const { data, error } = await supabase
    .from('incident_entities')
    .select('incident_id,entity_type,entity_value,role')
    .eq('incident_id', id)
  if (error) throw error
  return (data ?? []) as IncidentEntityRow[]
}

export async function fetchEvidence(id: string): Promise<EvidenceRow[]> {
  const { data, error } = await supabase
    .from('evidence')
    .select('evidence_id,incident_id,kind,source_event_ids,fact,provenance,confidence,created_at')
    .eq('incident_id', id)
    .order('created_at', { ascending: true })
  if (error) throw error
  return (data ?? []) as EvidenceRow[]
}

export async function fetchAgentRuns(id: string): Promise<AgentRunRow[]> {
  const { data, error } = await supabase
    .from('agent_runs')
    .select('run_id,incident_id,agent,tools_used,citations,output,status,unsupported_claims,latency_ms,tokens,created_at')
    .eq('incident_id', id)
    .order('created_at', { ascending: true })
  if (error) throw error
  return (data ?? []) as AgentRunRow[]
}

export async function fetchTimeline(id: string): Promise<TimelineRow[]> {
  const { data, error } = await supabase
    .from('incident_timeline')
    .select('id,incident_id,ts,label,event_id,evidence_id')
    .eq('incident_id', id)
    .order('ts', { ascending: true })
  if (error) throw error
  return (data ?? []) as TimelineRow[]
}

// ATT&CK KB is small and read-often → fetch once, index by technique_id.
export async function fetchAttackKb(): Promise<Map<string, AttackKbRow>> {
  const { data, error } = await supabase
    .from('attack_kb')
    .select('technique_id,name,tactic,description')
  if (error) throw error
  return new Map((data ?? []).map((r) => [r.technique_id, r as AttackKbRow]))
}

// Verifier verdicts for a set of incidents in ONE query (avoids N+1 on the
// Incidents list). Returns per-incident {supported, rejected} counts derived
// from the verifier agent_run (unsupported_claims = rejected hypotheses).
export async function fetchVerifierCounts(
  incidentIds: string[],
): Promise<Map<string, { supported: number; rejected: number }>> {
  const out = new Map<string, { supported: number; rejected: number }>()
  if (incidentIds.length === 0) return out
  const { data, error } = await supabase
    .from('agent_runs')
    .select('incident_id,agent,output,unsupported_claims')
    .eq('agent', 'verifier')
    .in('incident_id', incidentIds)
  if (error) throw error
  for (const r of (data ?? []) as { incident_id: string; output: unknown; unsupported_claims: unknown[] }[]) {
    const verdicts = Array.isArray(r.output) ? r.output : (r.output as { verdicts?: unknown[] })?.verdicts
    const supported = Array.isArray(verdicts)
      ? verdicts.filter((v) => (v as { supported?: boolean })?.supported).length
      : 0
    const rejected = Array.isArray(r.unsupported_claims) ? r.unsupported_claims.length : 0
    out.set(r.incident_id, { supported, rejected })
  }
  return out
}

// ---- Overview --------------------------------------------------------------
async function count(table: string, batchId?: BatchFilter): Promise<number> {
  const { count: c, error } = await applyBatch(
    supabase.from(table).select('*', { count: 'exact', head: true }),
    batchId,
  )
  if (error) throw error
  return c ?? 0
}

export async function fetchOverview(batchId?: BatchFilter): Promise<OverviewStats> {
  const [events, signals, alerts, incidents, rules] = await Promise.all([
    count('events', batchId), count('signals', batchId), count('alerts', batchId),
    count('incidents', batchId), count('detection_rules'), // rules are batch-independent
  ])

  // Pull the light columns we need to aggregate client-side (dataset is small).
  const { data: evRows, error } = await applyBatch(
    supabase.from('events').select('ts,source_type,severity'),
    batchId,
  )
  if (error) throw error

  const bySource = new Map<string, number>()
  const bySeverity = new Map<Severity, number>()
  const byMinute = new Map<string, number>()
  for (const r of (evRows ?? []) as { ts: string; source_type: string; severity: Severity }[]) {
    bySource.set(r.source_type, (bySource.get(r.source_type) ?? 0) + 1)
    bySeverity.set(r.severity, (bySeverity.get(r.severity) ?? 0) + 1)
    const m = r.ts.slice(0, 16) // yyyy-mm-ddThh:mm
    byMinute.set(m, (byMinute.get(m) ?? 0) + 1)
  }

  return {
    events, signals, alerts, incidents, rules,
    sourceCounts: [...bySource.entries()]
      .map(([source_type, c]) => ({ source_type, count: c }))
      .sort((a, b) => b.count - a.count),
    severityCounts: [...bySeverity.entries()].map(([severity, c]) => ({ severity, count: c })),
    ingest: [...byMinute.entries()]
      .map(([minute, c]) => ({ minute, count: c }))
      .sort((a, b) => a.minute.localeCompare(b.minute)),
  }
}
