import { getActiveBatchId, type ActiveBatchId } from "@/lib/active-batch";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface BatchRow {
  batch_id: string;
  label: string | null;
  source_filename: string | null;
  created_at: string;
  event_count: number | null;
  incident_count: number | null;
  status: string | null;
}

export interface AlertRow {
  alert_id: string;
  title: string;
  severity: Severity;
  confidence: number;
  detector: string | null;
  contributions: Record<string, number>;
  entity: string | null;
  event_ids: string[];
  correlation_count: number;
  status: string;
  incident_id: string | null;
  batch_id: string | null;
  created_at: string;
}

export interface IncidentRow {
  incident_id: string;
  code: string | null;
  title: string | null;
  risk_score: number;
  status: string;
  approval_state: string;
  mitre_techniques: string[];
  summary: string | null;
  batch_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface IncidentEntityRow {
  incident_id: string;
  entity_type: string;
  entity_value: string;
  role: string | null;
}

export interface EvidenceRow {
  evidence_id: string;
  incident_id: string;
  kind: string;
  source_event_ids: string[];
  fact: string;
  provenance: string | null;
  confidence: number;
  created_at: string;
}

export interface TimelineRow {
  id: number;
  incident_id: string;
  ts: string;
  label: string;
  event_id: string | null;
  evidence_id: string | null;
}

export interface AttackKbRow {
  technique_id: string;
  name: string;
  tactic: string | null;
  description: string | null;
}

export interface AgentRunRow {
  run_id: string;
  incident_id: string;
  agent: string;
  tools_used: string[];
  citations: string[];
  output: unknown;
  status: string;
  unsupported_claims: unknown[];
  latency_ms: number | null;
  tokens: number | null;
  created_at: string;
}

export interface ReportOutput {
  summary?: string;
  narrative?: string;
  recommended_actions?: string[];
}

export interface VerifierVerdict {
  hypothesis_id: string;
  supported: boolean;
  reason: string;
}

export interface RejectedClaim {
  hypothesis_id?: string;
  statement?: string;
  reason?: string;
}

export interface OverviewData {
  events: number;
  signals: number;
  alerts: number;
  incidents: number;
  rules: number;
  severity: { name: string; count: number }[];
  sources: { name: string; count: number }[];
  volume: { hour: string; count: number }[];
  priority: IncidentRow[];
}

const BASE = String(import.meta.env["VITE_SUPABASE_URL"] ?? "").replace(/\/$/, "");
const KEY = String(import.meta.env["VITE_SUPABASE_ANON_KEY"] ?? "");

function configError(): Error {
  return new Error(
    "Live data is not configured. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in web/.env.local, then restart the frontend.",
  );
}

function headers(extra: Record<string, string> = {}): Record<string, string> {
  if (!BASE || !KEY) throw configError();
  return { apikey: KEY, Authorization: `Bearer ${KEY}`, ...extra };
}

async function checked(response: Response): Promise<Response> {
  if (response.ok) return response;
  const text = await response.text().catch(() => "");
  throw new Error(`Supabase read failed (${response.status})${text ? `: ${text.slice(0, 240)}` : ""}`);
}

function makeUrl(table: string, params: URLSearchParams): string {
  if (!BASE || !KEY) throw configError();
  return `${BASE}/rest/v1/${table}?${params.toString()}`;
}

function datasetFilter(batchId: ActiveBatchId = getActiveBatchId()): Record<string, string> {
  return batchId === "seed" ? { batch_id: "is.null" } : { batch_id: `eq.${batchId}` };
}

async function rows<T>(
  table: string,
  select: string,
  filters: Record<string, string> = {},
  order?: string,
): Promise<T[]> {
  const params = new URLSearchParams({ select });
  for (const [key, value] of Object.entries(filters)) params.set(key, value);
  if (order) params.set("order", order);
  const response = await checked(await fetch(makeUrl(table, params), { headers: headers(), cache: "no-store" }));
  return (await response.json()) as T[];
}

async function allRows<T>(
  table: string,
  select: string,
  filters: Record<string, string> = {},
): Promise<T[]> {
  const out: T[] = [];
  const pageSize = 1000;
  for (let start = 0; ; start += pageSize) {
    const params = new URLSearchParams({ select });
    for (const [key, value] of Object.entries(filters)) params.set(key, value);
    const response = await checked(
      await fetch(makeUrl(table, params), {
        headers: headers({ Range: `${start}-${start + pageSize - 1}` }),
        cache: "no-store",
      }),
    );
    const page = (await response.json()) as T[];
    out.push(...page);
    if (page.length < pageSize) break;
    if (start > 50000) break;
  }
  return out;
}

async function count(table: string, filters: Record<string, string> = {}): Promise<number> {
  const params = new URLSearchParams({ select: "*" });
  for (const [key, value] of Object.entries(filters)) params.set(key, value);
  const response = await checked(
    await fetch(makeUrl(table, params), {
      headers: headers({ Prefer: "count=exact", Range: "0-0" }),
      cache: "no-store",
    }),
  );
  const contentRange = response.headers.get("content-range") ?? "";
  const total = Number(contentRange.split("/")[1]);
  if (Number.isFinite(total)) return total;
  const body = (await response.json()) as unknown[];
  return body.length;
}

export async function fetchBatches(): Promise<BatchRow[]> {
  return rows<BatchRow>(
    "ingest_batches",
    "batch_id,label,source_filename,created_at,event_count,incident_count,status",
    {},
    "created_at.desc",
  );
}

export async function fetchAlerts(batchId: ActiveBatchId = getActiveBatchId()): Promise<AlertRow[]> {
  return rows<AlertRow>(
    "alerts",
    "alert_id,title,severity,confidence,detector,contributions,entity,event_ids,correlation_count,status,incident_id,batch_id,created_at",
    datasetFilter(batchId),
    "created_at.desc",
  );
}

export async function fetchIncidents(batchId: ActiveBatchId = getActiveBatchId()): Promise<IncidentRow[]> {
  return rows<IncidentRow>(
    "incidents",
    "incident_id,code,title,risk_score,status,approval_state,mitre_techniques,summary,batch_id,created_at,updated_at",
    datasetFilter(batchId),
    "created_at.desc",
  );
}

export async function fetchIncident(id: string): Promise<IncidentRow | null> {
  const found = await rows<IncidentRow>(
    "incidents",
    "incident_id,code,title,risk_score,status,approval_state,mitre_techniques,summary,batch_id,created_at,updated_at",
    { incident_id: `eq.${id}` },
  );
  return found[0] ?? null;
}

export async function fetchIncidentEntities(id: string): Promise<IncidentEntityRow[]> {
  return rows<IncidentEntityRow>(
    "incident_entities",
    "incident_id,entity_type,entity_value,role",
    { incident_id: `eq.${id}` },
  );
}

export async function fetchEvidence(id: string): Promise<EvidenceRow[]> {
  return rows<EvidenceRow>(
    "evidence",
    "evidence_id,incident_id,kind,source_event_ids,fact,provenance,confidence,created_at",
    { incident_id: `eq.${id}` },
    "created_at.asc",
  );
}

export async function fetchTimeline(id: string): Promise<TimelineRow[]> {
  return rows<TimelineRow>(
    "incident_timeline",
    "id,incident_id,ts,label,event_id,evidence_id",
    { incident_id: `eq.${id}` },
    "ts.asc",
  );
}

export async function fetchAgentRuns(id: string): Promise<AgentRunRow[]> {
  return rows<AgentRunRow>(
    "agent_runs",
    "run_id,incident_id,agent,tools_used,citations,output,status,unsupported_claims,latency_ms,tokens,created_at",
    { incident_id: `eq.${id}` },
    "created_at.asc",
  );
}

export async function fetchIncidentAlerts(id: string): Promise<AlertRow[]> {
  return rows<AlertRow>(
    "alerts",
    "alert_id,title,severity,confidence,detector,contributions,entity,event_ids,correlation_count,status,incident_id,batch_id,created_at",
    { incident_id: `eq.${id}` },
    "created_at.desc",
  );
}

export async function fetchAttackKb(): Promise<Map<string, AttackKbRow>> {
  const data = await rows<AttackKbRow>("attack_kb", "technique_id,name,tactic,description");
  return new Map(data.map((item) => [item.technique_id, item]));
}

export interface AttackAssessment {
  hypothesis_id: string;
  statement: string;
  technique: string;
  confidence_pct: number;
  detector_component: number;
  entailment_component: number;
  basis: "behavioural" | "behavioural+annotation" | "annotation-only";
  corroborated_by_detector: boolean;
  top_detector: string | null;
  cited_evidence: string[];
}

export async function fetchVerifierCounts(
  incidentIds: string[],
): Promise<Map<string, { supported: number; rejected: number; assessment: AttackAssessment[] }>> {
  if (incidentIds.length === 0) return new Map();
  const wanted = new Set(incidentIds);
  const runs = await rows<{
    incident_id: string;
    output: { verdicts?: VerifierVerdict[]; attack_assessment?: AttackAssessment[] } | null;
    unsupported_claims: RejectedClaim[] | null;
    created_at: string;
  }>(
    "agent_runs",
    "incident_id,output,unsupported_claims,created_at",
    { agent: "eq.verifier" },
    "created_at.desc",
  );
  const out = new Map<string, { supported: number; rejected: number; assessment: AttackAssessment[] }>();
  for (const run of runs) {
    if (!wanted.has(run.incident_id) || out.has(run.incident_id)) continue;
    const verdicts = Array.isArray(run.output?.verdicts) ? run.output!.verdicts! : [];
    out.set(run.incident_id, {
      supported: verdicts.filter((v) => v.supported).length,
      rejected: Array.isArray(run.unsupported_claims) ? run.unsupported_claims.length : 0,
      assessment: Array.isArray(run.output?.attack_assessment) ? run.output!.attack_assessment! : [],
    });
  }
  return out;
}

export async function fetchOverview(batchId: ActiveBatchId = getActiveBatchId()): Promise<OverviewData> {
  const filter = datasetFilter(batchId);
  const [events, signals, alerts, incidents, rules, eventRows, incidentRows] = await Promise.all([
    count("events", filter),
    count("signals", filter),
    count("alerts", filter),
    count("incidents", filter),
    count("detection_rules"),
    allRows<{ ts: string; source_type: string; severity: string }>("events", "ts,source_type,severity", filter),
    fetchIncidents(batchId),
  ]);

  const sev = new Map<string, number>();
  const src = new Map<string, number>();
  const hour = new Map<string, number>();
  for (const event of eventRows) {
    sev.set(event.severity, (sev.get(event.severity) ?? 0) + 1);
    src.set(event.source_type, (src.get(event.source_type) ?? 0) + 1);
    const key = String(event.ts).replace("T", " ").slice(0, 13) + ":00";
    hour.set(key, (hour.get(key) ?? 0) + 1);
  }

  const volume = [...hour.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .slice(-24)
    .map(([h, c]) => ({ hour: h, count: c }));

  return {
    events,
    signals,
    alerts,
    incidents,
    rules,
    severity: [...sev.entries()].map(([name, c]) => ({ name, count: c })),
    sources: [...src.entries()].map(([name, c]) => ({ name, count: c })).sort((a, b) => b.count - a.count),
    volume,
    priority: [...incidentRows].sort((a, b) => b.risk_score - a.risk_score).slice(0, 6),
  };
}

export function latestRun(runs: AgentRunRow[], agent: string): AgentRunRow | undefined {
  return [...runs]
    .filter((run) => run.agent === agent)
    .sort((a, b) => b.created_at.localeCompare(a.created_at))[0];
}
