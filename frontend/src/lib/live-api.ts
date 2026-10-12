import { getActiveBatchId, type ActiveBatchId } from "@/lib/active-batch";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export interface BatchRow { batch_id:string; label:string|null; source_filename:string|null; created_at:string; event_count:number|null; incident_count:number|null; status:string|null; }
export interface AlertRow { alert_id:string; title:string; severity:Severity; confidence:number; detector:string|null; contributions:Record<string,number>; entity:string|null; event_ids:string[]; correlation_count:number; status:string; incident_id:string|null; batch_id:string|null; created_at:string; }
export interface IncidentRow { incident_id:string; code:string|null; title:string|null; risk_score:number; status:string; approval_state:string; mitre_techniques:string[]; summary:string|null; batch_id:string|null; created_at:string; updated_at:string; }
export interface IncidentEntityRow { incident_id:string; entity_type:string; entity_value:string; role:string|null; }
export interface EvidenceRow { evidence_id:string; incident_id:string; kind:string; source_event_ids:string[]; fact:string; provenance:string|null; confidence:number; created_at:string; }
export interface TimelineRow { id:number; incident_id:string; ts:string; label:string; event_id:string|null; evidence_id:string|null; }
export interface AttackKbRow { technique_id:string; name:string; tactic:string|null; description:string|null; }
export interface AgentRunRow { run_id:string; incident_id:string; agent:string; tools_used:string[]; citations:string[]; output:unknown; status:string; unsupported_claims:unknown[]; latency_ms:number|null; tokens:number|null; created_at:string; }
export interface ReportOutput { summary?:string; narrative?:string; recommended_actions?:string[]; }
export interface VerifierVerdict { hypothesis_id:string; supported:boolean; reason:string; }
export interface RejectedClaim { hypothesis_id?:string; statement?:string; reason?:string; }
export interface OverviewData { events:number; signals:number; alerts:number; incidents:number; rules:number; severity:{name:string;count:number}[]; sources:{name:string;count:number}[]; volume:{hour:string;count:number}[]; priority:IncidentRow[]; }
export interface AttackAssessment { hypothesis_id:string; statement:string; technique:string; confidence_pct:number; detector_component:number; entailment_component:number; basis:"behavioural"|"behavioural+annotation"|"annotation-only"; corroborated_by_detector:boolean; top_detector:string|null; cited_evidence:string[]; }

const BASE = String(import.meta.env["VITE_ANALYZE_API"] || "http://127.0.0.1:8787").replace(/\/$/, "");
async function get<T>(path:string):Promise<T> {
  const r = await fetch(`${BASE}${path}`, { cache:"no-store" });
  if (!r.ok) { const body = await r.json().catch(()=>({})); throw new Error(body.error || `Backend read failed (${r.status})`); }
  return r.json() as Promise<T>;
}
const batchQ = (batchId:ActiveBatchId) => `batchId=${encodeURIComponent(batchId)}`;

export async function fetchBatches():Promise<BatchRow[]> { return get("/api/data/batches"); }
export async function fetchAlerts(batchId:ActiveBatchId=getActiveBatchId()):Promise<AlertRow[]> { return get(`/api/data/alerts?${batchQ(batchId)}`); }
export async function fetchIncidents(batchId:ActiveBatchId=getActiveBatchId()):Promise<IncidentRow[]> { return get(`/api/data/incidents?${batchQ(batchId)}`); }
export async function fetchIncident(id:string):Promise<IncidentRow|null> { try { return await get(`/api/data/incidents/${encodeURIComponent(id)}`); } catch { return null; } }
export async function fetchIncidentEntities(id:string):Promise<IncidentEntityRow[]> { return get(`/api/data/incidents/${encodeURIComponent(id)}/entities`); }
export async function fetchEvidence(id:string):Promise<EvidenceRow[]> { return get(`/api/data/incidents/${encodeURIComponent(id)}/evidence`); }
export async function fetchTimeline(id:string):Promise<TimelineRow[]> { return get(`/api/data/incidents/${encodeURIComponent(id)}/timeline`); }
export async function fetchAgentRuns(id:string):Promise<AgentRunRow[]> { return get(`/api/data/incidents/${encodeURIComponent(id)}/agent-runs`); }
export async function fetchIncidentAlerts(id:string):Promise<AlertRow[]> { return get(`/api/data/alerts?incidentId=${encodeURIComponent(id)}`); }
export async function fetchAttackKb():Promise<Map<string,AttackKbRow>> { const data = await get<AttackKbRow[]>("/api/data/attack-kb"); return new Map(data.map(x=>[x.technique_id,x])); }
export async function fetchVerifierCounts(incidentIds:string[]):Promise<Map<string,{supported:number;rejected:number;assessment:AttackAssessment[]}>> {
  if (!incidentIds.length) return new Map();
  const raw = await get<Record<string,{supported:number;rejected:number;assessment:AttackAssessment[]}>>(`/api/data/verifier-counts?incidentIds=${encodeURIComponent(incidentIds.join(","))}`);
  return new Map(Object.entries(raw));
}
export async function fetchOverview(batchId:ActiveBatchId=getActiveBatchId()):Promise<OverviewData> { return get(`/api/data/overview?${batchQ(batchId)}`); }
export function latestRun(runs:AgentRunRow[], agent:string):AgentRunRow|undefined { return [...runs].filter(r=>r.agent===agent).sort((a,b)=>b.created_at.localeCompare(a.created_at))[0]; }
