import { q } from './db.js';
import type { Entity, EventRow, SignalRow, EvidenceItem } from './state.js';

// ============================================================================
// Investigation tools. READ tools are strict SELECTs (parameterised — no string
// interpolation of untrusted values). WRITE tools only touch the agent-output
// tables. This is the whole tool surface the agents are allowed to use.
// ============================================================================

// ---- READ ------------------------------------------------------------------

export async function getIncident(incidentId: string) {
  const rows = await q<{ incident_id: string; code: string; title: string; risk_score: number; mitre_techniques: string[] }>(
    `select incident_id, code, title, risk_score, mitre_techniques
       from incidents where incident_id = $1`,
    [incidentId],
  );
  return rows[0] ?? null;
}

export async function getIncidentEntities(incidentId: string): Promise<Entity[]> {
  return q<Entity>(
    `select entity_type, entity_value, role
       from incident_entities where incident_id = $1`,
    [incidentId],
  );
}

/** Events touching an IP entity (as source or destination), newest first, capped. */
export async function queryEventsForEntity(entityValue: string, limit = 40): Promise<EventRow[]> {
  return q<EventRow>(
    `select event_id, ts::text, host(src_ip) as src_ip, host(dst_ip) as dst_ip,
            severity::text, template_text, raw, mitre_tags
       from events
      where src_ip = $1::inet or dst_ip = $1::inet
      order by ts desc
      limit $2`,
    [entityValue, limit],
  );
}

/**
 * Events belonging to THIS incident, via the incident's alert(s) `event_ids`
 * set — newest first, capped. This is the principled retrieval path: it uses
 * the detection plane's own grouping (one alert per incident, event_ids scoped
 * to that incident's attack flows) instead of a raw src/dst IP match. It fixes
 * the cross-scenario leakage where two incidents sharing an actor/target IP
 * (e.g. brute-force + DDoS both hitting 192.168.10.50) pulled each other's
 * flows. Filtering with a subquery (not a join) dedupes at the event level and
 * keeps `order by ts desc` legal (no SELECT DISTINCT). Same select shape as
 * queryEventsForEntity so the EventRow typing is identical.
 */
export async function getIncidentEvents(incidentId: string, limit = 60): Promise<EventRow[]> {
  return q<EventRow>(
    `select event_id, ts::text, host(src_ip) as src_ip, host(dst_ip) as dst_ip,
            severity::text, template_text, raw, mitre_tags
       from events
      where event_id in (select unnest(event_ids) from alerts where incident_id = $1)
      order by ts desc
      limit $2`,
    [incidentId, limit],
  );
}

export async function getSignalsForEvents(eventIds: string[]): Promise<SignalRow[]> {
  if (eventIds.length === 0) return [];
  return q<SignalRow>(
    `select event_id, detector, detector_ref, score, reason
       from signals where event_id = any($1::uuid[])`,
    [eventIds],
  );
}

/** Lightweight ATT&CK KB retrieval (keyword ILIKE; pgvector optional/future). */
export async function searchAttackKb(terms: string[]) {
  if (terms.length === 0) return [];
  const like = terms.map((t) => `%${t.replace(/[%_]/g, '')}%`);
  return q<{ technique_id: string; name: string; tactic: string; description: string }>(
    `select technique_id, name, tactic, description
       from attack_kb
      where technique_id = any($1) or name ilike any($2) or description ilike any($2)
      limit 8`,
    [terms, like],
  );
}

// ---- WRITE (agent outputs only) --------------------------------------------

export async function insertEvidence(items: (EvidenceItem & { incident_id: string })[]) {
  for (const e of items) {
    await q(
      `insert into evidence (evidence_id, incident_id, kind, source_event_ids, fact, provenance, confidence)
       values ($1,$2,$3,$4::uuid[],$5,$6,$7)
       on conflict (evidence_id) do update set fact = excluded.fact`,
      [e.evidence_id, e.incident_id, e.kind, e.source_event_ids, e.fact, 'agent:evidence-collector', e.confidence],
    );
  }
}

export async function insertTimeline(
  incidentId: string,
  items: { ts: string; label: string; evidence_id?: string }[],
) {
  for (const t of items) {
    await q(
      `insert into incident_timeline (incident_id, ts, label, evidence_id) values ($1,$2,$3,$4)`,
      [incidentId, t.ts, t.label, t.evidence_id ?? null],
    );
  }
}

export async function writeReport(
  incidentId: string,
  summary: string,
  mitreTechniques: string[],
) {
  await q(
    `update incidents
        set summary = $2, mitre_techniques = $3, status = 'investigating', updated_at = now()
      where incident_id = $1`,
    [incidentId, summary, mitreTechniques],
  );
}

export async function recordAgentRun(row: {
  incident_id: string;
  agent: string;
  tools_used: string[];
  citations: string[];
  output: unknown;
  status: string;
  unsupported_claims: unknown[];
  latency_ms: number;
  tokens: number;
}) {
  await q(
    `insert into agent_runs
       (incident_id, agent, tools_used, citations, output, status, unsupported_claims, latency_ms, tokens)
     values ($1,$2,$3::jsonb,$4,$5::jsonb,$6,$7::jsonb,$8,$9)`,
    [
      row.incident_id,
      row.agent,
      JSON.stringify(row.tools_used),
      row.citations,
      JSON.stringify(row.output),
      row.status,
      JSON.stringify(row.unsupported_claims),
      row.latency_ms,
      row.tokens,
    ],
  );
}
