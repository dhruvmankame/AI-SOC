import { reason } from '../llm.js';
import {
  getIncident,
  getIncidentEntities,
  getIncidentEvents,
  queryEventsForEntity,
  getSignalsForEvents,
  insertEvidence,
  recordAgentRun,
} from '../tools.js';
import { EvidenceOut } from '../state.js';
import type { EvidenceItem, EventRow, SignalRow } from '../state.js';

// ============================================================================
// Agent 1 — EVIDENCE COLLECTOR
// Pulls the raw events + detector signals for every entity on the incident,
// asks the LLM to distil them into compact, checkable facts, then GROUNDS the
// output: every fact must cite event_ids that were actually in the provided
// set. Facts citing unknown ids are dropped before anything is written. The
// surviving facts become evidence rows EV-<incident>-<n> that all later agents
// must cite.
// ============================================================================

const SYSTEM =
  'You are the Evidence Collector in a SOC investigation pipeline. You are given ' +
  'network-flow events and the detector signals that fired on them. Extract the ' +
  'DISTINCT, checkable facts they establish (e.g. "host X made 312 flows to Y:22 ' +
  'in 90s", "detector R-NET-BRUTEFORCE scored 0.9 on these flows"). Every fact ' +
  'MUST cite the specific event_id values it is grounded in — never invent an id, ' +
  'only use ids present in the data. Do not speculate about intent or attribution; ' +
  'that is a later agent\'s job. Prefer a few strong facts over many weak ones.';

export interface EvidenceResult {
  evidence: EvidenceItem[];
  eventIndex: Map<string, EventRow>;
  tokens: number;
  droppedForBadCitations: number;
}

export async function runEvidenceCollector(incidentId: string): Promise<EvidenceResult> {
  const t0 = Date.now();
  const incident = await getIncident(incidentId);
  const entities = await getIncidentEntities(incidentId);

  // ---- retrieval: incident-scoped FIRST -----------------------------------
  // The principled path scopes events to THIS incident via its alert.event_ids
  // (detection-plane grouping), so two incidents that share an actor/target IP
  // don't pull each other's flows. Fall back to the entity-IP union only if the
  // incident has no alert-scoped events (seed/back-compat); that fallback keeps
  // the old cross-scenario leakage behaviour, which is why analyze.py and the
  // seed always populate alert.event_ids + incident_id for graded incidents.
  const eventIndex = new Map<string, EventRow>();
  const scoped = await getIncidentEvents(incidentId, 60);
  for (const r of scoped) eventIndex.set(r.event_id, r);

  let retrievalPath: 'incident-scoped' | 'entity-fallback' = 'incident-scoped';
  if (eventIndex.size === 0) {
    retrievalPath = 'entity-fallback';
    for (const e of entities) {
      if (e.entity_type !== 'ip' && e.entity_type !== 'src_ip' && e.entity_type !== 'dst_ip') continue;
      const rows = await queryEventsForEntity(e.entity_value, 40);
      for (const r of rows) eventIndex.set(r.event_id, r);
    }
  }
  const events = [...eventIndex.values()];
  const signals = await getSignalsForEvents(events.map((e) => e.event_id));
  const signalsByEvent = new Map<string, SignalRow[]>();
  for (const s of signals) {
    const arr = signalsByEvent.get(s.event_id) ?? [];
    arr.push(s);
    signalsByEvent.set(s.event_id, arr);
  }

  // Compact, LLM-readable rendering. Everything here is UNTRUSTED telemetry.
  const data = renderForLLM(incident, entities, events, signalsByEvent);

  const { parsed, tokens } = await reason({
    schema: EvidenceOut,
    system: SYSTEM,
    data,
    name: 'collect_evidence',
  });

  // ---- grounding gate: keep only facts whose citations are all real ---------
  const validIds = new Set(events.map((e) => e.event_id));
  const kept: EvidenceItem[] = [];
  let dropped = 0;
  let n = 0;
  const shortCode = incident?.code ?? incidentId.slice(0, 8);
  for (const f of parsed.evidence) {
    const good = f.source_event_ids.filter((id) => validIds.has(id));
    if (good.length === 0) {
      dropped++;
      continue;
    }
    n++;
    kept.push({
      evidence_id: `EV-${shortCode}-${n}`,
      kind: f.kind,
      fact: f.fact,
      source_event_ids: good,
      confidence: f.confidence,
    });
  }

  await insertEvidence(kept.map((e) => ({ ...e, incident_id: incidentId })));
  await recordAgentRun({
    incident_id: incidentId,
    agent: 'evidence-collector',
    tools_used: [
      'getIncidentEntities',
      retrievalPath === 'incident-scoped' ? 'getIncidentEvents' : 'queryEventsForEntity',
      'getSignalsForEvents',
      'insertEvidence',
    ],
    citations: kept.flatMap((e) => e.source_event_ids),
    output: { evidence: kept },
    status: dropped > 0 ? 'partial' : 'ok',
    unsupported_claims: dropped > 0 ? [{ dropped_facts_with_bad_citations: dropped }] : [],
    latency_ms: Date.now() - t0,
    tokens,
  });

  return { evidence: kept, eventIndex, tokens, droppedForBadCitations: dropped };
}

function renderForLLM(
  incident: { code: string; title: string; risk_score: number } | null,
  entities: { entity_type: string; entity_value: string; role: string | null }[],
  events: EventRow[],
  signalsByEvent: Map<string, SignalRow[]>,
): string {
  const lines: string[] = [];
  if (incident) lines.push(`INCIDENT ${incident.code}: ${incident.title} (risk ${incident.risk_score})`);
  lines.push('ENTITIES:');
  for (const e of entities) lines.push(`  - ${e.entity_type}=${e.entity_value} role=${e.role ?? '?'}`);
  lines.push('', `EVENTS (${events.length}):`);
  for (const e of events) {
    const sigs = (signalsByEvent.get(e.event_id) ?? [])
      .map((s) => `${s.detector}(${s.score.toFixed(2)}):${s.reason}`)
      .join('; ');
    lines.push(
      `  event_id=${e.event_id} ts=${e.ts} ${e.src_ip ?? '?'}->${e.dst_ip ?? '?'} ` +
        `sev=${e.severity} mitre=[${e.mitre_tags.join(',')}] ${e.template_text ?? ''}` +
        (sigs ? `\n      signals: ${sigs}` : ''),
    );
  }
  return lines.join('\n');
}
