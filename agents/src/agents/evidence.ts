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
import { DETECTOR_FAMILY, familiesOfTechniques, familyFromTitle } from '../mitre.js';
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
//
// Retrieval is incident-scoped first (via the incident's alert.event_ids). The
// entity-IP fallback exists for records with no alert grouping, and it narrows
// to the incident's own attack family before the model sees anything — see the
// comment at the narrowing block.
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
  // don't pull each other's flows.
  const eventIndex = new Map<string, EventRow>();
  const scoped = await getIncidentEvents(incidentId, 60);
  for (const r of scoped) eventIndex.set(r.event_id, r);

  let retrievalPath: 'incident-scoped' | 'entity-fallback' = 'incident-scoped';
  let narrowedFrom = 0;
  if (eventIndex.size === 0) {
    retrievalPath = 'entity-fallback';
    for (const e of entities) {
      if (e.entity_type !== 'ip' && e.entity_type !== 'src_ip' && e.entity_type !== 'dst_ip') continue;
      const rows = await queryEventsForEntity(e.entity_value, 40);
      for (const r of rows) eventIndex.set(r.event_id, r);
    }
  }

  // Signals are read for the CANDIDATE set (before any narrowing), because the
  // narrowing decision is made from detector output, not from the ip match.
  const candidates = [...eventIndex.values()];
  const candidateSignals = await getSignalsForEvents(candidates.map((e) => e.event_id));
  const signalsByEvent = new Map<string, SignalRow[]>();
  for (const s of candidateSignals) {
    const arr = signalsByEvent.get(s.event_id) ?? [];
    arr.push(s);
    signalsByEvent.set(s.event_id, arr);
  }

  // ---- fallback narrowing: keep only this incident's own attack family ------
  // `queryEventsForEntity` matches `src_ip = $1 OR dst_ip = $1`, so when two
  // incidents share an actor/target IP each one pulls the other's flows. The
  // incident's own technique (set by the detection plane at ingest) names the
  // family it is about; an event whose only behavioural signals belong to some
  // OTHER family is another incident's evidence, so it is dropped here. Without
  // this the model is shown port-80 flood flows while investigating a
  // brute-force incident and forms a technically-consistent-but-wrong claim.
  //
  // Deliberately fail-soft, not fail-closed: if the filter would empty the set
  // (e.g. the event carries no behavioural signal at all — an annotation-only
  // incident), the original events are kept and the degradation is logged
  // loudly. Emptying the evidence set would leave the incident uninvestigable,
  // and the verifier's consistency gate is the hard guarantee either way.
  if (retrievalPath === 'entity-fallback') {
    // Anchor on the incident TITLE first: it is the detection plane's own
    // statement of what this incident is, and `writeReport` never overwrites it.
    // `mitre_techniques` is the fallback only because the report writer DOES
    // overwrite that one with the verified technique — so on a re-run of an
    // already-misread incident it can echo the very error being corrected here.
    const byTitle = familyFromTitle(incident?.title);
    const families = byTitle
      ? new Set([byTitle])
      : familiesOfTechniques(incident?.mitre_techniques ?? []);
    if (families.size > 0) {
      const keep = new Set(
        candidates
          .filter((e) =>
            (signalsByEvent.get(e.event_id) ?? []).some(
              (s) => s.detector !== 'label' && families.has(DETECTOR_FAMILY[s.detector_ref]),
            ),
          )
          .map((e) => e.event_id),
      );
      if (keep.size === 0) {
        console.warn(
          `[evidence] ${incident?.code ?? incidentId}: entity-fallback narrowing found no ` +
            `event matching the incident's own families (${[...families].join(', ')}); ` +
            `keeping all ${candidates.length} entity-matched events (evidence may span scenarios)`,
        );
      } else if (keep.size < candidates.length) {
        narrowedFrom = candidates.length;
        for (const id of [...eventIndex.keys()]) if (!keep.has(id)) eventIndex.delete(id);
      }
    }
  }

  const events = [...eventIndex.values()];

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
    output: {
      evidence: kept,
      retrieval_path: retrievalPath,
      // Present only when the fallback's family narrowing actually dropped
      // events — so the audit shows what the model was NOT shown.
      ...(narrowedFrom > 0 ? { fallback_narrowed_from: narrowedFrom, fallback_kept: events.length } : {}),
    },
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
