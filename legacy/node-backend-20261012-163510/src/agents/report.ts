import { reason } from '../llm.js';
import { writeReport, insertTimeline, recordAgentRun } from '../tools.js';
import { ReportOut } from '../state.js';
import type { EvidenceItem, Hypothesis, EventRow, AttackAssessment } from '../state.js';

// ============================================================================
// Agent 4 — REPORT WRITER
// Builds the analyst-facing incident report from VERIFIED findings ONLY. It
// never sees the rejected hypotheses, so it structurally cannot narrate an
// unsupported claim. It is also handed Stage 3's confidence assessment and must
// report each claim's percentage AND its basis — so an annotation-only finding
// reads as "the dataset labelled this" rather than "we detected this". Writes
// incidents.summary, the deduped MITRE technique set, and a chronological
// timeline anchored to the cited events. Recommended actions are
// simulation-only.
// ============================================================================

const SYSTEM =
  'You are the Report Writer in a SOC pipeline. You are given ONLY the VERIFIED ' +
  'hypotheses, the evidence they cite, and a confidence assessment for each. RULES: ' +
  '(1) assert nothing that is not backed by the supplied evidence; (2) put an ' +
  'inline [EV-x] citation next to every factual claim in the narrative; (3) state ' +
  'each attack\'s confidence percentage, and when its basis is "annotation-only" say ' +
  'plainly that it rests on the dataset\'s own label and was NOT confirmed by an ' +
  'independent detector; (4) the summary is 2-4 sentences for a SOC lead; ' +
  '(5) recommended actions are simulation-only steps an analyst would approve, never ' +
  'auto-executed. If the verified evidence is thin, say so plainly rather than ' +
  'inflating confidence.';

export interface ReportResult {
  summary: string;
  narrative: string;
  recommended_actions: string[];
  tokens: number;
}

export async function runReportWriter(
  incidentId: string,
  supported: Hypothesis[],
  evidence: EvidenceItem[],
  eventIndex: Map<string, EventRow>,
  assessment: AttackAssessment[] = [],
): Promise<ReportResult> {
  const t0 = Date.now();
  if (supported.length === 0) throw new Error('report requires at least one verified finding');

  const citedEvIds = new Set(supported.flatMap((h) => h.citations));
  const usedEvidence = evidence.filter((e) => citedEvIds.has(e.evidence_id));
  const scoreById = new Map(assessment.map((a) => [a.hypothesis_id, a]));

  const data = [
    'VERIFIED HYPOTHESES:',
    ...supported.map((h) => {
      const a = scoreById.get(h.id);
      const score = a
        ? `\n      confidence: ${a.confidence_pct}% (basis: ${a.basis}` +
          `${a.corroborated_by_detector ? `, corroborated by detector ${a.top_detector}` : ', NOT corroborated by any independent detector'})`
        : '';
      return `  ${h.id} [${h.technique}] (conf ${h.confidence}): ${h.statement}\n      cites: ${h.citations.join(', ')}${score}`;
    }),
    '',
    'EVIDENCE:',
    ...usedEvidence.map((e) => `  ${e.evidence_id}: ${e.fact}`),
  ].join('\n');

  const { parsed, tokens } = await reason({
    schema: ReportOut,
    system: SYSTEM,
    data,
    name: 'write_report',
  });

  const techniques = uniq(supported.map((h) => h.technique).filter(Boolean));
  await writeReport(incidentId, parsed.summary, techniques);

  // Timeline: one entry per used evidence fact, anchored to its earliest event ts.
  const timeline = usedEvidence
    .map((e) => {
      const tss = e.source_event_ids
        .map((id) => eventIndex.get(id)?.ts)
        .filter((x): x is string => !!x)
        .sort();
      return { ts: tss[0] ?? new Date().toISOString(), label: e.fact, evidence_id: e.evidence_id };
    })
    .sort((a, b) => a.ts.localeCompare(b.ts));
  if (timeline.length > 0) await insertTimeline(incidentId, timeline);

  await recordAgentRun({
    incident_id: incidentId,
    agent: 'report-writer',
    tools_used: ['writeReport', 'insertTimeline'],
    citations: supported.flatMap((h) => h.citations),
    output: { ...parsed, attack_assessment: assessment },
    status: 'ok',
    unsupported_claims: [],
    latency_ms: Date.now() - t0,
    tokens,
  });

  return { ...parsed, tokens };
}

function uniq<T>(xs: T[]): T[] {
  return [...new Set(xs)];
}
