import { reason } from '../llm.js';
import { writeReport, insertTimeline, recordAgentRun } from '../tools.js';
import { ReportOut } from '../state.js';
import type { EvidenceItem, Hypothesis, EventRow } from '../state.js';

// ============================================================================
// Agent 4 — REPORT WRITER
// Builds the analyst-facing incident report from VERIFIED findings ONLY. It
// never sees the rejected hypotheses, so it structurally cannot narrate an
// unsupported claim. Writes incidents.summary, the deduped MITRE technique set,
// and a chronological timeline anchored to the cited events. Recommended
// actions are simulation-only.
// ============================================================================

const SYSTEM =
  'You are the Report Writer in a SOC pipeline. You are given ONLY the VERIFIED ' +
  'hypotheses and the evidence they cite. Write a concise analyst report. RULES: ' +
  '(1) assert nothing that is not backed by the supplied evidence; (2) put an ' +
  'inline [EV-x] citation next to every factual claim in the narrative; (3) the ' +
  'summary is 2-4 sentences for a SOC lead; (4) recommended actions are ' +
  'simulation-only steps an analyst would approve, never auto-executed. If the ' +
  'verified evidence is thin, say so plainly rather than inflating confidence.';

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
): Promise<ReportResult> {
  const t0 = Date.now();

  const citedEvIds = new Set(supported.flatMap((h) => h.citations));
  const usedEvidence = evidence.filter((e) => citedEvIds.has(e.evidence_id));

  const data = [
    'VERIFIED HYPOTHESES:',
    ...supported.map(
      (h) => `  ${h.id} [${h.technique}] (conf ${h.confidence}): ${h.statement}\n      cites: ${h.citations.join(', ')}`,
    ),
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
    output: parsed,
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
