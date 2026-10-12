import { reason } from '../llm.js';
import { searchAttackKb, recordAgentRun } from '../tools.js';
import { HypothesisOut } from '../state.js';
import type { EvidenceItem, Hypothesis } from '../state.js';

// ============================================================================
// Agent 2 — HYPOTHESIS / ATT&CK
// Reasons ONLY over the evidence facts the collector grounded, retrieves the
// relevant ATT&CK techniques (lightweight keyword RAG over attack_kb), and
// proposes investigative hypotheses. Every hypothesis must cite the evidence
// ids that support it — uncited hypotheses are meaningless to the Verifier.
// ============================================================================

const SYSTEM =
  'You are the Hypothesis & ATT&CK analyst in a SOC pipeline. You are given a set ' +
  'of grounded EVIDENCE facts (each with an evidence_id like EV-INC-2017-0001-3) ' +
  'and a slice of the MITRE ATT&CK knowledge base. Propose the most likely ' +
  'investigative conclusions about what happened. RULES: (1) reason ONLY from the ' +
  'listed evidence — never introduce facts that are not there; (2) every ' +
  'hypothesis MUST cite the evidence_id(s) that support it; (3) map each to the ' +
  'single best-fitting ATT&CK technique id from the provided KB; (4) recommended ' +
  'actions are simulation-only analyst steps. Fewer, well-supported hypotheses ' +
  'are better than many speculative ones.';

export interface HypothesisResult {
  hypotheses: Hypothesis[];
  tokens: number;
}

export async function runHypothesisAgent(
  incidentId: string,
  incidentCode: string,
  evidence: EvidenceItem[],
  seedTechniques: string[],
): Promise<HypothesisResult> {
  const t0 = Date.now();

  // RAG: retrieve KB entries by the incident's seed techniques + evidence keywords.
  const terms = uniq([
    ...seedTechniques,
    ...keywordsFrom(evidence.map((e) => e.fact).join(' ')),
  ]);
  const kb = await searchAttackKb(terms);

  const data = [
    'EVIDENCE:',
    ...evidence.map((e) => `  ${e.evidence_id} (${e.kind}, conf ${e.confidence}): ${e.fact}`),
    '',
    'ATT&CK KB:',
    ...kb.map((k) => `  ${k.technique_id} ${k.name} [${k.tactic}]: ${k.description}`),
  ].join('\n');

  const { parsed, tokens } = await reason({
    schema: HypothesisOut,
    system: SYSTEM,
    data,
    name: 'form_hypotheses',
  });

  // Preserve every proposed citation so the verifier can reject mixed real and
  // invented IDs rather than silently laundering the claim's grounding.
  const hypotheses: Hypothesis[] = parsed.hypotheses.map((h, i) => ({
    id: `H-${incidentCode}-${i + 1}`,
    statement: h.statement,
    technique: h.technique,
    citations: h.citations,
    confidence: h.confidence,
    recommended_actions: h.recommended_actions,
  }));

  await recordAgentRun({
    incident_id: incidentId,
    agent: 'hypothesis-attack',
    tools_used: ['searchAttackKb'],
    citations: hypotheses.flatMap((h) => h.citations),
    output: { hypotheses, kb_techniques: kb.map((k) => k.technique_id) },
    status: 'ok',
    unsupported_claims: [],
    latency_ms: Date.now() - t0,
    tokens,
  });

  return { hypotheses, tokens };
}

function keywordsFrom(text: string): string[] {
  const stop = new Set(['flows', 'flow', 'host', 'from', 'with', 'this', 'that', 'were', 'made', 'over', 'port', 'detector']);
  return uniq(
    (text.toLowerCase().match(/[a-z]{4,}/g) ?? []).filter((w) => !stop.has(w)),
  ).slice(0, 6);
}

function uniq<T>(xs: T[]): T[] {
  return [...new Set(xs)];
}
