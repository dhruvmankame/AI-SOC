import { reason } from '../llm.js';
import { recordAgentRun } from '../tools.js';
import { VerifierOut } from '../state.js';
import type { EvidenceItem, Hypothesis, Verdict } from '../state.js';

// ============================================================================
// Agent 3 — VERIFIER / CRITIC  (the graded centrepiece)
// Two-stage adversarial check on every hypothesis:
//   (A) DETERMINISTIC gate — a hypothesis with no citations, or whose citations
//       don't all resolve to real evidence, is rejected in code. No LLM can
//       argue its way past this.
//   (B) LLM ENTAILMENT check — for the survivors, the model is shown ONLY the
//       cited evidence and asked whether it genuinely supports the statement.
// A hypothesis is "supported" only if it passes BOTH. Everything rejected is
// written to agent_runs.unsupported_claims so the audit trail shows what the
// pipeline refused to assert.
// ============================================================================

const SYSTEM =
  'You are the Verifier in a SOC pipeline — a strict, adversarial fact-checker. ' +
  'For each hypothesis you are given its statement and the FULL TEXT of ONLY the ' +
  'evidence it cited. Decide supported=true ONLY if that cited evidence, on its ' +
  'own, genuinely establishes the statement. Reject (supported=false) if the ' +
  'evidence is unrelated, too weak, or the statement over-claims beyond what the ' +
  'evidence shows (e.g. asserting attribution or intent the evidence does not ' +
  'prove). Name the specific failing citation in your reason. Do not be charitable; ' +
  'an uncited or under-supported claim must fail.';

export interface VerifierResult {
  verdicts: Verdict[];
  supported: Hypothesis[];
  rejected: { hypothesis: Hypothesis; reason: string }[];
  tokens: number;
}

export async function runVerifier(
  incidentId: string,
  hypotheses: Hypothesis[],
  evidence: EvidenceItem[],
): Promise<VerifierResult> {
  const t0 = Date.now();
  const evById = new Map(evidence.map((e) => [e.evidence_id, e]));

  // ---- (A) deterministic gate ----------------------------------------------
  const deterministic = new Map<string, string | null>(); // hyp id -> failure reason (null = passed gate)
  for (const h of hypotheses) {
    if (h.citations.length === 0) {
      deterministic.set(h.id, 'no citations — claim is ungrounded');
    } else if (!h.citations.every((c) => evById.has(c))) {
      const bad = h.citations.filter((c) => !evById.has(c));
      deterministic.set(h.id, `citations do not resolve to evidence: ${bad.join(', ')}`);
    } else {
      deterministic.set(h.id, null);
    }
  }

  const gatePassed = hypotheses.filter((h) => deterministic.get(h.id) === null);

  // ---- (B) LLM entailment check on survivors --------------------------------
  let llmVerdicts: { hypothesis_id: string; supported: boolean; reason: string }[] = [];
  let tokens = 0;
  if (gatePassed.length > 0) {
    const data = gatePassed
      .map((h) => {
        const cited = h.citations
          .map((c) => `      ${c}: ${evById.get(c)!.fact}`)
          .join('\n');
        return `HYPOTHESIS ${h.id} (technique ${h.technique}):\n  statement: ${h.statement}\n  cited evidence:\n${cited}`;
      })
      .join('\n\n');
    const res = await reason({
      schema: VerifierOut,
      system: SYSTEM,
      data,
      name: 'verify_hypotheses',
    });
    llmVerdicts = res.parsed.verdicts;
    tokens = res.tokens;
  }
  const llmById = new Map(llmVerdicts.map((v) => [v.hypothesis_id, v]));

  // ---- combine --------------------------------------------------------------
  const verdicts: Verdict[] = [];
  const supported: Hypothesis[] = [];
  const rejected: { hypothesis: Hypothesis; reason: string }[] = [];
  for (const h of hypotheses) {
    const detReason = deterministic.get(h.id);
    if (detReason) {
      verdicts.push({ hypothesis_id: h.id, supported: false, reason: `[deterministic] ${detReason}` });
      rejected.push({ hypothesis: h, reason: detReason });
      continue;
    }
    const llm = llmById.get(h.id);
    // Fail-closed: if the LLM returned no verdict for a gated hypothesis, reject.
    if (!llm || !llm.supported) {
      const reason = llm?.reason ?? 'no verifier verdict returned';
      verdicts.push({ hypothesis_id: h.id, supported: false, reason: `[entailment] ${reason}` });
      rejected.push({ hypothesis: h, reason });
    } else {
      verdicts.push({ hypothesis_id: h.id, supported: true, reason: llm.reason });
      supported.push(h);
    }
  }

  await recordAgentRun({
    incident_id: incidentId,
    agent: 'verifier',
    tools_used: [],
    citations: supported.flatMap((h) => h.citations),
    output: { verdicts, supported: supported.map((h) => h.id) },
    status: rejected.length > 0 ? 'partial' : 'ok',
    unsupported_claims: rejected.map((r) => ({
      hypothesis_id: r.hypothesis.id,
      statement: r.hypothesis.statement,
      reason: r.reason,
    })),
    latency_ms: Date.now() - t0,
    tokens,
  });

  return { verdicts, supported, rejected, tokens };
}
