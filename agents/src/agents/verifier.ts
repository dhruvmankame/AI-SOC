import { reason } from '../llm.js';
import { recordAgentRun, getSignalsForEvents } from '../tools.js';
import { VerifierOut } from '../state.js';
import type { EvidenceItem, Hypothesis, Verdict, AttackAssessment } from '../state.js';

// ============================================================================
// Agent 3 — VERIFIER / CRITIC + CONFIDENCE SCORER  (the graded centrepiece)
//
// Stage 3 of the pipeline does two jobs, in this order:
//
//   VERIFY (fail-closed) — a two-stage adversarial check on every hypothesis:
//     (A) DETERMINISTIC gate — a hypothesis with no citations, or whose
//         citations don't all resolve to real evidence, is rejected in code.
//         No LLM can argue its way past this.
//     (B) LLM ENTAILMENT check — survivors are shown ONLY the evidence they
//         cited and asked whether it genuinely supports the statement.
//   A hypothesis is "supported" only if it passes BOTH. Everything rejected is
//   written to agent_runs.unsupported_claims.
//
//   SCORE — each SURVIVING claim gets a confidence percentage. The number is
//   computed HERE IN CODE, not emitted by the model:
//       confidence = detector_component x entailment_component
//   detector_component is the strongest real detector score on the events that
//   back the cited evidence (read from the signals table); entailment_component
//   is the verifier's judgement of how completely that evidence establishes the
//   claim. A claim resting only on a dataset annotation is capped at the
//   annotation score and labelled 'annotation-only', so it can never be shown
//   as though an independent detector had confirmed it.
//
// Rejected claims are never scored — they are refused, not given a low number.
// ============================================================================

// Must match soccore.LABEL_SCORE: the score an annotation-derived signal carries.
const ANNOTATION_SCORE = 0.5;

const SYSTEM =
  'You are the Verifier in a SOC pipeline — a strict, adversarial fact-checker. ' +
  'For each hypothesis you are given its statement and the FULL TEXT of ONLY the ' +
  'evidence it cited. Decide supported=true ONLY if that cited evidence, on its ' +
  'own, genuinely establishes the statement. Reject (supported=false) if the ' +
  'evidence is unrelated, too weak, or the statement over-claims beyond what the ' +
  'evidence shows (e.g. asserting attribution or intent the evidence does not ' +
  'prove). Name the specific failing citation in your reason. Do not be charitable; ' +
  'an uncited or under-supported claim must fail. Also rate evidence_strength: how ' +
  'COMPLETELY the cited evidence alone establishes the statement (1.0 fully, 0.6 ' +
  'mostly, 0.3 weakly, 0.0 not at all). Rate only what the cited text shows — never ' +
  'your own prior knowledge of the attack type.';

export interface VerifierResult {
  verdicts: Verdict[];
  supported: Hypothesis[];
  rejected: { hypothesis: Hypothesis; reason: string }[];
  assessment: AttackAssessment[];
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
  let llmVerdicts: { hypothesis_id: string; supported: boolean; evidence_strength: number; reason: string }[] = [];
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

  // ---- STAGE 3b: confidence scoring of the SURVIVORS ------------------------
  // Only supported claims are scored. The detector component is read from the
  // real signals table — the model cannot inflate it — and an annotation-only
  // claim is capped at the annotation score and labelled as such.
  const assessment: AttackAssessment[] = [];
  if (supported.length > 0) {
    const citedEventIds = [
      ...new Set(
        supported.flatMap((h) =>
          h.citations.flatMap((c) => evById.get(c)?.source_event_ids ?? []),
        ),
      ),
    ];
    const sigs = await getSignalsForEvents(citedEventIds);
    const sigsByEvent = new Map<string, typeof sigs>();
    for (const s of sigs) {
      const arr = sigsByEvent.get(s.event_id) ?? [];
      arr.push(s);
      sigsByEvent.set(s.event_id, arr);
    }

    for (const h of supported) {
      const eventIds = [
        ...new Set(h.citations.flatMap((c) => evById.get(c)?.source_event_ids ?? [])),
      ];
      const mine = eventIds.flatMap((id) => sigsByEvent.get(id) ?? []);
      const behavioural = mine.filter((s) => s.detector !== 'label');
      const hasAnnotation = mine.some((s) => s.detector === 'label');

      let topDetector: string | null = null;
      let detectorComponent = 0;
      for (const s of behavioural) {
        if (s.score > detectorComponent) {
          detectorComponent = s.score;
          topDetector = s.detector_ref;
        }
      }
      const corroborated = detectorComponent > 0;
      const basis: AttackAssessment['basis'] = corroborated
        ? hasAnnotation
          ? 'behavioural+annotation'
          : 'behavioural'
        : 'annotation-only';
      if (!corroborated) {
        // No independent detector backed this claim: it rests on the dataset's
        // own annotation, so it is capped there rather than scored as detection.
        detectorComponent = hasAnnotation ? ANNOTATION_SCORE : 0;
        topDetector = hasAnnotation ? (mine.find((s) => s.detector === 'label')?.detector_ref ?? null) : null;
      }

      const raw = llmById.get(h.id)?.evidence_strength;
      const entailment = typeof raw === 'number' && isFinite(raw) ? Math.min(1, Math.max(0, raw)) : 0.5;

      assessment.push({
        hypothesis_id: h.id,
        statement: h.statement,
        technique: h.technique,
        confidence_pct: Math.round(detectorComponent * entailment * 1000) / 10,
        detector_component: Math.round(detectorComponent * 1000) / 1000,
        entailment_component: Math.round(entailment * 1000) / 1000,
        basis,
        corroborated_by_detector: corroborated,
        top_detector: topDetector,
        cited_evidence: h.citations,
      });
    }
    assessment.sort((a, b) => b.confidence_pct - a.confidence_pct);
  }

  await recordAgentRun({
    incident_id: incidentId,
    agent: 'verifier',
    tools_used: supported.length > 0 ? ['getSignalsForEvents'] : [],
    citations: supported.flatMap((h) => h.citations),
    output: { verdicts, supported: supported.map((h) => h.id), attack_assessment: assessment },
    status: rejected.length > 0 ? 'partial' : 'ok',
    unsupported_claims: rejected.map((r) => ({
      hypothesis_id: r.hypothesis.id,
      statement: r.hypothesis.statement,
      reason: r.reason,
    })),
    latency_ms: Date.now() - t0,
    tokens,
  });

  return { verdicts, supported, rejected, assessment, tokens };
}
