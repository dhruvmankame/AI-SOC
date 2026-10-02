import { z } from 'zod';

// ---- shared incident-state contract (blueprint §8) ----------------------

export interface Entity {
  entity_type: string;
  entity_value: string;
  role: string | null;
}

export interface EventRow {
  event_id: string;
  ts: string;
  src_ip: string | null;
  dst_ip: string | null;
  severity: string;
  template_text: string | null;
  raw: string | null;
  mitre_tags: string[];
}

export interface SignalRow {
  event_id: string;
  detector: string;
  detector_ref: string;
  score: number;
  reason: string;
}

export interface EvidenceItem {
  evidence_id: string;
  kind: 'event' | 'derived' | 'intel';
  fact: string;
  source_event_ids: string[];
  confidence: number;
}

export interface Hypothesis {
  id: string;
  statement: string;
  technique: string;
  citations: string[]; // evidence_ids
  confidence: number;
  recommended_actions: string[];
}

export interface Verdict {
  hypothesis_id: string;
  supported: boolean;
  reason: string;
}

/**
 * Stage-3 output: a confidence percentage per verified attack claim.
 *
 * The number is NOT produced by the LLM alone. It is computed in code as
 *   detector_component x entailment_component
 * where detector_component is the strongest REAL detector score on the events
 * backing the cited evidence (read from the signals table) and
 * entailment_component is how completely the verifier judged the cited evidence
 * to establish the claim. `basis` records which kind of evidence produced it, so
 * an annotation-only finding can never be displayed as a detector-confirmed one.
 */
export interface AttackAssessment {
  hypothesis_id: string;
  statement: string;
  technique: string;
  confidence_pct: number;
  detector_component: number;
  entailment_component: number;
  basis: 'behavioural' | 'behavioural+annotation' | 'annotation-only';
  corroborated_by_detector: boolean;
  top_detector: string | null;
  cited_evidence: string[];
}

export interface Budget {
  maxSteps: number;
  maxTokens: number;
  stepsUsed: number;
  tokensUsed: number;
}

// ---- LLM output schemas (structured-output contracts) -------------------

export const EvidenceOut = z.object({
  evidence: z
    .array(
      z.object({
        fact: z
          .string()
          .describe('One compact, checkable factual statement grounded in the cited events.'),
        kind: z.enum(['event', 'derived', 'intel']).describe('event=directly observed; derived=aggregated/inferred from events'),
        source_event_ids: z
          .array(z.string())
          .describe('event_id values (from the provided events) that directly support this fact. Must be non-empty.'),
        confidence: z.number().min(0).max(1),
      }),
    )
    .describe('The distinct, evidence-backed facts about this incident.'),
});

export const HypothesisOut = z.object({
  hypotheses: z
    .array(
      z.object({
        statement: z.string().describe('A specific investigative conclusion about what happened.'),
        technique: z.string().describe('The single most relevant MITRE ATT&CK technique id, e.g. T1110.'),
        citations: z
          .array(z.string())
          .describe('evidence_id values (e.g. EV-1-3) that support this statement. Every claim MUST be cited.'),
        confidence: z.number().min(0).max(1),
        recommended_actions: z.array(z.string()).describe('Simulation-only response steps an analyst could approve.'),
      }),
    )
    .max(6),
});

export const VerifierOut = z.object({
  verdicts: z.array(
    z.object({
      hypothesis_id: z.string(),
      supported: z.boolean().describe('true only if the cited evidence genuinely supports the statement.'),
      evidence_strength: z
        .number()
        .min(0)
        .max(1)
        .describe(
          'How completely the CITED EVIDENCE ALONE establishes the statement: 1.0 = fully established, ' +
            '0.6 = mostly but with a gap, 0.3 = only weakly suggested, 0.0 = not established. ' +
            'Judge only the evidence text shown, never prior knowledge.',
        ),
      reason: z.string().describe('Why it is supported or rejected. Name the failing citation if rejected.'),
    }),
  ),
});

export const ReportOut = z.object({
  summary: z.string().describe('2-4 sentence executive summary of the verified incident.'),
  narrative: z.string().describe('Markdown analyst report built ONLY from verified findings, with inline [EV-x] citations.'),
  recommended_actions: z.array(z.string()),
});
