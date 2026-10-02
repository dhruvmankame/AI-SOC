import { StateGraph, Annotation, START, END } from '@langchain/langgraph';
import { ENV } from './env.js';
import { getIncident } from './tools.js';
import { runEvidenceCollector } from './agents/evidence.js';
import { runHypothesisAgent } from './agents/hypothesis.js';
import { runVerifier } from './agents/verifier.js';
import { runReportWriter } from './agents/report.js';
import type { EvidenceItem, Hypothesis, Verdict, EventRow, AttackAssessment } from './state.js';

// ============================================================================
// Orchestration graph (blueprint §8). The controller is DETERMINISTIC code:
// each node calls one specialist agent, which does its own bounded LLM call
// with structured output. The LLM never chooses the control flow or calls
// tools autonomously — that keeps the pipeline auditable, injection-safe, and
// inside the per-incident budget. Flow:
//   START -> evidence -> hypothesis -> verifier -> report -> END
// ============================================================================

const SocState = Annotation.Root({
  incidentId: Annotation<string>(),
  incidentCode: Annotation<string>(),
  seedTechniques: Annotation<string[]>({ reducer: (_, b) => b, default: () => [] }),
  evidence: Annotation<EvidenceItem[]>({ reducer: (_, b) => b, default: () => [] }),
  eventIndex: Annotation<Map<string, EventRow>>({ reducer: (_, b) => b, default: () => new Map() }),
  hypotheses: Annotation<Hypothesis[]>({ reducer: (_, b) => b, default: () => [] }),
  verdicts: Annotation<Verdict[]>({ reducer: (_, b) => b, default: () => [] }),
  supported: Annotation<Hypothesis[]>({ reducer: (_, b) => b, default: () => [] }),
  rejected: Annotation<{ hypothesis: Hypothesis; reason: string }[]>({ reducer: (_, b) => b, default: () => [] }),
  assessment: Annotation<AttackAssessment[]>({ reducer: (_, b) => b, default: () => [] }),
  report: Annotation<{ summary: string; narrative: string; recommended_actions: string[] } | null>({
    reducer: (_, b) => b,
    default: () => null,
  }),
  tokensUsed: Annotation<number>({ reducer: (a, b) => a + b, default: () => 0 }),
});

type SocStateT = typeof SocState.State;

function overBudget(s: SocStateT): boolean {
  return s.tokensUsed >= ENV.maxTokens;
}

const graph = new StateGraph(SocState)
  .addNode('collect', async (s: SocStateT) => {
    const r = await runEvidenceCollector(s.incidentId);
    return { evidence: r.evidence, eventIndex: r.eventIndex, tokensUsed: r.tokens };
  })
  .addNode('hypothesize', async (s: SocStateT) => {
    if (overBudget(s) || s.evidence.length === 0) return { hypotheses: [] };
    const r = await runHypothesisAgent(s.incidentId, s.incidentCode, s.evidence, s.seedTechniques);
    return { hypotheses: r.hypotheses, tokensUsed: r.tokens };
  })
  .addNode('verify', async (s: SocStateT) => {
    if (s.hypotheses.length === 0) return { supported: [], rejected: [], verdicts: [], assessment: [] };
    const r = await runVerifier(s.incidentId, s.hypotheses, s.evidence);
    return { verdicts: r.verdicts, supported: r.supported, rejected: r.rejected, assessment: r.assessment, tokensUsed: r.tokens };
  })
  .addNode('write_report', async (s: SocStateT) => {
    if (s.supported.length === 0) return {};
    const r = await runReportWriter(s.incidentId, s.supported, s.evidence, s.eventIndex, s.assessment);
    return { report: { summary: r.summary, narrative: r.narrative, recommended_actions: r.recommended_actions }, tokensUsed: r.tokens };
  })
  .addEdge(START, 'collect')
  .addEdge('collect', 'hypothesize')
  .addEdge('hypothesize', 'verify')
  .addEdge('verify', 'write_report')
  .addEdge('write_report', END);

export const socGraph = graph.compile();

export async function investigate(incidentId: string): Promise<SocStateT> {
  const incident = await getIncident(incidentId);
  if (!incident) throw new Error(`incident not found: ${incidentId}`);
  const final = await socGraph.invoke({
    incidentId,
    incidentCode: incident.code,
    seedTechniques: incident.mitre_techniques ?? [],
  });
  return final;
}

// ---------------------------------------------------------------------------
// Streaming variant for the upload backend (server.ts): emits a phase update as
// each graph node completes, so the UI can show live per-incident progress
// (collecting -> hypothesizing -> verifying -> reporting -> terminal). The
// terminal phase distinguishes done_with_report from done_no_report because a
// fully-rejected incident writes NO report and stays status='open' — otherwise
// indistinguishable from "still running" over PostgREST.
// ---------------------------------------------------------------------------
export type InvestigatePhase =
  | 'collecting'
  | 'hypothesizing'
  | 'verifying'
  | 'reporting'
  | 'done_with_report'
  | 'done_no_report'
  | 'error';

export interface InvestigateProgress {
  phase: InvestigatePhase;
  supported?: number;
  rejected?: number;
  hasReport?: boolean;
}

export async function investigateStreaming(
  incidentId: string,
  onPhase: (p: InvestigateProgress) => void,
): Promise<SocStateT> {
  const incident = await getIncident(incidentId);
  if (!incident) throw new Error(`incident not found: ${incidentId}`);
  onPhase({ phase: 'collecting' });

  // 'updates' mode yields { <nodeName>: <partial state> } as each node finishes.
  // The replace-reducer fields we care about (report/supported/rejected) merge
  // correctly with a shallow last-write-wins accumulation.
  const stream = await socGraph.stream(
    {
      incidentId,
      incidentCode: incident.code,
      seedTechniques: incident.mitre_techniques ?? [],
    },
    { streamMode: 'updates' },
  );
  // node just completed -> phase now active (the next node)
  const NEXT: Record<string, InvestigatePhase> = {
    collect: 'hypothesizing',
    hypothesize: 'verifying',
    verify: 'reporting',
  };
  let acc: Partial<SocStateT> = {};
  for await (const chunk of stream) {
    for (const [node, update] of Object.entries(chunk as Record<string, Partial<SocStateT>>)) {
      acc = { ...acc, ...update };
      if (NEXT[node]) onPhase({ phase: NEXT[node] });
    }
  }
  const hasReport = !!acc.report;
  onPhase({
    phase: hasReport ? 'done_with_report' : 'done_no_report',
    supported: acc.supported?.length ?? 0,
    rejected: acc.rejected?.length ?? 0,
    hasReport,
  });
  return acc as SocStateT;
}
