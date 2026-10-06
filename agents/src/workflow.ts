import { q } from "./db.js";
import { ENV } from "./env.js";
import type {
  EvidenceItem,
  Hypothesis,
  Verdict,
  AttackAssessment,
  EventRow,
} from "./state.js";

export const AGENTS = [
  "evidence-collector",
  "hypothesis-attack",
  "verifier",
  "report-writer",
] as const;
type Output = {
  evidence?: EvidenceItem[];
  hypotheses?: Hypothesis[];
  verdicts?: Verdict[];
  supported?: string[];
  attack_assessment?: AttackAssessment[];
  summary?: string;
  narrative?: string;
  recommended_actions?: string[];
  reason?: string;
  error?: string;
};
type Run = {
  run_id: string;
  agent: string;
  status: string;
  output: Output;
  tokens: number;
  latency_ms: number;
  created_at: string;
};
export async function loadWorkflow(id: string) {
  const [incident] = await q(
    "select incident_id, code, title, risk_score, batch_id from incidents where incident_id=$1",
    [id],
  );
  if (!incident) return null;
  const history = await q<Run>(
    "select run_id, agent, status, output, tokens, latency_ms, created_at from agent_runs where incident_id=$1 order by created_at, run_id",
    [id],
  );
  // Each collector starts a fresh attempt. Old verifier approvals must never authorize a new report.
  const first = [...history].reverse().find((r) => r.agent === AGENTS[0]);
  const start = first ? history.indexOf(first) : -1;
  const runs = start < 0 ? [] : history.slice(start);
  const latest = AGENTS.map((agent) =>
    [...runs].reverse().find((r) => r.agent === agent),
  );
  const [collector, hypothesis, verifier, writer] = latest;
  const evidence =
    collector && ["ok", "partial"].includes(collector.status)
      ? (collector.output.evidence ?? [])
      : [];
  const hypotheses =
    hypothesis?.status === "ok" ? (hypothesis.output.hypotheses ?? []) : [];
  const verified = verifier && ["ok", "partial"].includes(verifier.status);
  const supported = verified
    ? hypotheses.filter(
        (h) =>
          verifier.output.supported?.includes(h.id) &&
          verifier.output.verdicts?.some(
            (v) => v.hypothesis_id === h.id && v.supported,
          ),
      )
    : [];
  const validCitations = supported.every(
    (h) =>
      h.citations.length > 0 &&
      h.citations.every((c) =>
        evidence.some(
          (e) => e.evidence_id === c && e.source_event_ids.length > 0,
        ),
      ),
  );
  const budgetExceeded =
    runs.reduce((sum, r) => sum + (r.tokens ?? 0), 0) >= ENV.maxTokens;
  const report =
    writer?.status === "ok" && writer.output.summary ? writer.output : null;
  const canReport =
    supported.length > 0 && validCitations && !budgetExceeded && !report;
  const reason = report
    ? "Report generated from verified findings."
    : budgetExceeded
      ? "Investigation token budget exhausted."
      : !verified
        ? "Complete verification to unlock the report writer."
        : !supported.length
          ? "No findings passed verification. Review the rejected claims."
          : !validCitations
            ? "Verified findings are missing grounded citations."
            : "Verified findings are ready. Generate your report.";
  return {
    incident,
    runs,
    latest,
    evidence,
    supported,
    assessment: verifier?.output.attack_assessment ?? [],
    canReport,
    reason,
    report,
  };
}
export async function reportContext(
  w: NonNullable<Awaited<ReturnType<typeof loadWorkflow>>>,
) {
  if (!w.canReport) throw new Error(w.reason);
  const ids = [...new Set(w.evidence.flatMap((e) => e.source_event_ids))];
  const events = await q<EventRow>(
    "select event_id, ts, src_ip, dst_ip, severity, template_text, raw, mitre_tags from events where event_id = any($1::uuid[])",
    [ids],
  );
  const eventIndex = new Map(
    events.map((e) => [e.event_id, { ...e, ts: new Date(e.ts).toISOString() }]),
  );
  if (ids.some((id) => !eventIndex.has(id)))
    throw new Error(
      "Source events are missing; investigate again before generating a report.",
    );
  return eventIndex;
}
