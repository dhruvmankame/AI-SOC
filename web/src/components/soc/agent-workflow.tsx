import { useEffect, useRef, useState } from "react";
import {
  BrainCircuit,
  CheckCircle2,
  CircleDashed,
  Download,
  FileText,
  Loader2,
  Play,
  ScanSearch,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  fetchWorkflow,
  startAgentAction,
  type Workflow,
  type WorkflowStage,
} from "@/lib/analyze-client";

const agents = [
  {
    name: "Evidence collector",
    icon: ScanSearch,
    task: "Reads incident events and detector signals. Grounds every fact in source logs.",
  },
  {
    name: "Hypothesis & ATT&CK",
    icon: BrainCircuit,
    task: "Forms cited attack hypotheses and maps them to MITRE ATT&CK techniques.",
  },
  {
    name: "Verifier",
    icon: ShieldCheck,
    task: "Checks citations and tests each claim against the evidence. Rejects unsupported claims.",
  },
  {
    name: "Report writer",
    icon: FileText,
    task: "Turns verified findings into a cited analyst report and suggested response steps.",
  },
];
const labels = {
  waiting: "Waiting",
  running: "Working",
  complete: "Completed",
  ready: "Ready for you",
  blocked: "Blocked",
  skipped: "Skipped",
  error: "Failed",
};
function result(stage: WorkflowStage | undefined): string {
  if (!stage) return "Waiting for investigation";
  const o = stage.output;
  if (o.error || o.reason) return o.error || o.reason || "";
  if (o.evidence) return `${o.evidence.length} grounded facts collected`;
  if (o.hypotheses) return `${o.hypotheses.length} attack hypotheses proposed`;
  if (o.verdicts)
    return `${o.verdicts.filter((v) => v.supported).length} supported · ${o.verdicts.filter((v) => !v.supported).length} rejected`;
  return stage.status === "complete"
    ? "Report saved to incident"
    : stage.status === "ready"
      ? "Verified findings available"
      : stage.status === "running"
        ? "Processing evidence…"
        : "Waiting for the previous agent";
}

export function AgentWorkflow({
  incidentId,
  onUpdated,
}: {
  incidentId: string;
  onUpdated?: () => void;
}) {
  const [workflow, setWorkflow] = useState<Workflow | null>(null);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [now, setNow] = useState(Date.now());
  const onUpdatedRef = useRef(onUpdated);
  onUpdatedRef.current = onUpdated;
  const fingerprint = useRef("");
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const w = await fetchWorkflow(incidentId);
        if (cancelled) return;
        setWorkflow(w);
        setError("");
        const key = w.stages.map((s) => `${s.runId}:${s.status}`).join("|");
        if (fingerprint.current !== key) {
          fingerprint.current = key;
          onUpdatedRef.current?.();
        }
        timer = setTimeout(() => void poll(), w.active || w.busy ? 1500 : 5000);
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
          timer = setTimeout(() => void poll(), 5000);
        }
      }
    }
    void poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [incidentId, refresh]);
  useEffect(() => {
    if (!workflow?.active) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [workflow?.active]);
  async function start(action: "investigate" | "report") {
    setPending(true);
    setError("");
    try {
      await startAgentAction(incidentId, action);
      setRefresh((n) => n + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setPending(false);
    }
  }
  function download() {
    if (!workflow?.report) return;
    const r = workflow.report;
    const content = `# Incident report\n\n${r.summary}\n\n${r.narrative ?? ""}\n\n## Recommended actions (simulation only)\n\n${(r.recommended_actions ?? []).map((a) => `- ${a}`).join("\n")}\n`;
    const url = URL.createObjectURL(new Blob([content], { type: "text/markdown" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident-${incidentId}.md`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  const completed = workflow?.stages.filter((s) => s.status === "complete").length ?? 0;
  const hasRuns = workflow?.stages.some((s) => s.runId);
  const running = workflow?.stages.findIndex((s) => s.status === "running") ?? -1;
  return (
    <section
      className="agent-workflow rounded-xl border border-border bg-panel/70 p-4 sm:p-6"
      aria-label="Four-agent investigation"
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="mb-2 font-mono text-[10px] uppercase tracking-[0.18em] text-primary">
            Investigation workspace
          </div>
          <h3 className="font-display text-lg font-semibold">
            Four specialists. One evidence trail.
          </h3>
          <p className="mt-1 max-w-2xl text-xs leading-relaxed text-muted-foreground">
            Follow each agent as it works. Review verification, then generate your report.
          </p>
        </div>
        <div className="rounded-lg border border-border bg-panel2/50 px-3 py-2 text-right">
          <span className="font-display text-xl text-primary">
            {completed}
            <span className="text-sm text-muted-foreground"> / 4</span>
          </span>
          <div className="text-[10px] text-muted-foreground">agents completed</div>
        </div>
      </div>
      <div
        className="my-5 h-1.5 overflow-hidden rounded-full bg-panel2"
        role="progressbar"
        aria-label="Completed agents"
        aria-valuemin={0}
        aria-valuemax={4}
        aria-valuenow={completed}
      >
        <div
          className="h-full rounded-full bg-primary transition-all duration-700"
          style={{ width: `${completed * 25}%` }}
        />
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {agents.map((agent, i) => {
          const stage = workflow?.stages[i];
          const status = stage?.status ?? "waiting";
          const Icon = agent.icon;
          return (
            <article
              key={agent.name}
              className={`agent-stage agent-stage-${status} relative flex min-w-0 flex-col rounded-lg border border-border bg-panel2/25 p-4`}
            >
              <div className="flex items-center justify-between">
                <span className="flex size-10 items-center justify-center rounded-lg border border-border bg-panel">
                  <Icon className="size-5" />
                </span>
                <span className="font-mono text-[10px] text-faint">AGENT 0{i + 1}</span>
              </div>
              <h4 className="mt-4 text-sm font-semibold">{agent.name}</h4>
              <p className="mb-4 mt-2 min-h-14 text-[11px] leading-relaxed text-muted-foreground">
                {agent.task}
              </p>
              <div className="mt-auto flex items-center gap-1.5 text-xs font-medium">
                {status === "running" ? (
                  <Loader2 className="size-3.5 animate-spin" />
                ) : status === "complete" ? (
                  <CheckCircle2 className="size-3.5" />
                ) : (
                  <CircleDashed className="size-3.5" />
                )}
                {labels[status]}
              </div>
              <p className="mt-2 break-words text-[11px] leading-relaxed text-muted-foreground">
                {result(stage)}
              </p>
              {status === "running" && (
                <div className="agent-sweep mt-3 h-1 overflow-hidden rounded bg-primary/10">
                  <span />
                </div>
              )}
              {!!stage?.runId && (
                <div className="mt-3 font-mono text-[9px] text-faint">
                  {status === "error"
                    ? "No result saved for this stage"
                    : `${(stage.durationMs / 1000).toFixed(1)}s · ${stage.tokens.toLocaleString()} tokens`}
                </div>
              )}
              {i === 3 && (
                <Button
                  size="sm"
                  className="mt-4 w-full"
                  disabled={!workflow?.canReport || pending || !!error}
                  onClick={() => void start("report")}
                >
                  <FileText className="size-3.5" />
                  {status === "running"
                    ? "Generating…"
                    : workflow?.report
                      ? "Report generated"
                      : "Generate report"}
                </Button>
              )}
              {stage &&
              (stage.output.evidence?.length ||
                stage.output.hypotheses?.length ||
                stage.output.verdicts?.length) ? (
                <details className="mt-3 text-[11px]">
                  <summary className="cursor-pointer text-primary">Inspect results</summary>
                  <ul className="mt-2 space-y-2 text-muted-foreground">
                    {(
                      stage.output.evidence?.map((e) => e.fact) ??
                      stage.output.hypotheses?.map((h) => h.statement) ??
                      stage.output.verdicts?.map(
                        (v) => `${v.supported ? "Supported" : "Rejected"}: ${v.reason}`,
                      ) ??
                      []
                    ).map((text, n) => (
                      <li key={n} className="border-t border-border pt-2">
                        {text}
                      </li>
                    ))}
                  </ul>
                </details>
              ) : null}
            </article>
          );
        })}
      </div>
      {!!workflow?.stages[2]?.output.attack_assessment?.length && (
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          {workflow.stages[2].output.attack_assessment.map((a) => (
            <div key={a.hypothesis_id} className="rounded-lg border border-border bg-panel2/30 p-3">
              <div className="flex items-center justify-between gap-3 text-xs">
                <span className="font-mono text-primary">{a.technique} · verified finding</span>
                <span>{a.confidence_pct}% confidence</span>
              </div>
              <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{a.statement}</p>
              <div className="my-2 h-1 overflow-hidden rounded bg-panel2">
                <div
                  className="h-full bg-primary"
                  style={{ width: `${Math.min(100, Math.max(0, a.confidence_pct))}%` }}
                />
              </div>
              <p className="text-[10px] text-muted-foreground">
                {a.basis} ·{" "}
                {a.corroborated_by_detector
                  ? `Detector ${a.top_detector ?? "signal"} × evidence strength`
                  : "Dataset label only; no independent detector confirmation"}
              </p>
            </div>
          ))}
        </div>
      )}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg bg-panel2/40 p-3">
        <p role="status" className="max-w-2xl text-xs leading-relaxed text-muted-foreground">
          {workflow?.active
            ? `${running >= 0 ? agents[running]?.name : "Investigation queued"}${workflow.startedAt ? ` · ${Math.max(0, Math.floor((now - workflow.startedAt) / 1000))}s elapsed` : ""}. Updates arrive as each agent finishes.`
            : workflow?.busy
              ? "Another incident is being investigated. Your controls unlock when it finishes."
              : (workflow?.reason ?? "Connecting to the local agents service…")}
        </p>
        {workflow?.canInvestigate && !workflow.canReport && (
          <Button
            variant="outline"
            size="sm"
            disabled={pending || !!error}
            onClick={() => void start("investigate")}
          >
            <Play className="size-3.5" />
            {pending ? "Starting…" : hasRuns ? "Retry investigation" : "Start investigation"}
          </Button>
        )}
        {workflow?.report && (
          <Button variant="outline" size="sm" onClick={download}>
            <Download className="size-3.5" />
            Download report
          </Button>
        )}
      </div>
      {error && (
        <p role="alert" className="mt-3 text-xs text-crit">
          {error}{" "}
          <button
            type="button"
            className="underline"
            onClick={() => {
              setError("");
              setRefresh((n) => n + 1);
            }}
          >
            Reconnect
          </button>
        </p>
      )}
      {workflow?.report && (
        <details className="mt-4 rounded-lg border border-primary/20 bg-primary/5 p-4" open>
          <summary className="cursor-pointer text-sm font-medium text-primary">
            Verified incident report
          </summary>
          <p className="mt-3 text-sm leading-relaxed">{workflow.report.summary}</p>
          <p className="mt-3 whitespace-pre-wrap break-words text-xs leading-relaxed text-muted-foreground">
            {workflow.report.narrative}
          </p>
          {!!workflow.report.recommended_actions?.length && (
            <>
              <h4 className="mt-4 text-xs font-medium">Recommended actions · simulation only</h4>
              <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-muted-foreground">
                {workflow.report.recommended_actions.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </>
          )}
        </details>
      )}
    </section>
  );
}
