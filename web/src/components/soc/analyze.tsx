import { useEffect, useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import {
  ArrowRight,
  CheckCircle2,
  FileSpreadsheet,
  Info,
  Radio,
  ScanSearch,
  ShieldAlert,
  UploadCloud,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  analyzeFile,
  fetchJob,
  isTerminal,
  phaseLabels,
  phaseProgress,
  type AnalyzeResponse,
  type Job,
} from "@/lib/analyze-client";
import { setActiveBatchId } from "@/lib/active-batch";
import {
  fetchIncidents,
  fetchVerifierCounts,
  type IncidentRow,
} from "@/lib/live-api";
import { SectionTitle, Severity } from "./layout";

type Stage = "idle" | "uploading" | "analyzing" | "ready" | "error";

export function Analyze() {
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [response, setResponse] = useState<AnalyzeResponse | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [stage, setStage] = useState<Stage>("idle");
  const [uploadPct, setUploadPct] = useState(0);
  const [liveIncidents, setLiveIncidents] = useState<IncidentRow[]>([]);
  const [verifierCounts, setVerifierCounts] = useState<
    Map<string, { supported: number; rejected: number }>
  >(new Map());
  const inputRef = useRef<HTMLInputElement>(null);

  async function refreshLive(batchId: string) {
    try {
      const incs = await fetchIncidents(batchId);
      setLiveIncidents(incs);
      const counts = await fetchVerifierCounts(incs.map((i) => i.incident_id));
      setVerifierCounts(counts);
    } catch {
      // During the short inserting stage the batch may not be visible yet.
    }
  }

  useEffect(() => {
    if (!response) return;
    let live = true;
    let timer: ReturnType<typeof setTimeout>;

    async function tick() {
      if (!response) return;
      try {
        const next = await fetchJob(response.jobId);
        if (!live) return;
        setJob(next);

        if (next.status !== "inserting") {
          await refreshLive(response.batchId);
        }

        if (
          next.status !== "complete" ||
          next.incidents.some((incident) => !isTerminal(incident.phase))
        ) {
          timer = setTimeout(tick, 1200);
        } else {
          await refreshLive(response.batchId);
        }
      } catch (e) {
        if (live) setError(e instanceof Error ? e.message : String(e));
      }
    }

    void tick();
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [response]);

  async function submit() {
    if (!file || busy) return;

    setBusy(true);
    setError(null);
    setResponse(null);
    setJob(null);
    setLiveIncidents([]);
    setVerifierCounts(new Map());
    setUploadPct(0);
    setStage("uploading");

    try {
      const result = await analyzeFile(file, ({ percent }) => {
        setUploadPct(percent);
        setStage(percent >= 100 ? "analyzing" : "uploading");
      });
      setUploadPct(100);
      setResponse(result);
      setActiveBatchId(result.batchId);
      setStage("ready");
      void refreshLive(result.batchId);
    } catch (e) {
      setStage("error");
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const stageText =
    stage === "uploading"
      ? `Uploading dataset · ${uploadPct}%`
      : stage === "analyzing"
        ? "Upload complete · running detection and correlation…"
        : stage === "ready"
          ? "Deterministic analysis ready"
          : stage === "error"
            ? "Analysis failed"
            : "Ready";

  return (
    <div className="space-y-5 entrance">
      <div className="grid gap-5 xl:grid-cols-12">
        <section className="panel-surface overflow-hidden xl:col-span-8">
          <SectionTitle
            label="Analyze network flows"
            aside="Each uploaded CSV is analyzed as an independent dataset"
          />
          <div className="p-5">
            <div className="flex min-h-[250px] flex-col items-center justify-center rounded-md border border-dashed border-primary/30 bg-primary/[.025] px-5 py-8 text-center">
              <div className="mb-4 flex size-14 items-center justify-center rounded-md border border-primary/25 bg-primary/10 text-primary">
                <UploadCloud className="size-6" strokeWidth={1.6} />
              </div>
              <h3 className="font-display text-lg font-medium">Flow log ready for inspection</h3>
              <p className="mt-2 max-w-md text-xs leading-relaxed text-muted-foreground">
                Upload one CICIDS/CICFlowMeter-style CSV. Its events, alerts and incidents stay
                isolated from every other upload through its batch ID.
              </p>

              <input
                ref={inputRef}
                type="file"
                accept=".csv,text/csv"
                className="sr-only"
                aria-label="Choose CSV flow log"
                onChange={(e) => {
                  setFile(e.target.files?.[0] ?? null);
                  setError(null);
                  setStage("idle");
                  setUploadPct(0);
                }}
              />

              <div className="mt-5 flex flex-wrap justify-center gap-2">
                <Button variant="outline" onClick={() => inputRef.current?.click()} disabled={busy}>
                  <FileSpreadsheet className="size-4" /> Choose CSV
                </Button>
                <Button onClick={submit} disabled={!file || busy}>
                  <ScanSearch className="size-4" />
                  {busy ? (stage === "uploading" ? "Uploading…" : "Analyzing…") : "Run analysis"}
                </Button>
              </div>

              {file && (
                <div className="mt-4 max-w-full truncate rounded border border-border bg-panel px-3 py-1.5 font-mono text-[11px] text-muted-foreground">
                  {file.name} · {(file.size / 1024).toFixed(1)} KB
                </div>
              )}

              {(busy || response) && (
                <div className="mt-5 w-full max-w-xl text-left">
                  <div className="mb-2 flex items-center justify-between gap-3 font-mono text-[10px] uppercase text-muted-foreground">
                    <span>{stageText}</span>
                    <span>{uploadPct}%</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-panel2">
                    <div
                      className="h-full bg-primary transition-[width] duration-200"
                      style={{ width: `${uploadPct}%` }}
                    />
                  </div>
                  {stage === "analyzing" && (
                    <p className="mt-2 text-[11px] text-faint">
                      Upload is complete. The local detector is now parsing, detecting and
                      correlating the uploaded flows.
                    </p>
                  )}
                </div>
              )}

              {error && (
                <div
                  role="alert"
                  className="mt-4 w-full rounded border border-crit/30 bg-crit/10 p-3 text-left text-xs text-crit"
                >
                  {error}
                </div>
              )}
            </div>
          </div>
        </section>

        <section className="panel-surface overflow-hidden xl:col-span-4">
          <SectionTitle label="Investigation sequence" aside="Fast detection first · AI follows live" />
          <div className="p-5">
            {[
              { n: "01", label: "Upload", text: "Live byte-level upload progress" },
              { n: "02", label: "Detect", text: "Rules + statistical detection" },
              { n: "03", label: "Correlate", text: "Build independent incidents" },
              { n: "04", label: "Verify", text: "Evidence-grounded Gemini workflow" },
              { n: "05", label: "Report", text: "Verified report appears here" },
            ].map((s, i) => (
              <div key={s.n} className="relative flex gap-3 pb-5 last:pb-0">
                <div className="relative flex flex-col items-center">
                  <span className="flex size-7 shrink-0 items-center justify-center rounded border border-primary/25 bg-primary/10 font-mono text-[10px] text-primary">
                    {s.n}
                  </span>
                  {i < 4 && <span className="mt-1 h-full w-px bg-border" />}
                </div>
                <div className="pt-1">
                  <div className="text-xs font-medium">{s.label}</div>
                  <div className="mt-1 text-[11px] text-muted-foreground">{s.text}</div>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>

      {response && (
        <>
          <section className="panel-surface overflow-hidden">
            <SectionTitle
              label="Dataset analysis"
              aside={`${response.stats.sourceFilename} · deterministic result in ${(response.stats.processingMs / 1000).toFixed(2)} s`}
            />
            <div className="grid gap-px bg-border sm:grid-cols-2 xl:grid-cols-4">
              {[
                ["Stored events", response.stats.storedEvents.toLocaleString()],
                ["Detector signals", response.stats.signals.toLocaleString()],
                ["Alerts", response.stats.alerts.toString()],
                ["Incidents", response.stats.incidents.toString()],
              ].map(([label, value]) => (
                <div key={label} className="bg-panel p-5">
                  <div className="font-mono text-[10px] uppercase text-faint">{label}</div>
                  <div className="mt-2 font-display text-2xl font-semibold">{value}</div>
                </div>
              ))}
            </div>

            {response.eval && (
              <div className="grid gap-3 border-t border-border p-5 sm:grid-cols-3">
                <div className="rounded border border-border bg-panel2/30 p-3">
                  <div className="font-mono text-[10px] uppercase text-faint">Precision</div>
                  <div className="mt-1 text-lg">{((response.eval.precision ?? 0) * 100).toFixed(1)}%</div>
                </div>
                <div className="rounded border border-border bg-panel2/30 p-3">
                  <div className="font-mono text-[10px] uppercase text-faint">Recall</div>
                  <div className="mt-1 text-lg">{((response.eval.recall ?? 0) * 100).toFixed(1)}%</div>
                </div>
                <div className="rounded border border-border bg-panel2/30 p-3">
                  <div className="font-mono text-[10px] uppercase text-faint">F1</div>
                  <div className="mt-1 text-lg">{((response.eval.f1 ?? 0) * 100).toFixed(1)}%</div>
                </div>
              </div>
            )}
          </section>

          <section className="panel-surface overflow-hidden">
            <SectionTitle
              label="Detector findings"
              aside={`${response.alerts.length} alert${response.alerts.length === 1 ? "" : "s"} in this dataset only`}
            />
            {response.alerts.length === 0 ? (
              <p className="p-5 text-xs text-muted-foreground">
                No configured attack pattern crossed the detector thresholds in this file.
              </p>
            ) : (
              <div className="divide-y divide-border/70">
                {response.alerts.map((alert, index) => (
                  <div key={`${alert.title}-${index}`} className="grid gap-3 p-5 md:grid-cols-[1fr_auto]">
                    <div>
                      <div className="flex items-center gap-2">
                        <Radio className="size-4 text-high" />
                        <span className="text-sm font-medium">{alert.title}</span>
                        <Severity value={alert.severity} />
                      </div>
                      <div className="mt-2 font-mono text-[10px] text-faint">
                        {alert.detector} · {alert.entity} · {alert.correlationCount.toLocaleString()} correlated flows
                      </div>
                    </div>
                    <div className="font-mono text-sm text-primary">
                      {(alert.confidence * 100).toFixed(1)}% confidence
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="panel-surface overflow-hidden">
            <SectionTitle
              label="Live investigation"
              aside={`${response.incidents.length} incident${response.incidents.length === 1 ? "" : "s"} · ${job?.status ?? "inserting"}`}
            />
            {response.incidents.length === 0 ? (
              <div className="p-5">
                <div className="flex items-center gap-2 text-sm">
                  <CheckCircle2 className="size-4 text-primary" />
                  No attack incident was created for this dataset.
                </div>
              </div>
            ) : (
              <div className="divide-y divide-border/70">
                {response.incidents.map((inc) => {
                  const current = job?.incidents.find((item) => item.incidentId === inc.incidentId);
                  const phase = current?.phase ?? "queued";
                  const liveRow = liveIncidents.find((item) => item.incident_id === inc.incidentId);
                  const counts = verifierCounts.get(inc.incidentId);

                  return (
                    <div key={inc.incidentId} className="p-5">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <div className="flex items-center gap-2">
                            <ShieldAlert className="size-4 text-high" />
                            <div className="text-sm font-medium">{inc.attackType}</div>
                          </div>
                          <div className="mt-1 font-mono text-[10px] text-faint">
                            {inc.code} · RISK {Math.round(inc.risk)}
                          </div>
                        </div>
                        <span className="font-mono text-[11px] text-primary">
                          {job?.status === "inserting" ? "Saving dataset" : phaseLabels[phase]}
                        </span>
                      </div>

                      <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-panel2">
                        <div
                          className={`h-full transition-all duration-500 ${
                            phase === "error"
                              ? "bg-crit"
                              : phase === "done_no_report"
                                ? "bg-high"
                                : "bg-primary"
                          }`}
                          style={{
                            width: `${job?.status === "inserting" ? 10 : phaseProgress[phase]}%`,
                          }}
                        />
                      </div>

                      {current?.error && <p className="mt-3 text-xs text-crit">{current.error}</p>}

                      {counts && (
                        <div className="mt-3 font-mono text-[10px] text-muted-foreground">
                          verifier · {counts.supported} supported · {counts.rejected} rejected
                        </div>
                      )}

                      {liveRow?.summary && (
                        <div className="mt-4 rounded border border-primary/20 bg-primary/5 p-4">
                          <div className="mb-1 font-mono text-[10px] uppercase text-primary">
                            Verified report
                          </div>
                          <p className="text-xs leading-relaxed text-foreground">{liveRow.summary}</p>
                        </div>
                      )}

                      {isTerminal(phase) && (
                        <Link
                          className="mt-3 inline-flex items-center gap-1 text-xs text-primary hover:underline"
                          to="/incidents/$incidentId"
                          params={{ incidentId: inc.incidentId }}
                        >
                          Open full incident record <ArrowRight className="size-3" />
                        </Link>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </>
      )}

      <div className="flex items-start gap-3 rounded-md border border-border bg-panel/45 p-4 text-xs leading-relaxed text-muted-foreground">
        <Info className="mt-0.5 size-4 shrink-0 text-low" />
        <p>
          Detection results are returned before the Gemini investigation finishes. The AI section
          refreshes live in the background, so a remote LLM delay does not block the next CSV upload.
        </p>
      </div>
    </div>
  );
}
