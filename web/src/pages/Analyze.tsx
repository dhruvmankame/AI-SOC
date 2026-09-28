import { useEffect, useRef, useState } from 'react'
import type { AnalyzeResponse, IncidentPhase, JobResponse } from '../lib/analyzeApi'
import { analyzeFile, fetchJob, isTerminalPhase, PHASE_LABEL } from '../lib/analyzeApi'

// Phase → progress fraction, for the little per-incident bar.
const PHASE_PCT: Record<IncidentPhase, number> = {
  queued: 5, collecting: 25, hypothesizing: 45, verifying: 65, reporting: 85,
  done_with_report: 100, done_no_report: 100, error: 100,
}

export function Analyze({
  onUploaded,
  onOpenIncident,
}: {
  onUploaded: (batchId: string) => void
  onOpenIncident: (incidentId: string) => void
}) {
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [resp, setResp] = useState<AnalyzeResponse | null>(null)
  const [job, setJob] = useState<JobResponse | null>(null)
  const pollRef = useRef<number | null>(null)

  // Poll the job store until every incident reaches a terminal phase.
  useEffect(() => {
    if (!resp) return
    let live = true
    const tick = async () => {
      try {
        const j = await fetchJob(resp.jobId)
        if (!live) return
        setJob(j)
        const done = j.status === 'complete' && j.incidents.every((i) => isTerminalPhase(i.phase))
        if (!done) pollRef.current = window.setTimeout(tick, 2500)
      } catch (e) {
        if (live) setErr(String((e as Error).message ?? e))
      }
    }
    tick()
    return () => { live = false; if (pollRef.current) clearTimeout(pollRef.current) }
  }, [resp])

  async function submit() {
    if (!file || busy) return
    setBusy(true); setErr(null); setResp(null); setJob(null)
    try {
      const r = await analyzeFile(file)
      setResp(r)
      onUploaded(r.batchId) // switch the global batch filter to this upload
    } catch (e) {
      setErr(String((e as Error).message ?? e))
    } finally {
      setBusy(false)
    }
  }

  const investigating = !!resp && (!job || job.status !== 'complete' ||
    !job.incidents.every((i) => isTerminalPhase(i.phase)))

  return (
    <>
      <section className="card upload">
        <h2>Upload a flow log</h2>
        <p className="prose muted">
          Pick a CICIDS / CICFlowMeter <code>.csv</code> flow export. Detection runs on the
          <strong> local backend</strong>, creates a new batch, and the AI agents investigate every
          detected incident automatically.
        </p>
        <div className="drop">
          <input
            type="file"
            accept=".csv,text/csv"
            disabled={busy}
            onChange={(e) => { setFile(e.target.files?.[0] ?? null); setErr(null) }}
          />
          <button className="theme-toggle primary" onClick={submit} disabled={!file || busy}>
            {busy ? 'Uploading…' : 'Analyze'}
          </button>
        </div>
        {file && <div className="chip" style={{ marginTop: 8 }}>{file.name}</div>}
        {err && <div className="callout error">{err}</div>}
        <p className="prose muted small">
          The backend is local-only and unauthenticated by design — it writes to the database with a
          privileged key and runs the uploaded file through the detector. Do not expose it publicly.
        </p>
      </section>

      {resp && (
        <section className="card">
          <h2>
            {resp.incidents.length} incident{resp.incidents.length === 1 ? '' : 's'} detected
            {investigating ? ' · investigating…' : ' · investigation complete'}
          </h2>
          {resp.incidents.length === 0 ? (
            <p className="prose muted">No attacks detected in this file. The batch was still recorded.</p>
          ) : (
            <div className="prog-list">
              {resp.incidents.map((inc) => {
                const ij = job?.incidents.find((j) => j.incidentId === inc.incidentId)
                const phase = ij?.phase ?? 'queued'
                const terminal = isTerminalPhase(phase)
                return (
                  <div
                    className={`prog ${phase}`}
                    key={inc.incidentId}
                    onClick={() => terminal && onOpenIncident(inc.incidentId)}
                    style={{ cursor: terminal ? 'pointer' : 'default' }}
                  >
                    <div className="prog-head">
                      <span className="prog-title">{inc.attackType} · {inc.code}</span>
                      <span className="chip">risk {Math.round(inc.risk)}</span>
                    </div>
                    <div className="prog-bar">
                      <div className={`fill ${phase}`} style={{ width: `${PHASE_PCT[phase]}%` }} />
                    </div>
                    <div className="prog-foot">
                      <span>{PHASE_LABEL[phase]}{ij?.error ? ` — ${ij.error}` : ''}</span>
                      {terminal && <span className="link">open record →</span>}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </section>
      )}
    </>
  )
}