// ---------------------------------------------------------------------------
// Client for the LOCAL upload backend (agents/src/server.ts). This is the ONLY
// non-Supabase call path in the app: the browser is RLS read-only, so all
// writes (upload → detect → investigate) go through this local Node service.
// Everything else stays on the PostgREST/supabase-js read path.
//
// Base URL: VITE_ANALYZE_API (default http://localhost:8787). The backend is
// local-only + unauthenticated by design — never point this at a public host.
// ---------------------------------------------------------------------------

const BASE = (import.meta.env.VITE_ANALYZE_API as string) || 'http://localhost:8787'

// Per-incident investigation phase, mirrored from the backend job store.
export type IncidentPhase =
  | 'queued' | 'collecting' | 'hypothesizing' | 'verifying' | 'reporting'
  | 'done_with_report' | 'done_no_report' | 'error'

export interface AnalyzeIncident {
  incidentId: string
  code: string
  title: string
  attackType: string
  risk: number
}

// POST /api/analyze response — returned FAST, before investigation runs.
export interface AnalyzeResponse {
  batchId: string
  jobId: string
  incidents: AnalyzeIncident[]
}

// GET /api/jobs/:jobId — live per-incident investigation progress.
export interface JobIncident extends AnalyzeIncident {
  phase: IncidentPhase
  error?: string
  startedAt?: number
  finishedAt?: number
}
export interface JobResponse {
  jobId: string
  batchId: string
  createdAt: number
  status: 'parsing' | 'inserting' | 'investigating' | 'complete'
  incidents: JobIncident[]
}

async function readError(res: Response): Promise<string> {
  try {
    const body = await res.json()
    return (body as { error?: string })?.error ?? `HTTP ${res.status}`
  } catch {
    return `HTTP ${res.status}`
  }
}

// Upload one .csv flow file → detect + create a batch. Rejects with the
// backend's message (e.g. 409 "an analysis is already running", 400 bad file).
export async function analyzeFile(file: File): Promise<AnalyzeResponse> {
  const form = new FormData()
  form.append('file', file)
  let res: Response
  try {
    res = await fetch(`${BASE}/api/analyze`, { method: 'POST', body: form })
  } catch (e) {
    throw new Error(
      `cannot reach the analyze backend at ${BASE} — is it running? (\`npm run server\` in agents/). ${(e as Error).message}`,
    )
  }
  if (!res.ok) throw new Error(await readError(res))
  return (await res.json()) as AnalyzeResponse
}

export async function fetchJob(jobId: string): Promise<JobResponse> {
  const res = await fetch(`${BASE}/api/jobs/${jobId}`)
  if (!res.ok) throw new Error(await readError(res))
  return (await res.json()) as JobResponse
}

// Terminal phases (investigation of that incident has finished, one way or another).
export function isTerminalPhase(p: IncidentPhase): boolean {
  return p === 'done_with_report' || p === 'done_no_report' || p === 'error'
}

// Human label for a phase (progress line in the Analyze page).
export const PHASE_LABEL: Record<IncidentPhase, string> = {
  queued: 'Queued',
  collecting: 'Collecting evidence',
  hypothesizing: 'Forming hypotheses',
  verifying: 'Verifying against evidence',
  reporting: 'Writing report',
  done_with_report: 'Report ready',
  done_no_report: 'No report (all hypotheses rejected)',
  error: 'Error',
}
