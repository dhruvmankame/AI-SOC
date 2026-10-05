// ============================================================================
// AI-SOC upload backend — the server-side write + auto-investigate path.
//
// SECURITY POSTURE (read before exposing anything):
//   * LOCAL-ONLY and UNAUTHENTICATED. It binds to 127.0.0.1 and has no auth.
//     Do NOT put it on a public interface or behind a tunnel — it writes to the
//     database with the secret DATABASE_URL and executes uploaded CSVs through
//     the Python detector. CORS is restricted to the Vite dev origin.
//   * The browser (anon key) is RLS read-only; every write in the product goes
//     through THIS process. Reads stay on the PostgREST/supabase-js path.
//   * Uploads are accepted only as .csv, size-capped, spawned with an ARGS ARRAY
//     (never a shell string), and the temp file is deleted after parsing.
//
// Flow of POST /api/analyze:
//   upload .csv -> spawn ml/analyze.py -> bulk-insert one batch (txn) ->
//   respond fast with the detected incidents -> asynchronously investigate them
//   all (LangGraph), streaming per-incident phase into an in-memory job store
//   that the UI polls at GET /api/jobs/:jobId.
// ============================================================================
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, extname } from 'node:path';
import { mkdirSync, promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import type { PoolClient } from 'pg';
import { pool, q } from './db.js';
import { investigateStreaming, type InvestigateProgress } from './graph.js';
import { loadWorkflow, reportContext, AGENTS } from './workflow.js';
import { runReportWriter } from './agents/report.js';
import { recordAgentRun } from './tools.js';
import { classifyLLMError } from './llm.js';

// ---------------------------------------------------------------------------
// Config (all overridable via env; defaults suit local `npm run dev` + server).
// ---------------------------------------------------------------------------
const HERE = dirname(fileURLToPath(import.meta.url));      // agents/src
const REPO_ROOT = resolve(HERE, '../..');                  // dsl/
const ML_DIR = resolve(REPO_ROOT, 'ml');
const ANALYZE_PY = resolve(ML_DIR, 'analyze.py');

const HOST = '127.0.0.1';                                   // never 0.0.0.0
const PORT = Number(process.env.PORT ?? 8787);
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB ?? 300);
const CORS_ORIGINS = (process.env.CORS_ORIGIN ?? 'http://localhost:5173,http://127.0.0.1:5173')
  .split(',').map((s) => s.trim()).filter(Boolean);

const UPLOAD_DIR = resolve(tmpdir(), 'ai-soc-uploads');
mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// Console logging. The backend terminal is the operator's view of the pipeline,
// so every stage announces itself: upload -> standardize -> detect -> persist,
// then, per incident, the four agents in order with their results. Python's
// stderr is streamed through live so a long parse shows progress instead of
// looking hung.
// ---------------------------------------------------------------------------
const hhmmss = () => new Date().toISOString().slice(11, 19);
const log = (stage: string, msg: string) => console.log(`[${hhmmss()}] ${stage.padEnd(16)}${msg}`);
const logErr = (stage: string, msg: string) => console.error(`[${hhmmss()}] ${stage.padEnd(16)}${msg}`);
const rule = (msg: string) => console.log(`\n${'='.repeat(78)}\n  ${msg}\n${'='.repeat(78)}`);

// ---------------------------------------------------------------------------
// Upload handling: .csv only, size-capped, random on-disk filename (so a
// crafted originalname can never traverse paths). The file is deleted after
// analyze.py has read it.
// ---------------------------------------------------------------------------
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, _file, cb) => cb(null, `${randomUUID()}.csv`),
  }),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    if (extname(file.originalname).toLowerCase() === '.csv') cb(null, true);
    else cb(new Error('only .csv flow files are accepted'));
  },
}).single('file');

// ---------------------------------------------------------------------------
// In-memory job store. A fully-rejected incident writes NO report and stays
// status='open' — indistinguishable over PostgREST from "still running" — so
// the terminal phase lives here, and the UI refetches DB content once a phase
// goes terminal. Cleared on process exit (fine: uploads re-derive stable ids).
// ---------------------------------------------------------------------------
type IncidentPhase =
  | 'queued' | 'collecting' | 'hypothesizing' | 'verifying' | 'reporting'
  | 'ready_for_report' | 'done_with_report' | 'done_no_report' | 'error';

interface IncidentJob {
  incidentId: string; code: string; title: string; attackType: string; risk: number;
  phase: IncidentPhase; error?: string; startedAt?: number; finishedAt?: number;
}
interface Job {
  jobId: string; batchId: string; createdAt: number;
  status: 'parsing' | 'inserting' | 'investigating' | 'complete';
  incidents: IncidentJob[];
  error?: string;
}
const jobs = new Map<string, Job>();
// Single-flight. The Gemini throttle in llm.ts is process-GLOBAL, so two
// concurrent analyses don't actually run in parallel — their LLM calls queue
// behind each other and their progress interleaves, which makes the backend log
// unreadable and the UI misleading. One analysis at a time; a second upload gets
// a clean 409 telling it to wait.
let activeJobId: string | null = null;

// ---------------------------------------------------------------------------
// Shape emitted by ml/analyze.py (JSON on stdout). Loose: only the fields we
// insert are typed; the detector owns the exact contents.
// ---------------------------------------------------------------------------
interface AnalyzeResult {
  error?: string;
  batch: { batch_id: string; label: string; source_filename: string; event_count: number; incident_count: number; status: string };
  standardization?: {
    source_columns: number;
    source_column_names: string[];
    canonical_mapping: Record<string, string | null>;
    label_column_present: boolean;
    rows_read: number;
    rows_standardized: number;
    rows_dropped_unparseable_timestamp: number;
    incidents_discovered: number;
    incidents_truncated: number;
    attack_classes: { attack_class: string; annotated_flows: number; corroborated_by_detector: number; corroboration_pct: number }[];
  };
  incidents: Array<{ incident_id: string; code: string; title: string; risk_score: number; risk_factors: unknown; mitre_techniques: string[]; summary: string | null }>;
  incident_entities: Array<{ incident_id: string; entity_type: string; entity_value: string; role: string }>;
  events: Array<Record<string, unknown>>;
  signals: Array<{ event_id: string; detector: string; detector_ref: string; score: number; reason: string }>;
  alerts: Array<{ alert_id: string; title: string; severity: string; confidence: number; detector: string; contributions: unknown; entity: string; event_ids: string[]; correlation_count: number; status: string; incident_id: string }>;
  rules: Array<{ rule_id: string; title: string; detector: string; mitre_tags: string[]; severity: string }>;
  attack_kb: Array<{ technique_id: string; name: string; tactic: string; description: string }>;
  eval?: unknown;
}

// Spawn the stdlib-only Python detector with an ARGS ARRAY (never a shell
// string) — the uploaded path/label are data, not shell tokens.
function runAnalyze(csvPath: string, batchId: string, label: string): Promise<AnalyzeResult> {
  return new Promise((resolvePromise, reject) => {
    const started = Date.now();
    log('STAGE 1', `standardizing "${label}" -> ${ANALYZE_PY}`);
    const py = spawn('python3', [ANALYZE_PY, csvPath, '--batch', batchId, '--label', label], { cwd: ML_DIR });
    let out = '';
    let err = '';
    py.stdout.on('data', (d) => { out += d.toString(); });
    // Stream python's progress lines through live so a large file visibly
    // advances instead of looking hung.
    py.stderr.on('data', (d) => {
      const chunk = d.toString();
      err += chunk;
      for (const line of chunk.split('\n')) {
        if (line.trim()) log('STAGE 1', `  ${line.trim()}`);
      }
    });
    py.on('error', (e) => reject(new Error(`failed to spawn python3: ${e.message}`)));
    py.on('close', (code) => {
      if (code !== 0) return reject(new Error(`analyze.py exited ${code}: ${err.slice(0, 500)}`));
      try {
        const parsed = JSON.parse(out) as AnalyzeResult;
        const s = parsed.standardization;
        log('STAGE 1', `done in ${((Date.now() - started) / 1000).toFixed(1)}s`);
        if (s) {
          log('STAGE 1', `rows ${s.rows_read} read / ${s.rows_standardized} standardized / ${s.rows_dropped_unparseable_timestamp} dropped`);
          log('STAGE 1', `attack column: ${s.label_column_present ? 'present' : 'absent'}`);
          for (const c of s.attack_classes ?? []) {
            log('STAGE 1', `  class "${c.attack_class}": ${c.annotated_flows} flows, ${c.corroboration_pct}% corroborated by a detector`);
          }
          if (s.incidents_truncated > 0) {
            log('STAGE 1', `NOTE ${s.incidents_discovered} incidents found; investigating top ${s.incidents_discovered - s.incidents_truncated} (quota cap)`);
          }
        }
        resolvePromise(parsed);
      } catch (e) {
        reject(new Error(`unparseable analyze.py output: ${(e as Error).message}; stderr: ${err.slice(0, 300)}`));
      }
    });
  });
}

// Chunked, parameterized multi-row INSERT. Postgres caps a statement at 65535
// bound params; we chunk well under that. JS arrays are serialized natively by
// node-postgres (pass string[] with a ::text[]/::uuid[] cast, never a '{}'
// literal); jsonb columns take a JSON.stringify'd string with a ::jsonb cast.
type Col = { name: string; cast?: string };
async function bulkInsert(
  client: PoolClient,
  table: string,
  columns: Col[],
  rows: unknown[][],
  onConflict = '',
): Promise<void> {
  if (rows.length === 0) return;
  const ncols = columns.length;
  const chunkSize = Math.max(1, Math.min(500, Math.floor(60000 / ncols)));
  const colList = columns.map((c) => `"${c.name}"`).join(',');
  for (let start = 0; start < rows.length; start += chunkSize) {
    const chunk = rows.slice(start, start + chunkSize);
    const params: unknown[] = [];
    const tuples: string[] = [];
    for (const row of chunk) {
      const ph: string[] = [];
      for (let c = 0; c < ncols; c++) {
        params.push(row[c]);
        ph.push(`$${params.length}${columns[c].cast ? `::${columns[c].cast}` : ''}`);
      }
      tuples.push(`(${ph.join(',')})`);
    }
    await client.query(
      `insert into ${table} (${colList}) values ${tuples.join(',')}${onConflict ? ` ${onConflict}` : ''}`,
      params,
    );
  }
}

// One transaction, FK-safe order: batch -> incidents -> events -> signals ->
// entities -> alerts -> rules/kb. Every produced row is stamped with batch_id
// (seeded CICIDS rows keep batch_id NULL). Rolls back on any error.
async function insertBatch(batchId: string, data: AnalyzeResult): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(
      `insert into ingest_batches (batch_id, label, source_filename, event_count, incident_count, status)
       values ($1,$2,$3,$4,$5,$6)`,
      [batchId, data.batch.label, data.batch.source_filename, data.batch.event_count,
        data.batch.incident_count, data.batch.status ?? 'detected'],
    );

    await bulkInsert(client, 'incidents',
      [{ name: 'incident_id' }, { name: 'code' }, { name: 'title' }, { name: 'risk_score' },
        { name: 'risk_factors', cast: 'jsonb' }, { name: 'mitre_techniques', cast: 'text[]' },
        { name: 'summary' }, { name: 'batch_id' }],
      data.incidents.map((i) => [
        i.incident_id, i.code, i.title, i.risk_score,
        JSON.stringify(i.risk_factors ?? {}), i.mitre_techniques ?? [], i.summary ?? null, batchId,
      ]),
    );

    await bulkInsert(client, 'events',
      [{ name: 'event_id' }, { name: 'ts' }, { name: 'source_type' }, { name: 'vendor' }, { name: 'product' },
        { name: 'class_uid' }, { name: 'category' }, { name: 'activity' }, { name: 'severity' }, { name: 'outcome' },
        { name: 'src_ip', cast: 'inet' }, { name: 'dst_ip', cast: 'inet' }, { name: 'template_id' }, { name: 'template_text' },
        { name: 'parser_confidence' }, { name: 'mitre_tags', cast: 'text[]' }, { name: 'raw' }, { name: 'raw_hash' },
        { name: 'gt_label' }, { name: 'gt_scenario' }, { name: 'batch_id' }],
      data.events.map((e) => [
        e.event_id, e.ts, e.source_type, e.vendor, e.product,
        e.class_uid, e.category, e.activity, e.severity, e.outcome,
        e.src_ip, e.dst_ip, e.template_id, e.template_text,
        e.parser_confidence, e.mitre_tags ?? [], e.raw, e.raw_hash,
        e.gt_label ?? null, e.gt_scenario ?? null, batchId,
      ]),
    );

    await bulkInsert(client, 'signals',
      [{ name: 'event_id' }, { name: 'detector' }, { name: 'detector_ref' }, { name: 'score' }, { name: 'reason' }, { name: 'batch_id' }],
      data.signals.map((s) => [s.event_id, s.detector, s.detector_ref, s.score, s.reason, batchId]),
    );

    await bulkInsert(client, 'incident_entities',
      [{ name: 'incident_id' }, { name: 'entity_type' }, { name: 'entity_value' }, { name: 'role' }, { name: 'batch_id' }],
      data.incident_entities.map((en) => [en.incident_id, en.entity_type, en.entity_value, en.role, batchId]),
      'on conflict (incident_id, entity_type, entity_value) do nothing',
    );

    await bulkInsert(client, 'alerts',
      [{ name: 'alert_id' }, { name: 'title' }, { name: 'severity' }, { name: 'confidence' }, { name: 'detector' },
        { name: 'contributions', cast: 'jsonb' }, { name: 'entity' }, { name: 'event_ids', cast: 'uuid[]' },
        { name: 'correlation_count' }, { name: 'status' }, { name: 'incident_id' }, { name: 'batch_id' }],
      data.alerts.map((a) => [
        a.alert_id, a.title, a.severity, a.confidence, a.detector,
        JSON.stringify(a.contributions ?? {}), a.entity, a.event_ids ?? [],
        a.correlation_count, a.status, a.incident_id, batchId,
      ]),
    );

    // detection_rules.logic is NOT NULL; analyze.py omits it -> derive {ref}.
    await bulkInsert(client, 'detection_rules',
      [{ name: 'rule_id' }, { name: 'title' }, { name: 'detector' }, { name: 'logic', cast: 'jsonb' },
        { name: 'mitre_tags', cast: 'text[]' }, { name: 'severity' }],
      data.rules.map((r) => [r.rule_id, r.title, r.detector, JSON.stringify({ ref: r.rule_id }), r.mitre_tags ?? [], r.severity]),
      'on conflict (rule_id) do nothing',
    );

    await bulkInsert(client, 'attack_kb',
      [{ name: 'technique_id' }, { name: 'name' }, { name: 'tactic' }, { name: 'description' }],
      data.attack_kb.map((k) => [k.technique_id, k.name, k.tactic, k.description]),
      'on conflict (technique_id) do nothing',
    );

    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

// A Gemini quota/rate-limit OR a Google-side overload (503) must fail ONE
// incident fast, not stall the whole job for minutes. llm.ts now classifies and
// fails fast on both; here we just turn the error into a plain UI message and
// always continue to the next incident.
function llmErrorMessage(err: unknown): string {
  switch (classifyLLMError(err)) {
    case 'overload': return 'Gemini model overloaded (503 / high demand) — retry later';
    case 'quota':    return 'Gemini quota / rate limit reached';
    default:         return String((err as Error)?.message ?? err).slice(0, 200);
  }
}

// Investigate every detected incident in sequence, streaming per-node phase into
// the job store. Fire-and-forget from the handler (.catch-wrapped): an unhandled
// rejection here would crash the process.
async function runInvestigations(job: Job): Promise<void> {
  job.status = 'investigating';
  try {
    await q('update ingest_batches set status = $1 where batch_id = $2', ['investigating', job.batchId]);
  } catch { /* best-effort */ }
  rule(`INVESTIGATION PLANE — ${job.incidents.length} incident(s) queued for the 4-agent pipeline`);
  let n = 0;
  for (const ij of job.incidents) {
    n++;
    // Skip anything that already carries a report (re-run safety; a fresh
    // upload has none). A written report sets incidents.summary.
    try {
      const rows = await q<{ summary: string | null }>('select summary from incidents where incident_id = $1', [ij.incidentId]);
      if (rows[0]?.summary) {
        ij.phase = 'done_with_report';
        ij.finishedAt = Date.now();
        log('SKIP', `${ij.code} already has a report`);
        continue;
      }
    } catch { /* fall through and investigate */ }

    rule(`[${n}/${job.incidents.length}] ${ij.code} — ${ij.attackType} (risk ${Math.round(ij.risk)})`);
    ij.phase = 'collecting';
    ij.startedAt = Date.now();
    const t0 = Date.now();
    // Every line carries the incident code: with one analysis at a time this is
    // merely helpful, but it keeps the log unambiguous no matter what else runs.
    const ilog = (stage: string, msg: string) => log(stage, `${ij.code}  ${msg}`);
    ilog('AGENT 1/4', 'Evidence Collector — incident-scoped events + signals, grounding every fact to event_ids');
    try {
      await investigateStreaming(ij.incidentId, (p: InvestigateProgress) => {
        ij.phase = p.phase;
        if (p.phase === 'hypothesizing') ilog('AGENT 2/4', 'Hypothesis & ATT&CK — reasoning over cited evidence only');
        else if (p.phase === 'verifying') ilog('AGENT 3/4', 'Verifier — citation gate + entailment, then confidence scoring');
        else if (p.phase === 'reporting') ilog('AGENT 4/4', 'Report Writer — verified findings only');
        else if (p.phase === 'ready_for_report') ilog('READY', `${p.supported} verified finding(s) — waiting for Generate report`);
        else if (p.phase === 'done_with_report') {
          ilog('RESULT', `VERIFIED REPORT written — ${p.supported} supported / ${p.rejected} rejected (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
        } else if (p.phase === 'done_no_report') {
          ilog('RESULT', `NO REPORT — ${p.supported} supported / ${p.rejected} rejected; see agent audit for skipped stages (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
        }
        if (p.phase === 'ready_for_report' || p.phase === 'done_with_report' || p.phase === 'done_no_report') ij.finishedAt = Date.now();
      }, false);
    } catch (err) {
      await recordFailure(ij.incidentId, ij.phase, err);
      ij.phase = 'error';
      ij.error = llmErrorMessage(err);
      ij.finishedAt = Date.now();
      logErr('ERROR', `${ij.code}  ${ij.error}`);
      // continue: one incident failing must not abort the batch
    }
  }
  job.status = 'complete';
  const ok = job.incidents.filter((i) => i.phase === 'done_with_report').length;
  const none = job.incidents.filter((i) => i.phase === 'done_no_report').length;
  const ready = job.incidents.filter((i) => i.phase === 'ready_for_report').length;
  const bad = job.incidents.filter((i) => i.phase === 'error').length;
  rule(`BATCH COMPLETE — ${ok} report(s) written, ${ready} ready for report, ${none} without report, ${bad} error(s)`);
  try {
    await q('update ingest_batches set status = $1 where batch_id = $2', ['complete', job.batchId]);
  } catch { /* best-effort */ }
}

const app = express();
app.use(cors({ origin: CORS_ORIGINS }));
app.use(express.json());

app.get('/api/health', (_req, res) => res.json({ ok: true }));

// The heavy lifting for POST /api/analyze, after multer has stored the file.
async function handleAnalyze(req: express.Request, res: express.Response): Promise<void> {
  // Single-flight: refuse a second analysis while one is still running.
  if (activeJobId && jobs.get(activeJobId)?.status !== 'complete') {
    if (req.file?.path) await fsp.unlink(req.file.path).catch(() => {});
    const running = jobs.get(activeJobId);
    logErr('REJECTED', `upload refused — analysis ${activeJobId.slice(0, 8)} is still ${running?.status}`);
    res.status(409).json({
      error: 'An analysis is already running. Wait for it to finish before uploading another dataset.',
      activeJobId,
    });
    return;
  }
  if (!req.file) {
    res.status(400).json({ error: 'no file uploaded (multipart field "file")' });
    return;
  }

  const requestStarted = Date.now();
  const batchId = randomUUID();
  const jobId = randomUUID();
  const filePath = req.file.path;
  const label = req.file.originalname || 'upload.csv';
  activeJobId = jobId;                       // claim the slot before any await
  rule(`UPLOAD RECEIVED — ${label} (${(req.file.size / 1048576).toFixed(1)} MB)  batch ${batchId.slice(0, 8)}`);

  try {
    const data = await runAnalyze(filePath, batchId, label);
    if (data.error) {
      activeJobId = null;
      logErr('STAGE 1', `rejected: ${data.error}`);
      res.status(400).json({ error: data.error });
      return;
    }
    // The random temp basename is an implementation detail; retain the user's
    // filename in the batch registry and response.
    data.batch.source_filename = label;
    log('STAGE 2', `detection: ${data.incidents.length} incident(s), ${data.alerts.length} alert(s), ${data.signals.length} signal(s)`);
    for (const i of data.incidents) {
      log('STAGE 2', `  ${i.code} ${i.title} [${(i.mitre_techniques ?? []).join(',')}] risk ${i.risk_score}`);
    }

    const kbName = new Map(data.attack_kb.map((k) => [k.technique_id, k.name]));
    const job: Job = {
      jobId,
      batchId,
      createdAt: Date.now(),
      status: 'inserting',
      incidents: data.incidents.map((i) => ({
        incidentId: i.incident_id,
        code: i.code,
        title: i.title,
        risk: i.risk_score,
        // The incident title is the specific attack class ("SQL Injection",
        // "Cross-Site Scripting"); the KB name is the broader technique
        // ("Exploit Public-Facing Application"). Show the specific one.
        attackType: i.title || kbName.get(i.mitre_techniques?.[0]) || 'Unknown',
        phase: 'queued' as IncidentPhase,
      })),
    };
    jobs.set(jobId, job);

    res.json({
      batchId,
      jobId,
      stats: {
        storedEvents: data.batch.event_count,
        signals: data.signals.length,
        alerts: data.alerts.length,
        incidents: data.incidents.length,
        processingMs: Date.now() - requestStarted,
        sourceFilename: data.batch.source_filename,
      },
      standardization: data.standardization ?? null,
      incidents: job.incidents.map((i) => ({
        incidentId: i.incidentId,
        code: i.code,
        title: i.title,
        attackType: i.attackType,
        risk: i.risk,
      })),
      alerts: data.alerts.map((a) => ({
        title: a.title,
        severity: a.severity,
        confidence: a.confidence,
        detector: a.detector,
        entity: a.entity,
        correlationCount: a.correlation_count,
        contributions: a.contributions ?? {},
      })),
      eval: data.eval ?? null,
    });

    void (async () => {
      try {
        log('PERSIST', `writing batch to Postgres (${data.events.length} events, ${data.signals.length} signals)…`);
        await insertBatch(batchId, data);
        log('PERSIST', 'batch committed');

        if (job.incidents.length === 0) {
          job.status = 'complete';
          try {
            await q('update ingest_batches set status = $1 where batch_id = $2', ['complete', batchId]);
          } catch { /* best-effort */ }
          return;
        }

        await runInvestigations(job);
      } catch (err) {
        const message = String((err as Error)?.message ?? err).slice(0, 200);
        job.error = message;
        console.error('[background-analysis] error', err);
        for (const incident of job.incidents) {
          if (incident.phase === 'queued') {
            incident.phase = 'error';
            incident.error = message;
            incident.finishedAt = Date.now();
          }
        }
        job.status = 'complete';
      }
    })().finally(() => { if (activeJobId === jobId) activeJobId = null; });
  } catch (err) {
    activeJobId = null;
    console.error('[analyze] error', err);
    if (!res.headersSent) {
      res.status(500).json({ error: String((err as Error)?.message ?? 'analyze failed') });
    }
  } finally {
    await fsp.unlink(filePath).catch(() => {});
  }
}

// Run multer ourselves so its errors (wrong type, too large) become clean 400s.
app.post('/api/analyze', (req, res) => {
  upload(req, res, (mErr) => {
    if (mErr) {
      res.status(400).json({ error: (mErr as Error).message });
      return;
    }
    void handleAnalyze(req, res);
  });
});

// Polling endpoint for live per-incident agent progress (~2-3s cadence; the
// LLM steps are ~13s apart, so nothing changes faster than that).
app.get('/api/jobs/:jobId', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) {
    res.status(404).json({ error: 'job not found' });
    return;
  }
  res.json(job);
});

const phaseAgent: Record<string, string> = { collecting: AGENTS[0], hypothesizing: AGENTS[1], verifying: AGENTS[2], reporting: AGENTS[3] };
async function recordFailure(id: string, phase: string, err: unknown) {
  const agent = phaseAgent[phase];
  if (!agent) return;
  await recordAgentRun({ incident_id: id, agent, tools_used: [], citations: [], output: { error: llmErrorMessage(err) }, status: 'error', unsupported_claims: [], latency_ms: 0, tokens: 0 }).catch(e => console.error('Could not persist agent error', e));
}
const validId = (id: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
app.get('/api/incidents/:id/workflow', async (req, res) => {
  if (!validId(req.params.id)) { res.status(400).json({ error: 'Invalid incident ID' }); return; }
  try {
    const w = await loadWorkflow(req.params.id);
    if (!w) { res.status(404).json({ error: 'Incident not found' }); return; }
    const liveJob = activeJobId ? jobs.get(activeJobId) : undefined;
    const live = liveJob?.status !== 'complete' ? liveJob?.incidents.find(i => i.incidentId === req.params.id && !i.finishedAt) : undefined;
    const active = live ? phaseAgent[live.phase] : undefined;
    let blocked = false;
    const stages = AGENTS.map((agent, index) => {
      let run = w.latest[index];
      if (live?.startedAt && live.phase !== 'reporting' && run && new Date(run.created_at).getTime() < live.startedAt) run = undefined;
      const status = agent === active ? 'running' : run?.status === 'error' ? 'error' : run?.status === 'skipped' ? 'skipped' : run ? 'complete' : index === 3 && w.canReport && !live ? 'ready' : blocked ? 'blocked' : 'waiting';
      if (status === 'error' || status === 'skipped') blocked = true;
      return { agent, status, runId: run?.run_id, tokens: run?.tokens ?? 0, durationMs: run?.latency_ms ?? 0, output: run?.output ?? {} };
    });
    res.json({ stages, active: !!live, busy: !!activeJobId, canReport: w.canReport && !activeJobId, canInvestigate: !activeJobId && !w.report, reason: w.reason, report: w.report, startedAt: live?.startedAt ?? null });
  } catch (err) { res.status(500).json({ error: llmErrorMessage(err) }); }
});

for (const action of ['investigate', 'report'] as const) {
  app.post(`/api/incidents/:id/${action}`, async (req, res) => {
    const id = req.params.id as string;
    if (!validId(id)) { res.status(400).json({ error: 'Invalid incident ID' }); return; }
    if (activeJobId) { res.status(409).json({ error: 'Another investigation is running. Wait for it to finish.' }); return; }
    const jobId = randomUUID();
    activeJobId = jobId; // Claim before the first await; shared with CSV uploads.
    let handedOff = false;
    try {
      const w = await loadWorkflow(id);
      if (!w) { res.status(404).json({ error: 'Incident not found' }); return; }
      if (w.report) { res.json({ complete: true }); return; }
      if (action === 'report' && !w.canReport) { res.status(409).json({ error: w.reason }); return; }
      const eventIndex = action === 'report' ? await reportContext(w) : undefined;
      const inc = w.incident;
      const ij: IncidentJob = { incidentId: id, code: inc.code, title: inc.title, attackType: inc.title, risk: inc.risk_score, phase: action === 'report' ? 'reporting' : 'queued', startedAt: Date.now() };
      const job: Job = { jobId, batchId: inc.batch_id ?? '', createdAt: Date.now(), status: 'investigating', incidents: [ij] };
      jobs.set(jobId, job);
      handedOff = true;
      res.status(202).json({ jobId });
      void (async () => {
        try {
          if (action === 'investigate') await runInvestigations(job);
          else {
            await runReportWriter(id, w.supported, w.evidence, eventIndex!, w.assessment);
            ij.phase = 'done_with_report';
          }
        } catch (err) {
          await recordFailure(id, ij.phase, err);
          ij.phase = 'error'; ij.error = llmErrorMessage(err);
        } finally {
          ij.finishedAt = Date.now(); job.status = 'complete';
          if (activeJobId === jobId) activeJobId = null;
        }
      })();
    } catch (err) { res.status(500).json({ error: llmErrorMessage(err) }); }
    finally { if (!handedOff && activeJobId === jobId) activeJobId = null; }
  });
}

app.listen(PORT, HOST, () => {
  console.log(`[ai-soc] upload backend on http://${HOST}:${PORT}  (LOCAL-ONLY, UNAUTHENTICATED — do not expose)`);
  console.log(`[ai-soc] CORS: ${CORS_ORIGINS.join(', ')}  |  max upload: ${MAX_UPLOAD_MB} MB  |  analyze.py: ${ANALYZE_PY}`);
});
