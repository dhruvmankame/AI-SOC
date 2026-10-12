import { q, closeDb } from './db.js';
import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// ============================================================================
// npm run eval — Investigation-quality evaluation (Day 3 / Phase 3).
//
// Reads the STORED agent_runs already produced by past investigations and
// computes the metrics the project thesis rests on. It makes NO new LLM calls
// (quota-free, per execution decision #1) — re-run it any time more
// investigations have been stored and it recomputes from the DB.
//
// Metrics (blueprint / plan §12):
//   * evidence-grounding coverage  — are asserted claims cited to real evidence?
//   * unsupported-claim rate        — of grounded claims, how many over-claim?
//   * verifier rejected-claim count — what the pipeline refused to assert
//   * tokens + latency per investigation
//   * a verifier ON vs OFF comparison derived from the SAME runs (decision #2):
//       without = every hypothesis would ship, INCLUDING the rejected ones;
//       with    = only verifier-supported hypotheses ship.
//
// Output: data/investigation_eval.json + a readable table on stdout.
// ============================================================================

const HERE = dirname(fileURLToPath(import.meta.url));            // agents/src
const OUT = resolve(HERE, '../../data/investigation_eval.json'); // dsl/data/

interface Hypo { id: string; statement: string; technique: string; citations: string[]; confidence?: number; }
interface Rejected { hypothesis_id?: string; statement?: string; reason?: string; }

interface RunRow {
  code: string; incident_id: string; agent: string; status: string;
  created_at: string; tokens: number | null; latency_ms: number | null;
  tools_used: unknown; output: any; unsupported_claims: any; citations: string[] | null;
}

interface Investigation {
  code: string; incident_id: string; started_at: string; retrieval: string;
  evidence_facts: number; dropped_facts: number;
  hypotheses: number; grounded_hypotheses: number; cited_evidence: number;
  supported: number; rejected: number;
  rejections: { statement: string; reason: string }[];
  has_report: boolean; report_summary: string | null;
  tokens: number; latency_ms: number; agents_seen: string[];
}

const num = (x: unknown): number => (typeof x === 'number' && isFinite(x) ? x : 0);
const pct = (n: number, d: number): number => (d > 0 ? Math.round((n / d) * 1000) / 10 : 0);

function newInvestigation(r: RunRow): Investigation {
  return {
    code: r.code, incident_id: r.incident_id, started_at: r.created_at, retrieval: 'unknown',
    evidence_facts: 0, dropped_facts: 0, hypotheses: 0, grounded_hypotheses: 0, cited_evidence: 0,
    supported: 0, rejected: 0, rejections: [], has_report: false, report_summary: null,
    tokens: 0, latency_ms: 0, agents_seen: [],
  };
}

function detectRetrieval(r: RunRow): string {
  const tools = Array.isArray(r.tools_used) ? (r.tools_used as string[]) : [];
  if (tools.includes('getIncidentEvents')) return 'incident-scoped';
  if (tools.includes('queryEventsForEntity')) return 'entity-fallback';
  return 'unknown';
}

// One investigation = a maximal run of [evidence-collector -> hypothesis ->
// verifier -> report?]. A fresh evidence-collector run starts a new one, so an
// incident investigated twice (e.g. a rejected attempt then a fixed one) yields
// two rows — each a real, separately-measurable data point.
export function groupInvestigations(runs: RunRow[]): Investigation[] {
  const out: Investigation[] = [];
  const measured = new Set<Investigation>();
  let evidenceIds = new Set<string>();
  let cur: Investigation | null = null;
  for (const r of runs) {
    if (r.agent === 'evidence-collector' || cur === null) {
      cur = newInvestigation(r);
      evidenceIds = new Set();
      out.push(cur);
    }
    cur.tokens += num(r.tokens);
    cur.latency_ms += num(r.latency_ms);
    cur.agents_seen.push(r.agent);

    if (r.agent === 'evidence-collector') {
      const ev = Array.isArray(r.output?.evidence) ? r.output.evidence : [];
      evidenceIds = new Set(ev.map((e: { evidence_id: string }) => e.evidence_id));
      cur.evidence_facts = ev.length;
      const uc = Array.isArray(r.unsupported_claims) ? r.unsupported_claims : [];
      cur.dropped_facts = num(uc[0]?.dropped_facts_with_bad_citations);
      cur.retrieval = detectRetrieval(r);
    } else if (r.agent === 'hypothesis-attack') {
      const hs: Hypo[] = Array.isArray(r.output?.hypotheses) ? r.output.hypotheses : [];
      cur.hypotheses = hs.length;
      cur.grounded_hypotheses = hs.filter((h) => (h.citations?.length ?? 0) > 0
        && h.citations.every(c => evidenceIds.has(c))).length;
      cur.cited_evidence = new Set(hs.flatMap((h) => h.citations ?? [])).size;
    } else if (r.agent === 'verifier') {
      if (r.status !== 'skipped') measured.add(cur);
      cur.supported = Array.isArray(r.output?.supported) ? r.output.supported.length : 0;
      const uc: Rejected[] = Array.isArray(r.unsupported_claims) ? r.unsupported_claims : [];
      cur.rejected = uc.length;
      cur.rejections = uc.map((u) => ({ statement: u.statement ?? '', reason: u.reason ?? '' }));
    } else if (r.agent === 'report-writer') {
      cur.has_report = r.status !== 'skipped' && typeof r.output?.summary === 'string';
      cur.report_summary = typeof r.output?.summary === 'string' ? r.output.summary : null;
    }
  }
  // Only count investigations that actually reached the verifier (a complete
  // measurable unit); an evidence-only stub (e.g. an aborted run) is dropped.
  return out.filter((i) => measured.has(i));
}

async function main(): Promise<void> {
  const runs = await q<RunRow>(
    `select i.code, r.incident_id, r.agent, r.status, r.created_at,
            r.tokens, r.latency_ms, r.tools_used, r.output, r.unsupported_claims, r.citations
       from agent_runs r
       join incidents i on i.incident_id = r.incident_id
      order by i.code, r.created_at`,
  );
  const invs = groupInvestigations(runs);
  if (invs.length === 0) {
    console.log('no completed investigations found in agent_runs — run `npm run investigate` first');
    return;
  }

  // ---- aggregate ------------------------------------------------------------
  const sum = (f: (i: Investigation) => number) => invs.reduce((a, i) => a + f(i), 0);
  const totalHyp = sum((i) => i.hypotheses);
  const grounded = sum((i) => i.grounded_hypotheses);
  const supported = sum((i) => i.supported);
  const rejected = sum((i) => i.rejected);
  const evidenceFacts = sum((i) => i.evidence_facts);
  const droppedFacts = sum((i) => i.dropped_facts);
  const tokens = sum((i) => i.tokens);
  const latency = sum((i) => i.latency_ms);

  const aggregate = {
    investigations: invs.length,
    incidents: new Set(invs.map((i) => i.incident_id)).size,
    evidence_facts_collected: evidenceFacts,
    facts_dropped_by_grounding_gate: droppedFacts,
    total_claims: totalHyp,
    grounded_claims: grounded,
    claim_grounding_coverage_pct: pct(grounded, totalHyp),
    verifier_supported_claims: supported,
    verifier_rejected_claims: rejected,
    unsupported_claim_rate_pct: pct(rejected, totalHyp),
    avg_tokens_per_investigation: Math.round(tokens / invs.length),
    avg_latency_ms_per_investigation: Math.round(latency / invs.length),
  };

  // ---- verifier ON vs OFF (decision #2: derived from the same stored runs) --
  const verifier_comparison = {
    note: 'Both arms derive from the SAME stored investigations — no second LLM pass. '
      + '"Without verifier" ships every hypothesis (including the ones the verifier rejected); '
      + '"with verifier" ships only verifier-supported hypotheses.',
    without_verifier: {
      claims_asserted: totalHyp,
      unsupported_claims_asserted: rejected,
      unsupported_rate_pct: pct(rejected, totalHyp),
    },
    with_verifier: {
      claims_asserted: supported,
      unsupported_claims_asserted: 0,
      unsupported_rate_pct: 0,
    },
    claims_blocked_by_verifier: rejected,
    rejected_examples: invs.flatMap((i) =>
      i.rejections.map((r) => ({ incident: i.code, statement: r.statement, reason: r.reason })),
    ),
  };

  const report = {
    generated_at: new Date().toISOString(),
    source: 'stored agent_runs (no new LLM calls)',
    aggregate,
    verifier_comparison,
    per_investigation: invs,
  };

  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify(report, null, 2));

  // ---- readable stdout ------------------------------------------------------
  const pad = (s: unknown, n: number) => String(s ?? '').padEnd(n);
  console.log(`\nInvestigation evaluation — ${invs.length} investigations over ${aggregate.incidents} incidents`);
  console.log('='.repeat(92));
  console.log(pad('incident', 16) + pad('retrieval', 17) + pad('ev', 4) + pad('hyp', 5)
    + pad('sup', 5) + pad('rej', 5) + pad('tokens', 8) + pad('ms', 8) + 'report');
  console.log('-'.repeat(92));
  for (const i of invs) {
    console.log(pad(i.code, 16) + pad(i.retrieval, 17) + pad(i.evidence_facts, 4) + pad(i.hypotheses, 5)
      + pad(i.supported, 5) + pad(i.rejected, 5) + pad(i.tokens, 8) + pad(i.latency_ms, 8)
      + (i.has_report ? 'yes' : 'NO (all rejected)'));
  }
  console.log('-'.repeat(92));
  console.log(`grounding coverage: ${aggregate.claim_grounding_coverage_pct}%   `
    + `unsupported-claim rate: ${aggregate.unsupported_claim_rate_pct}%   `
    + `rejected: ${rejected}`);
  console.log('\nVerifier OFF vs ON:');
  console.log(`  OFF: ${totalHyp} claims asserted, ${rejected} unsupported (${verifier_comparison.without_verifier.unsupported_rate_pct}%)`);
  console.log(`  ON : ${supported} claims asserted, 0 unsupported (0%)  -> verifier blocked ${rejected}`);
  if (verifier_comparison.rejected_examples.length > 0) {
    console.log('\nClaims the verifier refused to assert:');
    for (const r of verifier_comparison.rejected_examples) {
      console.log(`  [${r.incident}] "${r.statement}"\n      -> ${r.reason}`);
    }
  }
  console.log(`\nwrote ${OUT}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(closeDb);
