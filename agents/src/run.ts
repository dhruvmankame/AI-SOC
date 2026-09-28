import { q, closeDb } from './db.js';
import { investigate } from './graph.js';

// ============================================================================
// CLI entrypoint:  npm run investigate [-- CODE|all]
//   npm run investigate                 -> all open incidents
//   npm run investigate -- INC-2017-0002 -> just that one (by code or id)
// Runs the orchestration graph and prints a before/after-style summary so the
// value the agents added (evidence, verdicts, report) is visible on stdout.
// ============================================================================

async function pickIncidents(arg?: string): Promise<{ incident_id: string; code: string; title: string }[]> {
  if (arg && arg !== 'all') {
    return q(
      `select incident_id, code, title from incidents where code = $1 or incident_id::text = $1`,
      [arg],
    );
  }
  return q(`select incident_id, code, title from incidents order by code`);
}

async function main() {
  const arg = process.argv[2];
  const incidents = await pickIncidents(arg);
  if (incidents.length === 0) {
    console.log('no matching incidents');
    return;
  }

  for (const inc of incidents) {
    console.log(`\n${'='.repeat(72)}\n▶ ${inc.code} — ${inc.title}\n${'='.repeat(72)}`);
    try {
      const s = await investigate(inc.incident_id);
      console.log(`  evidence collected : ${s.evidence.length}`);
      console.log(`  hypotheses formed  : ${s.hypotheses.length}`);
      console.log(`  verified / rejected: ${s.supported.length} / ${s.rejected.length}`);
      for (const r of s.rejected) {
        console.log(`    ✗ REJECTED ${r.hypothesis.id}: ${r.reason}`);
      }
      if (s.report) {
        console.log(`\n  SUMMARY: ${s.report.summary}`);
        console.log(`  actions: ${s.report.recommended_actions.map((a) => `\n    - ${a}`).join('')}`);
      } else {
        console.log('  (no report — nothing survived verification)');
      }
      console.log(`\n  tokens used: ${s.tokensUsed}`);
    } catch (err) {
      console.error(`  ERROR investigating ${inc.code}:`, err instanceof Error ? err.message : err);
    }
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(closeDb);
