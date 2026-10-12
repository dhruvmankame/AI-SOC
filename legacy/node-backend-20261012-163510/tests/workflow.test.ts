import { mock, test } from 'node:test';
import assert from 'node:assert/strict';
let runs: any[] = [];
let events: any[] = [];
mock.module('../src/env.js', { namedExports: { ENV: { maxTokens: 1000 } } });
mock.module('../src/db.js', { namedExports: { q: async (sql: string) => sql.includes('from incidents') ? [{ incident_id: 'incident' }] : sql.includes('from events') ? events : runs } });
const { loadWorkflow, reportContext } = await import('../src/workflow.js');
const run = (agent: string, output: any, status = 'ok', tokens = 10) => ({ agent, output, status, tokens });
function ready() {
  runs = [
    run('evidence-collector', { evidence: [{ evidence_id: 'EV-1', source_event_ids: ['event'], fact: 'Grounded fact' }] }, 'partial'),
    run('hypothesis-attack', { hypotheses: [{ id: 'H-1', citations: ['EV-1'] }] }),
    run('verifier', { supported: ['H-1'], verdicts: [{ hypothesis_id: 'H-1', supported: true }] }),
  ];
}
test('report requires verification and grounded citations, including partially filtered evidence', async () => {
  ready(); assert.equal((await loadWorkflow('incident'))!.canReport, true);
  runs[2].output.verdicts[0].supported = false;
  assert.equal((await loadWorkflow('incident'))!.canReport, false);
  ready(); runs[1].output.hypotheses[0].citations = ['invented'];
  assert.equal((await loadWorkflow('incident'))!.canReport, false);
});
test('a new or failed collector invalidates earlier verifier approvals', async () => {
  ready(); runs.push(run('evidence-collector', { error: 'service unavailable' }, 'error'));
  const w = (await loadWorkflow('incident'))!;
  assert.equal(w.canReport, false); assert.equal(w.runs.length, 1);
});
test('budget and existing reports prevent duplicate model calls', async () => {
  ready(); runs[0].tokens = 1000;
  assert.equal((await loadWorkflow('incident'))!.canReport, false);
  ready(); runs.push(run('report-writer', { summary: 'Saved report' }));
  const w = (await loadWorkflow('incident'))!;
  assert.equal(w.canReport, false); assert.equal(w.report?.summary, 'Saved report');
});
test('missing source events prevent report generation', async () => {
  ready(); events = [];
  await assert.rejects(() => reportContextResult(), /Source events are missing/);
  events = [{ event_id: 'event', ts: '2026-01-01T00:00:00Z' }];
  assert.equal((await reportContextResult()).size, 1);
});
async function reportContextResult() { return reportContext((await loadWorkflow('incident'))!); }
