import { mock, test } from 'node:test';
import assert from 'node:assert/strict';

let response: any = {};
let calls = 0;
let events: any[] = [];
let signals: any[] = [];
const audit: any[] = [];
const writes: any[] = [];
mock.module('../src/env.js', { namedExports: { ENV: { maxTokens: 1000 } } });
mock.module('../src/db.js', { namedExports: { q: async () => [], closeDb: async () => {} } });
mock.module('../src/llm.js', { namedExports: {
  reason: async () => { calls++; return { parsed: Array.isArray(response) ? response.shift() : response, tokens: 10 }; },
} });
mock.module('../src/tools.js', { namedExports: {
  getIncident: async () => ({ code: 'INC-TEST', title: 'DDoS', risk_score: 90, mitre_techniques: ['T1498'] }),
  getIncidentEntities: async () => [], getIncidentEvents: async () => events,
  queryEventsForEntity: async () => [], getSignalsForEvents: async () => signals,
  insertEvidence: async (rows: any) => writes.push(rows),
  recordAgentRun: async (row: any) => audit.push(row),
  searchAttackKb: async () => [], writeReport: async () => writes.push('report'),
  insertTimeline: async () => {},
} });
const { runEvidenceCollector } = await import('../src/agents/evidence.js');
const { runVerifier } = await import('../src/agents/verifier.js');
const { socGraph } = await import('../src/graph.js');
const { runReportWriter } = await import('../src/agents/report.js');
const { groupInvestigations } = await import('../src/eval.js');

test('collector rejects an entire fact when any citation is invented', async () => {
  events = [{ event_id: 'real', ts: '2026-01-01', src_ip: null, dst_ip: null,
    severity: 'high', mitre_tags: [], template_text: '', raw: '' }];
  response = { evidence: [
    { fact: 'mixed citations', kind: 'event', source_event_ids: ['real', 'invented'], confidence: 1 },
    { fact: 'grounded', kind: 'event', source_event_ids: ['real'], confidence: 1 },
    { fact: 'uncited', kind: 'event', source_event_ids: [], confidence: 1 },
  ] };
  const result = await runEvidenceCollector('incident');
  assert.equal(result.droppedForBadCitations, 2);
  assert.deepEqual(result.evidence.map(e => e.fact), ['grounded']);
});

const evidence: any[] = [{ evidence_id: 'EV-1', source_event_ids: ['real'], fact: 'Dataset annotation', kind: 'event', confidence: 1 }];
const hypothesis = (citations: string[], technique = 'T1498'): any => ({ id: 'H-1', statement: 'Flood', technique, citations, confidence: 1, recommended_actions: [] });

test('missing or invented citations fail without an LLM call', async () => {
  for (const citations of [[], ['invented']]) {
    calls = 0;
    const result = await runVerifier('incident', [hypothesis(citations)], evidence);
    assert.equal(result.supported.length, 0);
    assert.equal(result.rejected.length, 1);
    assert.equal(calls, 0);
  }
});

test('contradictory detector families fail before entailment', async () => {
  signals = [{ event_id: 'real', detector: 'rule', detector_ref: 'R-NET-FLOOD', score: 0.97 }];
  calls = 0;
  const result = await runVerifier('incident', [hypothesis(['EV-1'], 'T1110')], evidence);
  assert.equal(result.supported.length, 0);
  assert.equal(calls, 0);
});

test('an omitted verifier verdict fails closed', async () => {
  signals = []; response = { verdicts: [] };
  const result = await runVerifier('incident', [hypothesis(['EV-1'])], evidence);
  assert.equal(result.supported.length, 0);
  assert.match(result.rejected[0]!.reason, /no verifier verdict/);
});

test('annotation-only confidence stays at or below 50 percent', async () => {
  signals = [{ event_id: 'real', detector: 'label', detector_ref: 'LBL-DDOS', score: 0.5 }];
  response = { verdicts: [{ hypothesis_id: 'H-1', supported: true, evidence_strength: 1, reason: 'annotation' }] };
  const result = await runVerifier('incident', [hypothesis(['EV-1'])], evidence);
  assert.equal(result.assessment[0]!.confidence_pct, 50);
  assert.equal(result.assessment[0]!.basis, 'annotation-only');
  assert.equal(result.assessment[0]!.corroborated_by_detector, false);
});

test('empty evidence traverses four audited stages and writes no report', async () => {
  events = []; signals = []; response = { evidence: [] }; audit.length = 0; writes.length = 0;
  const result = await socGraph.invoke({ incidentId: 'incident', incidentCode: 'INC-TEST' });
  assert.equal(result.report, null);
  assert.deepEqual(audit.map(a => a.agent), ['evidence-collector', 'hypothesis-attack', 'verifier', 'report-writer']);
  assert.equal(writes.includes('report'), false);
});

test('mixed hypothesis citations remain intact and prevent a report', async () => {
  events = [{ event_id: 'real', ts: '2026-01-01', src_ip: null, dst_ip: null,
    severity: 'high', mitre_tags: [], template_text: '', raw: '' }];
  signals = []; audit.length = 0; writes.length = 0; calls = 0;
  response = [
    { evidence: [{ fact: 'a flow', kind: 'event', source_event_ids: ['real'], confidence: 1 }] },
    { hypotheses: [{ statement: 'Flood', technique: 'T1498',
      citations: ['EV-INC-TEST-1', 'invented'], confidence: 1, recommended_actions: [] }] },
  ];
  const result = await socGraph.invoke({ incidentId: 'incident', incidentCode: 'INC-TEST' });
  assert.equal(result.report, null);
  assert.equal(result.rejected.length, 1);
  assert.match(result.rejected[0].reason, /invented/);
  assert.equal(calls, 2);
  assert.equal(audit.length, 4);
  assert.equal(audit[3].status, 'skipped');
  assert.equal(writes.includes('report'), false);
});

test('report writer refuses an empty verified set even outside the graph', async () => {
  calls = 0;
  await assert.rejects(runReportWriter('incident', [], [], new Map()), /verified finding/);
  assert.equal(calls, 0);
});

test('evaluation resolves grounding IDs and does not count skipped reports', () => {
  const row = (agent: string, output: any, status = 'ok'): any => ({ agent, output, status,
    code: 'INC-TEST', incident_id: 'incident', created_at: '2026-01-01', tokens: 0,
    latency_ms: 0, tools_used: [], unsupported_claims: [], citations: [] });
  const result = groupInvestigations([
    row('evidence-collector', { evidence }),
    row('hypothesis-attack', { hypotheses: [hypothesis(['EV-1', 'invented'])] }),
    row('verifier', { supported: [] }),
    row('report-writer', { skipped: true }, 'skipped'),
  ]);
  assert.equal(result.length, 1);
  assert.equal(result[0]!.grounded_hypotheses, 0);
  assert.equal(result[0]!.has_report, false);
  assert.equal(groupInvestigations([
    row('evidence-collector', { evidence: [] }), row('verifier', { skipped: true }, 'skipped'),
  ]).length, 0);
});

test('browser mode pauses after verification without calling or auditing the report writer', async () => {
  events = [{ event_id: 'real', ts: '2026-01-01', src_ip: null, dst_ip: null,
    severity: 'high', mitre_tags: [], template_text: '', raw: '' }];
  signals = []; audit.length = 0; writes.length = 0; calls = 0;
  response = [
    { evidence: [{ fact: 'a flow', kind: 'event', source_event_ids: ['real'], confidence: 1 }] },
    { hypotheses: [{ statement: 'Flow observed', technique: 'T1498', citations: ['EV-INC-TEST-1'], confidence: 1, recommended_actions: [] }] },
    { verdicts: [{ hypothesis_id: 'H-INC-TEST-1', supported: true, evidence_strength: 1, reason: 'grounded' }] },
  ];
  const result = await socGraph.invoke({ incidentId: 'incident', incidentCode: 'INC-TEST', autoReport: false });
  assert.equal(result.reportPending, true);
  assert.equal(result.report, null);
  assert.equal(result.supported.length, 1);
  assert.equal(calls, 3);
  assert.equal(audit.length, 3);
  assert.equal(writes.includes('report'), false);
});
