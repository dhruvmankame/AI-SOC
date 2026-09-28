import { useEffect, useState } from 'react'
import type {
  AgentRunRow, AttackKbRow, EvidenceRow, IncidentEntityRow, IncidentRow,
  RejectedClaim, ReportOutput, TimelineRow, VerifierVerdict,
} from '../lib/types'
import {
  fetchAgentRuns, fetchAttackKb, fetchEvidence, fetchIncident,
  fetchIncidentEntities, fetchTimeline,
} from '../lib/api'
import { ConfidenceMeter, RiskPill, StatusBadge, VerdictBadges } from '../components/ui'

interface RecordData {
  incident: IncidentRow | null
  entities: IncidentEntityRow[]
  evidence: EvidenceRow[]
  runs: AgentRunRow[]
  timeline: TimelineRow[]
  kb: Map<string, AttackKbRow>
}

// Pull the verifier verdicts out of that agent's run.output ({verdicts, supported}).
function verdictsOf(runs: AgentRunRow[]): { verdicts: VerifierVerdict[]; rejected: RejectedClaim[] } {
  const v = runs.find((r) => r.agent === 'verifier')
  if (!v) return { verdicts: [], rejected: [] }
  const out = v.output as { verdicts?: VerifierVerdict[] } | VerifierVerdict[]
  const verdicts = Array.isArray(out) ? out : (out?.verdicts ?? [])
  const rejected = Array.isArray(v.unsupported_claims) ? (v.unsupported_claims as RejectedClaim[]) : []
  return { verdicts, rejected }
}

export function IncidentRecord({ incidentId, onBack }: { incidentId: string; onBack: () => void }) {
  const [d, setD] = useState<RecordData | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    setD(null)
    setErr(null)
    Promise.all([
      fetchIncident(incidentId), fetchIncidentEntities(incidentId), fetchEvidence(incidentId),
      fetchAgentRuns(incidentId), fetchTimeline(incidentId), fetchAttackKb(),
    ])
      .then(([incident, entities, evidence, runs, timeline, kb]) => {
        if (live) setD({ incident, entities, evidence, runs, timeline, kb })
      })
      .catch((e) => live && setErr(String(e.message ?? e)))
    return () => { live = false }
  }, [incidentId])

  if (err) return <div className="status-line">Failed to load: {err}</div>
  if (!d) return <div className="status-line">Loading incident record…</div>
  if (!d.incident) return <div className="status-line">Incident not found.</div>

  const inc = d.incident
  const primaryTech = inc.mitre_techniques?.[0]
  const attackType = (primaryTech && d.kb.get(primaryTech)?.name) || inc.title || 'Incident'
  const report = (d.runs.find((r) => r.agent === 'report-writer')?.output as ReportOutput | undefined)
  const { verdicts, rejected } = verdictsOf(d.runs)
  const investigated = d.runs.length > 0
  const byRole = new Map<string, IncidentEntityRow[]>()
  for (const e of d.entities) {
    const k = e.role ?? 'other'
    byRole.set(k, [...(byRole.get(k) ?? []), e])
  }

  return (
    <div className="record">
      <button className="theme-toggle back" onClick={onBack}>← Incidents</button>

      <header className="rec-head">
        <div>
          <div className="rec-code">{inc.code}</div>
          <h2 className="rec-title">{attackType}</h2>
          <div className="rec-meta">
            {primaryTech && <span className="mitre">{primaryTech}</span>}
            <span className="chip">{inc.title}</span>
          </div>
        </div>
        <div className="rec-badges">
          <RiskPill risk={inc.risk_score} />
          <StatusBadge status={inc.status} />
        </div>
      </header>

      {!investigated && (
        <div className="callout info">
          Agents have not finished investigating this incident yet. Evidence, the report, and the
          verifier verdicts appear here once the run completes (poll the Analyze page for progress).
        </div>
      )}

      {/* Summary — the report headline (incidents.summary). A fully-rejected
          incident has none: the verifier found no evidence-backed hypothesis. */}
      <section className="card rec-summary">
        <h2>Summary</h2>
        {inc.summary ? (
          <p className="prose">{inc.summary}</p>
        ) : (
          <p className="prose muted">
            No report was written for this incident{rejected.length > 0
              ? ' — every hypothesis was rejected by the verifier for lacking evidence.'
              : investigated ? '.' : ' yet.'}
          </p>
        )}
      </section>

      {/* Agent report — narrative + recommended actions (report-writer run). */}
      {report && (
        <section className="card">
          <h2>Agent report</h2>
          <p className="prose">{report.narrative}</p>
          {report.recommended_actions?.length > 0 && (
            <>
              <h4 className="sub-h">Recommended actions</h4>
              <ul className="actions">
                {report.recommended_actions.map((a, i) => <li key={i}>{a}</li>)}
              </ul>
            </>
          )}
        </section>
      )}

      {/* Verifier verdicts — the graded safety property. Rejections are shown
          in full: the verifier refuses any hypothesis it can't ground in cited
          evidence, so a rejected claim is a feature, not a gap. */}
      {(verdicts.length > 0 || rejected.length > 0) && (
        <section className="card">
          <h2>Verifier verdicts</h2>
          <VerdictBadges
            supported={verdicts.filter((v) => v.supported).length}
            rejected={rejected.length}
          />
          <div className="verdicts-list">
            {verdicts.filter((v) => v.supported).map((v) => (
              <div className="verdict ok" key={v.hypothesis_id}>
                <span className="mark">✓</span>
                <div><div className="vh">{v.hypothesis_id}</div><div className="vr">{v.reason}</div></div>
              </div>
            ))}
            {rejected.map((r, i) => (
              <div className="verdict rej" key={r.hypothesis_id ?? i}>
                <span className="mark">✗</span>
                <div>
                  <div className="vh">{r.statement}</div>
                  <div className="vr">Rejected: {r.reason}</div>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="grid-2">
        {/* Evidence — each fact cites the event_ids it is grounded in. */}
        <section className="card">
          <h2>Evidence ({d.evidence.length})</h2>
          {d.evidence.length === 0 ? (
            <p className="prose muted">No evidence collected.</p>
          ) : (
            <div className="ev-list">
              {d.evidence.map((e) => (
                <div className="ev-item" key={e.evidence_id}>
                  <div className="ev-top">
                    <span className="chip">{e.kind}</span>
                    <ConfidenceMeter value={e.confidence} />
                  </div>
                  <div className="ev-fact">{e.fact}</div>
                  <div className="ev-cites">
                    {(e.source_event_ids ?? []).slice(0, 8).map((id) => (
                      <span className="cite" key={id} title={id}>{id.slice(0, 8)}</span>
                    ))}
                    {(e.source_event_ids?.length ?? 0) > 8 && (
                      <span className="cite more">+{(e.source_event_ids!.length - 8)}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Entities — grouped by role (actor / target / victim / …). */}
        <section className="card">
          <h2>Entities ({d.entities.length})</h2>
          {d.entities.length === 0 ? (
            <p className="prose muted">No entities.</p>
          ) : (
            [...byRole.entries()].map(([role, ents]) => (
              <div className="ent-group" key={role}>
                <h4 className="sub-h">{role}</h4>
                <div className="ent-chips">
                  {ents.map((e) => (
                    <span className="ent" key={`${e.entity_type}:${e.entity_value}`}>
                      <span className="et">{e.entity_type}</span> {e.entity_value}
                    </span>
                  ))}
                </div>
              </div>
            ))
          )}
        </section>
      </div>

      {/* Attack timeline — one entry per grounded evidence fact. */}
      {d.timeline.length > 0 && (
        <section className="card">
          <h2>Timeline</h2>
          <div className="timeline">
            {d.timeline.map((t) => (
              <div className="tl-row" key={t.id}>
                <span className="tl-ts">{t.ts.replace('T', ' ').slice(0, 19)}</span>
                <span className="tl-dot" aria-hidden="true" />
                <span className="tl-label">{t.label}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Agent-run audit — the auditable trail: which agent ran, its outcome,
          tools used, and cost. Grounds the "evidence-first" claim. */}
      {d.runs.length > 0 && (
        <section className="card">
          <h2>Agent run audit</h2>
          <div className="table-wrap">
            <table className="alerts">
              <thead>
                <tr>
                  <th>Agent</th><th>Status</th><th>Tools</th>
                  <th className="num">Citations</th><th className="num">Tokens</th><th className="num">Latency</th>
                </tr>
              </thead>
              <tbody>
                {d.runs.map((r) => (
                  <tr key={r.run_id} style={{ cursor: 'default' }}>
                    <td>{r.agent}</td>
                    <td><span className="chip">{r.status}</span></td>
                    <td className="entity">
                      {(Array.isArray(r.tools_used) ? r.tools_used : []).join(', ') || '—'}
                    </td>
                    <td className="num">{r.citations?.length ?? 0}</td>
                    <td className="num">{r.tokens ?? '—'}</td>
                    <td className="num">{r.latency_ms != null ? `${r.latency_ms} ms` : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}
