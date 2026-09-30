import { useEffect, useState } from 'react'
import type { AttackKbRow, IncidentRow } from '../lib/types'
import type { BatchFilter } from '../lib/api'
import { fetchIncidents, fetchAttackKb, fetchVerifierCounts } from '../lib/api'
import { RiskPill, StatusBadge, VerdictBadges } from '../components/ui'

type Counts = Map<string, { supported: number; rejected: number }>

// Attack type = human name of the incident's primary MITRE technique (from the
// ATT&CK KB), falling back to the incident title.
function attackType(inc: IncidentRow, kb: Map<string, AttackKbRow>): string {
  const t = inc.mitre_techniques?.[0]
  return (t && kb.get(t)?.name) || inc.title || '—'
}

export function Incidents({
  batchId,
  onOpen,
}: {
  batchId: BatchFilter
  onOpen: (incidentId: string) => void
}) {
  const [rows, setRows] = useState<IncidentRow[] | null>(null)
  const [kb, setKb] = useState<Map<string, AttackKbRow>>(new Map())
  const [counts, setCounts] = useState<Counts>(new Map())
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    setRows(null)
    setErr(null)
    Promise.all([fetchIncidents(batchId), fetchAttackKb()])
      .then(async ([incs, kbMap]) => {
        if (!live) return
        setKb(kbMap)
        setRows(incs)
        // Second round-trip (not N+1): verifier verdicts for all incidents at once.
        const c = await fetchVerifierCounts(incs.map((i) => i.incident_id))
        if (live) setCounts(c)
      })
      .catch((e) => live && setErr(String(e.message ?? e)))
    return () => { live = false }
  }, [batchId])

  if (err) return <div className="status-line">Failed to load: {err}</div>
  if (!rows) return <div className="status-line">Loading incidents…</div>
  if (rows.length === 0)
    return (
      <div className="status-line">
        No incidents in this batch. Upload a flow CSV on the <strong>Analyze</strong> page to detect some.
      </div>
    )

  return (
    <div className="card">
      <h2>{rows.length} incidents · ranked by risk</h2>
      <div className="table-wrap">
        <table className="alerts">
          <thead>
            <tr>
              <th style={{ width: 70 }}>Risk</th>
              <th>Attack type</th>
              <th style={{ width: 90 }}>Technique</th>
              <th>Incident</th>
              <th style={{ width: 140 }}>Status</th>
              <th style={{ width: 210 }}>Verifier</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((inc) => {
              const c = counts.get(inc.incident_id)
              return (
                <tr key={inc.incident_id} onClick={() => onOpen(inc.incident_id)}>
                  <td><RiskPill risk={inc.risk_score} /></td>
                  <td>{attackType(inc, kb)}</td>
                  <td className="entity">{inc.mitre_techniques?.[0] ?? '—'}</td>
                  <td>
                    <div>{inc.title}</div>
                    <div className="chip" style={{ marginTop: 4 }}>{inc.code}</div>
                  </td>
                  <td><StatusBadge status={inc.status} /></td>
                  <td>
                    {c ? (
                      <VerdictBadges supported={c.supported} rejected={c.rejected} />
                    ) : (
                      <span className="entity">
                        {inc.summary ? 'report ready' : 'not yet investigated'}
                      </span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
