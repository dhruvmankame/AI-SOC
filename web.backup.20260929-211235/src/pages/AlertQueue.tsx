import { Fragment, useEffect, useState } from 'react'
import type { AlertRow, EventRow } from '../lib/types'
import { fetchAlerts, fetchEventsByIds } from '../lib/api'
import type { BatchFilter } from '../lib/api'
import { SeverityBadge, ConfidenceMeter, Contributions } from '../components/ui'

function EvidenceEvents({ ids }: { ids: string[] }) {
  const [rows, setRows] = useState<EventRow[] | null>(null)
  useEffect(() => { fetchEventsByIds(ids.slice(0, 25)).then(setRows).catch(() => setRows([])) }, [ids])
  if (!rows) return <div className="ev-events">loading events…</div>
  return (
    <div className="ev-events">
      {rows.map((e) => (
        <div className="ev-row" key={e.event_id}>
          <span className="t">{e.ts.slice(11, 19)}</span>
          <span>{e.source_type}</span>
          <span>{e.user ?? e.host ?? e.src_ip ?? '—'}</span>
          <span>{e.outcome ?? ''}</span>
          <span>{e.mitre_tags?.map((m) => <span className="mitre" key={m}>{m}</span>)}</span>
        </div>
      ))}
    </div>
  )
}

export function AlertQueue({ batchId }: { batchId: BatchFilter }) {
  const [alerts, setAlerts] = useState<AlertRow[] | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [open, setOpen] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    setAlerts(null)
    setErr(null)
    fetchAlerts(batchId)
      .then((a) => live && setAlerts(a))
      .catch((e) => live && setErr(String(e.message ?? e)))
    return () => { live = false }
  }, [batchId])

  if (err) return <div className="status-line">Failed to load: {err}</div>
  if (!alerts) return <div className="status-line">Loading alerts…</div>
  if (alerts.length === 0) return <div className="status-line">No alerts. Run <code>build_alerts()</code> against the database.</div>

  return (
    <div className="card">
      <h2>{alerts.length} alerts · deduplicated from raw signals</h2>
      <div className="table-wrap">
        <table className="alerts">
          <thead>
            <tr>
              <th>Severity</th><th>Alert</th><th>Entity</th>
              <th>Detectors</th><th className="num">Events</th><th style={{ width: 150 }}>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => {
              const expanded = open === a.alert_id
              return (
                <Fragment key={a.alert_id}>
                  <tr
                    className={expanded ? 'expanded' : ''}
                    onClick={() => setOpen(expanded ? null : a.alert_id)}
                  >
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td>{a.title}</td>
                    <td className="entity">{a.entity ?? '—'}</td>
                    <td><span className="chip">{Object.keys(a.contributions).length} detector(s)</span></td>
                    <td className="num">{a.correlation_count}</td>
                    <td><ConfidenceMeter value={a.confidence} /></td>
                  </tr>
                  {expanded && (
                    <tr className="expanded">
                      <td colSpan={6}>
                        <div className="evidence-panel">
                          <h4>Why this fired — per-detector contributions</h4>
                          <Contributions contributions={a.contributions} />
                          <h4>Source events ({a.correlation_count})</h4>
                          <EvidenceEvents ids={a.event_ids} />
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
