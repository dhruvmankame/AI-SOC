import { useEffect, useState } from 'react'
import type { Mode } from '../lib/palette'
import { sourceColor } from '../lib/palette'
import type { OverviewStats } from '../lib/types'
import { fetchOverview } from '../lib/api'
import type { BatchFilter } from '../lib/api'
import { StatTile } from '../components/ui'
import { EventsBySourceChart, IngestChart, SeverityChart } from '../components/charts'

export function Overview({ mode, batchId }: { mode: Mode; batchId: BatchFilter }) {
  const [stats, setStats] = useState<OverviewStats | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    setStats(null)
    setErr(null)
    fetchOverview(batchId)
      .then((s) => live && setStats(s))
      .catch((e) => live && setErr(String(e.message ?? e)))
    return () => { live = false }
  }, [batchId])

  if (err) return <div className="status-line">Failed to load: {err}</div>
  if (!stats) return <div className="status-line">Loading telemetry…</div>

  const compression = stats.signals > 0 && stats.alerts > 0
    ? `${(stats.signals / stats.alerts).toFixed(1)}× vs signals`
    : undefined

  return (
    <>
      <div className="tiles">
        <StatTile label="Events" value={stats.events.toLocaleString()} sub="normalized (OCSF)" />
        <StatTile label="Signals" value={stats.signals} sub="raw detector hits" />
        <StatTile label="Alerts" value={stats.alerts} sub={compression} />
        <StatTile label="Incidents" value={stats.incidents} sub="correlated (Day 3)" />
        <StatTile label="Rules" value={stats.rules} sub="enabled detectors" />
      </div>

      <div className="grid-2">
        <div className="card">
          <h2>Ingest rate (events / min)</h2>
          <IngestChart data={stats.ingest} mode={mode} />
        </div>
        <div className="card">
          <h2>Event severity mix</h2>
          <SeverityChart data={stats.severityCounts} mode={mode} />
        </div>
      </div>

      <div className="card">
        <h2>Events by source</h2>
        <EventsBySourceChart data={stats.sourceCounts} mode={mode} />
        <div className="legend">
          {stats.sourceCounts.map((s) => (
            <span className="k" key={s.source_type}>
              <span className="swatch" style={{ background: sourceColor(s.source_type, mode) }} />
              {s.source_type} <span className="chip">{s.count}</span>
            </span>
          ))}
        </div>
      </div>
    </>
  )
}
