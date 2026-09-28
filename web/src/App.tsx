import { useEffect, useState } from 'react'
import type { Mode } from './lib/palette'
import type { BatchFilter } from './lib/api'
import type { BatchRow } from './lib/types'
import { fetchBatches } from './lib/api'
import { Overview } from './pages/Overview'
import { AlertQueue } from './pages/AlertQueue'
import { Analyze } from './pages/Analyze'
import { Incidents } from './pages/Incidents'
import { IncidentRecord } from './pages/IncidentRecord'

type Page = 'overview' | 'analyze' | 'incidents' | 'alerts' | 'incident'

const PAGES: { id: Page; label: string; icon: string }[] = [
  { id: 'overview', label: 'Overview', icon: '▚' },
  { id: 'analyze', label: 'Analyze', icon: '⇪' },
  { id: 'incidents', label: 'Incidents', icon: '◇' },
  { id: 'alerts', label: 'Alert Queue', icon: '▤' },
]

const TITLES: Record<Page, { h1: string; p: string }> = {
  overview: { h1: 'Overview', p: 'Ingest health, event mix, and detection volume' },
  analyze: { h1: 'Analyze', p: 'Upload a flow log → detect attacks → auto-investigate' },
  incidents: { h1: 'Incidents', p: 'Detected attacks with attack type, risk, and verifier status' },
  alerts: { h1: 'Alert Queue', p: 'Deduplicated alerts with per-detector evidence' },
  incident: { h1: 'Incident Record', p: 'Evidence, agent report, verifier verdicts, and audit trail' },
}

function batchLabel(b: BatchRow): string {
  const name = b.label || b.source_filename || b.batch_id.slice(0, 8)
  return b.incident_count != null ? `${name} (${b.incident_count})` : name
}

export default function App() {
  const [page, setPage] = useState<Page>('overview')
  const [selectedBatch, setSelectedBatch] = useState<BatchFilter>('all')
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null)
  const [batches, setBatches] = useState<BatchRow[]>([])
  const [mode, setMode] = useState<Mode>(
    () => (localStorage.getItem('theme') as Mode) || 'dark',
  )

  useEffect(() => {
    document.documentElement.dataset.theme = mode
    localStorage.setItem('theme', mode)
  }, [mode])

  function loadBatches() {
    fetchBatches().then(setBatches).catch(() => setBatches([]))
  }
  useEffect(loadBatches, [])

  function openIncident(id: string) {
    setSelectedIncidentId(id)
    setPage('incident')
  }

  const t = TITLES[page]

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">AI<span>·</span>SOC</div>
        {PAGES.map((p) => (
          <button
            key={p.id}
            className={`nav-item ${page === p.id || (p.id === 'incidents' && page === 'incident') ? 'active' : ''}`}
            onClick={() => setPage(p.id)}
          >
            <span aria-hidden="true">{p.icon}</span> {p.label}
          </button>
        ))}
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <h1>{t.h1}</h1>
            <p>{t.p}</p>
          </div>
          <div className="topbar-tools">
            <label className="batch-select">
              <span>Batch</span>
              <select value={selectedBatch} onChange={(e) => setSelectedBatch(e.target.value)}>
                <option value="all">All batches</option>
                <option value="seed">CICIDS Seed (baseline)</option>
                {batches.map((b) => (
                  <option key={b.batch_id} value={b.batch_id}>{batchLabel(b)}</option>
                ))}
              </select>
            </label>
            <button className="theme-toggle" onClick={() => setMode(mode === 'dark' ? 'light' : 'dark')}>
              {mode === 'dark' ? '☀ Light' : '☾ Dark'}
            </button>
          </div>
        </header>

        {page === 'overview' && <Overview mode={mode} batchId={selectedBatch} />}
        {page === 'alerts' && <AlertQueue batchId={selectedBatch} />}
        {page === 'analyze' && (
          <Analyze
            onUploaded={(batchId) => { setSelectedBatch(batchId); loadBatches() }}
            onOpenIncident={openIncident}
          />
        )}
        {page === 'incidents' && <Incidents batchId={selectedBatch} onOpen={openIncident} />}
        {page === 'incident' && selectedIncidentId && (
          <IncidentRecord incidentId={selectedIncidentId} onBack={() => setPage('incidents')} />
        )}
      </main>
    </div>
  )
}
