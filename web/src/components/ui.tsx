import type { Severity } from '../lib/types'
import { SEVERITY_COLOR } from '../lib/palette'

// Severity = reserved status color + a text label (never color alone).
export function SeverityBadge({ severity }: { severity: Severity }) {
  const color = SEVERITY_COLOR[severity]
  return (
    <span className="badge" style={{ color, background: `${color}22` }}>
      <span className="dot" aria-hidden="true" />
      <span>{severity}</span>
    </span>
  )
}

// Risk score (0–100) → reserved status band + numeric label (never color alone).
export function RiskPill({ risk }: { risk: number }) {
  const band: Severity = risk >= 80 ? 'critical' : risk >= 60 ? 'high' : risk >= 40 ? 'medium' : 'low'
  const color = SEVERITY_COLOR[band]
  return (
    <span className="badge" style={{ color, background: `${color}22` }} title={`risk band: ${band}`}>
      <span className="dot" aria-hidden="true" />
      <span>{Math.round(risk)}</span>
    </span>
  )
}

// Incident lifecycle status. Investigating uses the accent; terminal-good
// states use the "good" status hue; open/false-positive stay muted.
const STATUS_COLOR: Record<string, string> = {
  open: '#898781',
  investigating: '#2a78d6',
  contained: '#1baf7a',
  closed: '#1baf7a',
  false_positive: '#898781',
}
export function StatusBadge({ status }: { status: string }) {
  const color = STATUS_COLOR[status] ?? '#898781'
  return (
    <span className="badge" style={{ color, background: `${color}22` }}>
      <span className="dot" aria-hidden="true" />
      <span>{status.replace(/_/g, ' ')}</span>
    </span>
  )
}

// Verifier outcome — supported vs rejected counts, each with an icon + label
// (never color alone). Rejections are the graded safety property, so they are
// always shown, in the "warning" hue.
export function VerdictBadges({ supported, rejected }: { supported: number; rejected: number }) {
  return (
    <span className="verdicts">
      <span className="v ok" title="hypotheses supported by evidence">✓ {supported} supported</span>
      <span className={`v ${rejected > 0 ? 'rej' : 'none'}`} title="hypotheses rejected by the verifier">
        ✗ {rejected} rejected
      </span>
    </span>
  )
}


export function StatTile({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="tile">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {sub && <div className="sub">{sub}</div>}
    </div>
  )
}

export function ConfidenceMeter({ value }: { value: number }) {
  const pct = Math.round(value * 100)
  return (
    <div className="meter">
      <div className="bar">
        <div className="fill" style={{ width: `${pct}%` }} />
      </div>
      <span className="pct">{pct}%</span>
    </div>
  )
}

// Per-detector "why" — each detector that contributed to the alert + its score.
export function Contributions({ contributions }: { contributions: Record<string, number> }) {
  const entries = Object.entries(contributions).sort((a, b) => b[1] - a[1])
  return (
    <div className="contribs">
      {entries.map(([name, score]) => (
        <div className="contrib" key={name}>
          <span className="name">{name}</span>
          <span className="track">
            <span className="val" style={{ width: `${Math.round(score * 100)}%` }} />
          </span>
          <span className="score">{score.toFixed(2)}</span>
        </div>
      ))}
    </div>
  )
}
