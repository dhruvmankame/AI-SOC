import {
  ResponsiveContainer, BarChart, Bar, Cell, XAxis, YAxis, CartesianGrid, Tooltip, AreaChart, Area,
} from 'recharts'
import type { Mode } from '../lib/palette'
import { CHROME, sourceColor, SEVERITY_COLOR, SEVERITY_ORDER } from '../lib/palette'
import type { OverviewStats, Severity } from '../lib/types'

function tooltipStyle(mode: Mode) {
  const c = CHROME[mode]
  return {
    contentStyle: { background: c.surface, border: `1px solid ${c.axis}`, borderRadius: 8, fontSize: 12, color: c.text },
    labelStyle: { color: c.textSecondary },
    itemStyle: { color: c.text },
    cursor: { fill: mode === 'dark' ? '#ffffff10' : '#0b0b0b08' },
  }
}

// Events by source — one measure across a categorical axis (identity on axis).
export function EventsBySourceChart({ data, mode }: { data: OverviewStats['sourceCounts']; mode: Mode }) {
  const c = CHROME[mode]; const tip = tooltipStyle(mode)
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} barCategoryGap="28%" margin={{ top: 4, right: 8, bottom: 0, left: -14 }}>
        <CartesianGrid stroke={c.grid} vertical={false} />
        <XAxis dataKey="source_type" tick={{ fill: c.muted, fontSize: 12 }} axisLine={{ stroke: c.axis }} tickLine={false} />
        <YAxis tick={{ fill: c.muted, fontSize: 12 }} axisLine={false} tickLine={false} width={44} />
        <Tooltip {...tip} />
        <Bar dataKey="count" radius={[4, 4, 0, 0]} isAnimationActive={false}>
          {data.map((d) => <Cell key={d.source_type} fill={sourceColor(d.source_type, mode)} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

// Ingest over time — single series (title names it, so no legend).
export function IngestChart({ data, mode }: { data: OverviewStats['ingest']; mode: Mode }) {
  const c = CHROME[mode]; const tip = tooltipStyle(mode); const accent = sourceColor('auth', mode)
  const fmt = (m: string) => m.slice(11, 16)
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{ top: 4, right: 10, bottom: 0, left: -14 }}>
        <defs>
          <linearGradient id="ingestFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={accent} stopOpacity={0.35} />
            <stop offset="100%" stopColor={accent} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={c.grid} vertical={false} />
        <XAxis dataKey="minute" tickFormatter={fmt} tick={{ fill: c.muted, fontSize: 12 }} axisLine={{ stroke: c.axis }} tickLine={false} minTickGap={28} />
        <YAxis tick={{ fill: c.muted, fontSize: 12 }} axisLine={false} tickLine={false} width={44} />
        <Tooltip {...tip} labelFormatter={(label) => fmt(String(label))} />
        <Area type="monotone" dataKey="count" stroke={accent} strokeWidth={2} fill="url(#ingestFill)" isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

// Event severity mix — horizontal status bars (label on axis + reserved color).
export function SeverityChart({ data, mode }: { data: OverviewStats['severityCounts']; mode: Mode }) {
  const c = CHROME[mode]; const tip = tooltipStyle(mode)
  const ordered = SEVERITY_ORDER
    .map((s) => data.find((d) => d.severity === s))
    .filter((d): d is { severity: Severity; count: number } => !!d)
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart layout="vertical" data={ordered} barCategoryGap="24%" margin={{ top: 4, right: 12, bottom: 0, left: 6 }}>
        <CartesianGrid stroke={c.grid} horizontal={false} />
        <XAxis type="number" tick={{ fill: c.muted, fontSize: 12 }} axisLine={false} tickLine={false} />
        <YAxis type="category" dataKey="severity" tick={{ fill: c.textSecondary, fontSize: 12 }} axisLine={false} tickLine={false} width={62} />
        <Tooltip {...tip} />
        <Bar dataKey="count" radius={[0, 4, 4, 0]} isAnimationActive={false}>
          {ordered.map((d) => <Cell key={d.severity} fill={SEVERITY_COLOR[d.severity]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
