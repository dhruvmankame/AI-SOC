// Validated design tokens from the dataviz skill's reference palette.
// Categorical hues are in FIXED slot order (never cycled); source types are
// pinned to a slot so a filter never repaints survivors. Severity uses the
// reserved STATUS palette (always shown with a text label, never color alone).
import type { Severity } from './types'

export type Mode = 'light' | 'dark'

// Categorical slots 1..8 (light / dark) — validated adjacent-pair CVD-safe.
const CATEGORICAL: Record<Mode, string[]> = {
  light: ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#4a3aa7', '#e34948'],
  dark: ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767'],
}

// Source type → fixed categorical slot index. Stable identity mapping.
const SOURCE_SLOT: Record<string, number> = {
  auth: 0,
  process: 1,
  network: 2,
  firewall: 3,
  web: 4,
  cloud: 5,
}

export function sourceColor(sourceType: string, mode: Mode): string {
  const slot = SOURCE_SLOT[sourceType] ?? 6
  return CATEGORICAL[mode][slot]
}

// Reserved status palette (mode-invariant hues; validated on both surfaces).
// Severity is a state → status colors, always paired with the label text.
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#d03b3b',
  high: '#ec835a',
  medium: '#fab219',
  low: '#2a78d6',
  info: '#898781',
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

// Chart chrome & ink per mode (axis/grid/text) for recharts props.
export const CHROME: Record<Mode, {
  surface: string; text: string; textSecondary: string; muted: string; grid: string; axis: string
}> = {
  light: { surface: '#fcfcfb', text: '#0b0b0b', textSecondary: '#52514e', muted: '#898781', grid: '#e1e0d9', axis: '#c3c2b7' },
  dark: { surface: '#1a1a19', text: '#ffffff', textSecondary: '#c3c2b7', muted: '#898781', grid: '#2c2c2a', axis: '#383835' },
}
