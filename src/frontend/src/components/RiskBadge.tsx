// RiskBadge — colour-coded severity pill
import type { Alert } from '../types'

const COLOURS: Record<string, { bg: string; color: string; label: string }> = {
  CRITICAL:      { bg: '#3d1b1b', color: '#f85149', label: '🔴 CRITICAL' },
  HIGH:          { bg: '#3d2a0d', color: '#e3a346', label: '🟠 HIGH' },
  MEDIUM:        { bg: '#3d3200', color: '#d29922', label: '🟡 MEDIUM' },
  LOW:           { bg: '#0d2d1a', color: '#3fb950', label: '🟢 LOW' },
  FALSE_POSITIVE:{ bg: '#1f1f1f', color: '#8b949e', label: '⬜ FALSE POS' },
}

interface Props {
  level: Alert['risk_level']
  score?: number
  size?: 'sm' | 'md' | 'lg'
}

export function RiskBadge({ level, score, size = 'md' }: Props) {
  const c = COLOURS[level] ?? COLOURS.LOW
  const pad = size === 'sm' ? '2px 8px' : size === 'lg' ? '6px 16px' : '3px 10px'
  const fs = size === 'sm' ? '11px' : size === 'lg' ? '15px' : '12px'
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: 4,
      background: c.bg,
      color: c.color,
      border: `1px solid ${c.color}44`,
      borderRadius: 4,
      padding: pad,
      fontSize: fs,
      fontWeight: 600,
      whiteSpace: 'nowrap',
    }}>
      {c.label}{score !== undefined ? ` — ${score.toFixed(0)}` : ''}
    </span>
  )
}
