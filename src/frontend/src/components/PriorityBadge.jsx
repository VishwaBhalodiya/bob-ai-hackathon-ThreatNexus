import './PriorityBadge.css'

const CONFIG = {
  CRITICAL: { label: '🔴 CRITICAL', cls: 'badge-critical' },
  HIGH:     { label: '🟠 HIGH',     cls: 'badge-high'     },
  MEDIUM:   { label: '🟡 MEDIUM',   cls: 'badge-medium'   },
  LOW:      { label: '🟢 LOW',      cls: 'badge-low'      },
}

export default function PriorityBadge({ priority }) {
  const p = (priority || 'LOW').toUpperCase()
  const { label, cls } = CONFIG[p] || CONFIG.LOW
  return <span className={`priority-badge ${cls}`}>{label}</span>
}
