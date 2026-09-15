import './StatsCards.css'

// Every card is a shortcut: clicking filters the alert table (or jumps to the
// relevant panel).  `active` marks the card whose filter is currently applied.
const CARDS = [
  { key: 'total',    label: 'Total Alerts',        icon: '⚡', colorVar: '--info',       hint: 'Show all alerts'                    },
  { key: 'critical', label: 'Critical',             icon: '🔴', colorVar: '--critical',   hint: 'Filter: CRITICAL priority'          },
  { key: 'high',     label: 'High',                 icon: '🟠', colorVar: '--high',       hint: 'Filter: HIGH priority'              },
  { key: 'chains',   label: 'Attack Chains',        icon: '⛓', colorVar: '--critical',   hint: 'Open active chains in the Commander Brief' },
  { key: 'genuine',  label: 'Genuine Threats',      icon: '◆',  colorVar: '--critical',   hint: 'Filter: genuine threats'            },
  { key: 'fp',       label: 'Suppressed as FP',     icon: '◇',  colorVar: '--text-muted', hint: 'Filter: likely false positives'     },
  { key: 'review',   label: 'Needs Review',         icon: '◈',  colorVar: '--medium',     hint: 'Filter: needs analyst review'       },
  { key: 'iocs',     label: 'Known IOCs',           icon: '🎯', colorVar: '--medium',     hint: 'Jump to IOC reputation panel'       },
]

export default function StatsCards({ stats, iocCount, onSelect, active }) {
  const values = {
    total:    stats?.total    ?? '—',
    critical: stats?.critical ?? '—',
    high:     stats?.high     ?? '—',
    chains:   stats?.attack_chains ?? '—',
    genuine:  stats?.verdict_summary?.genuine ?? '—',
    fp:       stats?.verdict_summary?.likely_false_positive ?? '—',
    review:   stats?.verdict_summary?.needs_review ?? '—',
    iocs:     iocCount        ?? '—',
  }

  return (
    <div className="stats-grid">
      {CARDS.map(({ key, label, icon, colorVar, hint }) => (
        <button
          key={key}
          type="button"
          className={`stat-card${active === key ? ' stat-card-active' : ''}`}
          style={{ '--accent': `var(${colorVar})` }}
          onClick={() => onSelect?.(key)}
          title={hint}
        >
          <div className="stat-icon">{icon}</div>
          <div className="stat-body">
            <div className="stat-value">{values[key]}</div>
            <div className="stat-label">{label}</div>
          </div>
          <div className="stat-glow" />
          <span className="stat-arrow">›</span>
        </button>
      ))}
    </div>
  )
}
