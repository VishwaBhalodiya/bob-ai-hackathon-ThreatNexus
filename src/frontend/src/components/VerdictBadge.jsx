import './VerdictBadge.css'

// Correlation verdict — genuine threat vs suppressed noise vs needs a human.
export const VERDICT_META = {
  GENUINE_THREAT:        { label: 'Genuine',      short: 'GENUINE', symbol: '◆', cls: 'verdict-genuine' },
  LIKELY_FALSE_POSITIVE: { label: 'Likely FP',    short: 'LIKELY FP', symbol: '◇', cls: 'verdict-fp'      },
  NEEDS_REVIEW:          { label: 'Needs review', short: 'REVIEW',  symbol: '◈', cls: 'verdict-review'  },
}

export default function VerdictBadge({ verdict, confidence, compact = false }) {
  const meta = VERDICT_META[(verdict || 'NEEDS_REVIEW').toUpperCase()] || VERDICT_META.NEEDS_REVIEW
  const title = confidence != null
    ? `${meta.label} — ${Number(confidence).toFixed(0)}% confidence`
    : meta.label
  return (
    <span className={`verdict-badge ${meta.cls}${compact ? ' verdict-compact' : ''}`} title={title}>
      <span className="verdict-symbol">{meta.symbol}</span>
      {compact ? meta.short : meta.label}
      {!compact && confidence != null && (
        <span className="verdict-conf">{Number(confidence).toFixed(0)}%</span>
      )}
    </span>
  )
}
