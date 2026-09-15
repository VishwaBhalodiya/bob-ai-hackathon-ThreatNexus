import { useNavigate } from 'react-router-dom'
import './AttackTimeline.css'

// Mirrors _EVENT_TACTIC in correlation_engine.py and the MITRE table in
// AlertDetails.jsx — one source of truth per layer.
const TACTIC_ORDER = [
  'Initial Access',
  'Defense Evasion',
  'Discovery',
  'Credential Access',
  'Privilege Escalation',
  'Lateral Movement',
  'Execution',
  'Command & Control',
  'Exfiltration',
  'Impact',
]

const PRIORITY_COLOR = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
}

const TACTIC_COLOR = {
  'Initial Access':       '#6366f1',
  'Defense Evasion':      '#8b5cf6',
  'Discovery':            '#3b82f6',
  'Credential Access':    '#f59e0b',
  'Privilege Escalation': '#f97316',
  'Lateral Movement':     '#ef4444',
  'Execution':            '#dc2626',
  'Command & Control':    '#b91c1c',
  'Exfiltration':         '#7c3aed',
  'Impact':               '#991b1b',
}

function fmtTime(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('en-GB', {
    month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function TacticPill({ tactic }) {
  if (!tactic) return null
  const color = TACTIC_COLOR[tactic] || '#64748b'
  return (
    <span className="tactic-pill" style={{ color, borderColor: color, background: `${color}18` }}>
      {tactic}
    </span>
  )
}

/**
 * AttackTimeline renders a vertical timeline of the current alert plus its
 * related_events, sorted by timestamp.
 *
 * Props:
 *   currentAlert  – the full alert object (id, timestamp, event_type, …)
 *   relatedEvents – array of RelatedEventResponse dicts from the API
 *   isAttackChain – boolean flag from the backend
 */
export default function AttackTimeline({ currentAlert, relatedEvents, isAttackChain }) {
  const navigate = useNavigate()

  if (!relatedEvents?.length) return null

  // Merge current + related, mark current, sort by timestamp
  const allEvents = [
    {
      ...currentAlert,
      mitre_tactic: currentAlert.mitre_tactic ?? null,
      _isCurrent: true,
    },
    ...relatedEvents.map(e => ({ ...e, _isCurrent: false })),
  ].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))

  // Collect distinct tactics in kill-chain order for the legend
  const presentTactics = TACTIC_ORDER.filter(t =>
    allEvents.some(e => e.mitre_tactic === t)
  )

  return (
    <div className="timeline-root">
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="timeline-header">
        <div className="timeline-title-row">
          <span className="timeline-icon">⛓</span>
          <span className="timeline-title">Attack Timeline</span>
          <span className="timeline-count">{allEvents.length} events · ±10 min window</span>
        </div>

        {isAttackChain && (
          <div className="attack-chain-banner">
            <span className="chain-icon">⚠</span>
            <div>
              <div className="chain-label">MULTI-STAGE ATTACK CHAIN DETECTED</div>
              <div className="chain-sub">
                {presentTactics.length} distinct MITRE tactics spanning this activity cluster
              </div>
            </div>
          </div>
        )}

        {/* Tactic legend */}
        {presentTactics.length > 0 && (
          <div className="tactic-legend">
            {presentTactics.map((t, i) => (
              <span key={t} className="legend-item">
                <TacticPill tactic={t} />
                {i < presentTactics.length - 1 && (
                  <span className="legend-arrow">→</span>
                )}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* ── Timeline ────────────────────────────────────────────────────── */}
      <div className="timeline-track">
        {allEvents.map((evt, idx) => {
          const priorityColor = PRIORITY_COLOR[(evt.priority || 'LOW').toUpperCase()]
          const isCurrent     = evt._isCurrent
          const isLast        = idx === allEvents.length - 1

          return (
            <div key={evt.id} className={`tl-item${isCurrent ? ' tl-item--current' : ''}`}>
              {/* Left: connector */}
              <div className="tl-connector">
                <div
                  className={`tl-dot${isCurrent ? ' tl-dot--current' : ''}`}
                  style={{ borderColor: priorityColor, background: isCurrent ? priorityColor : 'var(--bg-card)' }}
                />
                {!isLast && <div className="tl-line" />}
              </div>

              {/* Right: content card */}
              <div
                className={`tl-card${isCurrent ? ' tl-card--current' : ''}`}
                style={isCurrent ? { borderColor: priorityColor } : {}}
                onClick={() => !isCurrent && navigate(`/alerts/${evt.id}`)}
                role={isCurrent ? undefined : 'button'}
                tabIndex={isCurrent ? undefined : 0}
                onKeyDown={e => {
                  if (!isCurrent && (e.key === 'Enter' || e.key === ' ')) navigate(`/alerts/${evt.id}`)
                }}
              >
                <div className="tl-card-top">
                  <span className="tl-event-type" style={{ color: isCurrent ? priorityColor : 'var(--text-primary)' }}>
                    {isCurrent && <span className="tl-current-marker">● THIS ALERT  </span>}
                    {evt.event_type}
                  </span>
                  <span className="tl-time mono">{fmtTime(evt.timestamp)}</span>
                </div>

                <div className="tl-card-meta">
                  <span className="tl-meta-item mono">{evt.source_ip}</span>
                  {evt.destination_ip && (
                    <>
                      <span className="tl-arrow">→</span>
                      <span className="tl-meta-item mono">{evt.destination_ip}</span>
                    </>
                  )}
                  <span
                    className="tl-severity"
                    style={{ color: PRIORITY_COLOR[(evt.severity || 'LOW').toUpperCase()] }}
                  >
                    {evt.severity}
                  </span>
                  <span className="tl-score" style={{ color: priorityColor }}>
                    {evt.risk_score?.toFixed(0)}
                  </span>
                </div>

                {evt.mitre_tactic && (
                  <div className="tl-tactic">
                    <TacticPill tactic={evt.mitre_tactic} />
                  </div>
                )}

                {!isCurrent && (
                  <div className="tl-link-hint">View alert #{evt.id} →</div>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
