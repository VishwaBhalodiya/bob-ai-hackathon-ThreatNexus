// AlertCard — summary card used in the alert list
import type { Alert } from '../types'
import { RiskBadge } from './RiskBadge'
import { IOCPanel } from './IOCPanel'

interface Props {
  alert: Alert
  onClick: () => void
  onAcknowledge: () => void
}

function timeAgo(iso: string) {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000
  if (diff < 60) return `${Math.round(diff)}s ago`
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`
  return `${Math.round(diff / 86400)}d ago`
}

export function AlertCard({ alert, onClick, onAcknowledge }: Props) {
  return (
    <div
      onClick={onClick}
      style={{
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 8,
        padding: '14px 16px',
        cursor: 'pointer',
        transition: 'border-color 0.15s',
        opacity: alert.is_acknowledged ? 0.6 : 1,
      }}
      onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--accent)')}
      onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
    >
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 8 }}>
        <RiskBadge level={alert.risk_level} score={alert.risk_score} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 14, lineHeight: 1.3, marginBottom: 2 }}>
            {alert.title}
          </div>
          <div style={{ color: 'var(--muted)', fontSize: 12 }}>
            {alert.source_system && <span style={{ marginRight: 12 }}>📡 {alert.source_system}</span>}
            {alert.asset && <span style={{ marginRight: 12 }}>🖥 {alert.asset.hostname}</span>}
            <span>🕐 {timeAgo(alert.timestamp)}</span>
          </div>
        </div>
        {alert.correlation_group_id && (
          <span title="Part of correlated attack group" style={{
            background: '#1f2d3d', color: '#79c0ff', border: '1px solid #1f6feb',
            borderRadius: 4, padding: '2px 7px', fontSize: 11, whiteSpace: 'nowrap',
          }}>
            🔗 Correlated
          </span>
        )}
      </div>

      {/* IOCs */}
      {alert.iocs.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <IOCPanel iocs={alert.iocs.slice(0, 4)} />
        </div>
      )}

      {/* AI summary snippet */}
      {alert.ai_explanation && (
        <div style={{
          background: 'var(--surface-2)', borderRadius: 4, padding: '8px 10px',
          fontSize: 12, color: 'var(--muted)', lineHeight: 1.5,
          borderLeft: '2px solid var(--accent)',
        }}>
          {alert.ai_explanation.slice(0, 160)}…
        </div>
      )}

      {/* Footer */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 10,
      }}>
        <span style={{ fontSize: 11, color: 'var(--muted)' }}>
          #{alert.id} · {alert.source_severity?.toUpperCase()} severity
        </span>
        {!alert.is_acknowledged && (
          <button
            onClick={e => { e.stopPropagation(); onAcknowledge() }}
            style={{
              background: 'transparent', border: '1px solid var(--border)',
              color: 'var(--muted)', borderRadius: 4, padding: '3px 10px', fontSize: 11,
            }}
          >
            Acknowledge
          </button>
        )}
        {alert.is_acknowledged && (
          <span style={{ fontSize: 11, color: 'var(--low)' }}>✓ Acknowledged</span>
        )}
      </div>
    </div>
  )
}
