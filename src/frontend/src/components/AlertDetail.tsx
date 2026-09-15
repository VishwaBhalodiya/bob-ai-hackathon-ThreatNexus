// AlertDetail — full right-panel view of a single alert
import type { Alert } from '../types'
import { RiskBadge } from './RiskBadge'
import { IOCPanel } from './IOCPanel'

interface Props {
  alert: Alert
  onClose: () => void
  onAcknowledge: () => void
  onFalsePositive: () => void
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{
        fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.08em',
        color: 'var(--muted)', marginBottom: 8, fontWeight: 600,
      }}>
        {title}
      </div>
      {children}
    </div>
  )
}

export function AlertDetail({ alert, onClose, onAcknowledge, onFalsePositive }: Props) {
  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 100,
      background: 'rgba(0,0,0,0.6)',
      display: 'flex', justifyContent: 'flex-end',
    }}
      onClick={onClose}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: 'var(--surface)',
          width: '100%', maxWidth: 600,
          height: '100vh', overflowY: 'auto',
          borderLeft: '1px solid var(--border)',
          padding: '24px 20px',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
          <RiskBadge level={alert.risk_level} score={alert.risk_score} size="lg" />
          <button
            onClick={onClose}
            style={{
              background: 'transparent', border: 'none', color: 'var(--muted)',
              fontSize: 20, lineHeight: 1,
            }}
          >✕</button>
        </div>

        <h2 style={{ fontSize: 16, fontWeight: 700, lineHeight: 1.4, marginBottom: 16 }}>
          {alert.title}
        </h2>

        {/* Meta row */}
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 20, fontSize: 12, color: 'var(--muted)' }}>
          {alert.source_system && <span>📡 <strong style={{ color: 'var(--text)' }}>{alert.source_system}</strong></span>}
          {alert.asset && <span>🖥 <strong style={{ color: 'var(--text)' }}>{alert.asset.hostname}</strong> (crit {alert.asset.criticality}/10)</span>}
          <span>🕐 {new Date(alert.timestamp).toLocaleString()}</span>
          {alert.correlation_group_id && <span style={{ color: '#79c0ff' }}>🔗 {alert.correlation_group_id}</span>}
        </div>

        {/* Description */}
        {alert.description && (
          <Section title="Description">
            <p style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--text)' }}>{alert.description}</p>
          </Section>
        )}

        {/* AI Explanation */}
        {alert.ai_explanation && (
          <Section title="🤖 AI Analysis">
            <div style={{
              background: '#0d2137', border: '1px solid #1f6feb',
              borderRadius: 6, padding: '12px 14px',
              fontSize: 13, lineHeight: 1.6, color: '#cae8ff',
            }}>
              {alert.ai_explanation}
            </div>
          </Section>
        )}

        {/* Investigation Steps */}
        {alert.investigation_steps.length > 0 && (
          <Section title="🔍 Recommended Investigation Steps">
            <ol style={{ paddingLeft: 20, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {alert.investigation_steps.map((step, i) => (
                <li key={i} style={{ fontSize: 13, lineHeight: 1.5 }}>{step}</li>
              ))}
            </ol>
          </Section>
        )}

        {/* IOCs */}
        <Section title="Indicators of Compromise">
          <IOCPanel iocs={alert.iocs} />
        </Section>

        {/* Asset */}
        {alert.asset && (
          <Section title="Affected Asset">
            <div style={{
              background: 'var(--surface-2)', borderRadius: 6, padding: '10px 12px',
              fontSize: 12, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px 16px',
            }}>
              <span style={{ color: 'var(--muted)' }}>Hostname</span>
              <span>{alert.asset.hostname}</span>
              <span style={{ color: 'var(--muted)' }}>IP Address</span>
              <span style={{ fontFamily: 'monospace' }}>{alert.asset.ip_address}</span>
              <span style={{ color: 'var(--muted)' }}>Type</span>
              <span>{alert.asset.asset_type}</span>
              <span style={{ color: 'var(--muted)' }}>Criticality</span>
              <span>{alert.asset.criticality}/10</span>
              <span style={{ color: 'var(--muted)' }}>Owner</span>
              <span>{alert.asset.owner}</span>
              <span style={{ color: 'var(--muted)' }}>Department</span>
              <span>{alert.asset.department}</span>
            </div>
          </Section>
        )}

        {/* Raw Log */}
        {alert.raw_log && (
          <Section title="Raw Log">
            <pre style={{
              background: '#0d1117', border: '1px solid var(--border)',
              borderRadius: 4, padding: 10, fontSize: 11,
              fontFamily: 'monospace', overflowX: 'auto',
              color: '#7ee787', lineHeight: 1.5, whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
            }}>
              {alert.raw_log}
            </pre>
          </Section>
        )}

        {/* Actions */}
        <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
          {!alert.is_acknowledged && (
            <button
              onClick={onAcknowledge}
              style={{
                flex: 1, background: '#1f6feb', color: '#fff',
                border: 'none', borderRadius: 6, padding: '8px 0', fontSize: 13, fontWeight: 600,
              }}
            >
              ✓ Acknowledge Alert
            </button>
          )}
          {!alert.is_false_positive && (
            <button
              onClick={onFalsePositive}
              style={{
                flex: 1, background: 'transparent', color: 'var(--muted)',
                border: '1px solid var(--border)', borderRadius: 6, padding: '8px 0', fontSize: 13,
              }}
            >
              Mark as False Positive
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
