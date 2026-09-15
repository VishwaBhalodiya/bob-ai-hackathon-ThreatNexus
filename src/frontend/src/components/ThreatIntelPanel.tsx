// ThreatIntelPanel — top known-bad IOC feed sidebar
import type { ThreatIntel } from '../types'

interface Props {
  threats: ThreatIntel[]
}

const TYPE_ICON: Record<string, string> = {
  ip: '🌐', domain: '🔗', url: '🌍', sha256: '#️⃣', sha1: '#️⃣', md5: '#️⃣', email: '📧',
}

const CAT_COLOR: Record<string, string> = {
  ransomware: '#f85149',
  apt: '#f85149',
  c2: '#e3a346',
  malware: '#e3a346',
  phishing: '#d29922',
  scanner: '#8b949e',
}

function ReputationBar({ score }: { score: number }) {
  const color = score >= 80 ? '#f85149' : score >= 60 ? '#e3a346' : score >= 40 ? '#d29922' : '#3fb950'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div style={{
        flex: 1, height: 4, background: 'var(--surface-2)', borderRadius: 2, overflow: 'hidden',
      }}>
        <div style={{ width: `${score}%`, height: '100%', background: color, borderRadius: 2 }} />
      </div>
      <span style={{ fontSize: 10, color, fontWeight: 600, minWidth: 24 }}>{score.toFixed(0)}</span>
    </div>
  )
}

export function ThreatIntelPanel({ threats }: Props) {
  return (
    <div>
      {threats.length === 0 && (
        <p style={{ color: 'var(--muted)', fontSize: 12 }}>No threat intel loaded.</p>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {threats.map(t => (
          <div key={t.id} style={{
            background: 'var(--surface-2)', borderRadius: 6,
            padding: '10px 12px', border: '1px solid var(--border)',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 12, fontFamily: 'monospace', color: '#79c0ff' }}>
                {TYPE_ICON[t.ioc_type] ?? '🔍'} {t.ioc_value.length > 32 ? t.ioc_value.slice(0, 32) + '…' : t.ioc_value}
              </span>
              {t.threat_category && (
                <span style={{
                  fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
                  color: CAT_COLOR[t.threat_category.toLowerCase()] ?? '#8b949e',
                }}>
                  {t.threat_category}
                </span>
              )}
            </div>
            <ReputationBar score={t.reputation_score} />
            {t.source && (
              <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>
                Source: {t.source}
                {t.last_seen && ` · Last seen: ${new Date(t.last_seen).toLocaleDateString()}`}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
