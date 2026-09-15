import { useEffect, useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { api } from '../services/api.js'
import PriorityBadge  from '../components/PriorityBadge.jsx'
import VerdictBadge   from '../components/VerdictBadge.jsx'
import TacticCoverage from '../components/TacticCoverage.jsx'
import AiEngineBadge  from '../components/AiEngineBadge.jsx'
import './CommanderBrief.css'

const POSTURE_META = {
  CRITICAL: { color: '#ef4444', label: 'CRITICAL', blurb: 'Active multi-stage intrusion — contain now' },
  ELEVATED: { color: '#f97316', label: 'ELEVATED', blurb: 'Confirmed threats need action this shift'   },
  GUARDED:  { color: '#eab308', label: 'GUARDED',  blurb: 'Investigate high-priority items'            },
  NORMAL:   { color: '#22c55e', label: 'NORMAL',   blurb: 'No genuine critical or high threats'        },
}

const WINDOWS = [
  { label: '24 h', value: 24  },
  { label: '72 h', value: 72  },
  { label: '7 d',  value: 168 },
]

function fmtTime(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })
}

export default function CommanderBrief() {
  const navigate = useNavigate()
  const [brief,   setBrief]   = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const [window,  setWindow]  = useState(72)
  const [limit,   setLimit]   = useState(8)
  const location = useLocation()

  // /brief#chains → scroll to the attack-chain section once loaded
  useEffect(() => {
    if (!brief || !location.hash) return
    const el = document.getElementById(location.hash.slice(1))
    if (el) setTimeout(() => el.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50)
  }, [brief, location.hash])

  useEffect(() => {
    setLoading(true)
    api.getBrief({ window_hours: window, limit })
      .then(b => { setBrief(b); setError(null) })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [window, limit])

  const posture = POSTURE_META[brief?.posture] || POSTURE_META.NORMAL

  return (
    <div className="brief-page">
      <header className="brief-header">
        <button className="back-btn" onClick={() => navigate('/')}>← Dashboard</button>
        <div className="brief-header-title">
          <span className="logo-icon-sm">🛡️</span> THREATNEXUS <span className="brief-header-sub">Commander Brief</span>
        </div>
        <div className="brief-header-actions">
          <AiEngineBadge />
          <div className="brief-window">
            {WINDOWS.map(w => (
              <button key={w.value} className={`status-filter-pill${window === w.value ? ' active' : ''}`} onClick={() => setWindow(w.value)}>
                {w.label}
              </button>
            ))}
          </div>
          <button className="brief-print" onClick={() => print()}>⎙ Print</button>
        </div>
      </header>

      {error && <div className="error-banner">Backend unreachable: {error}</div>}
      {loading && !brief && <div className="brief-loading">Compiling brief…</div>}

      {brief && (
        <main className="brief-body" style={{ opacity: loading ? 0.6 : 1 }}>
          {/* ── Headline BLUF ────────────────────────────────────────────── */}
          <section className="brief-hero" style={{ borderLeftColor: posture.color }}>
            <div className="brief-posture">
              <span className="brief-posture-label">Threat posture</span>
              <span className="brief-posture-value" style={{ color: posture.color }}>{posture.label}</span>
              <span className="brief-posture-blurb">{posture.blurb}</span>
              <span className="brief-generated mono">Generated {fmtTime(brief.generated_at)} · last {brief.stats.window_hours} h</span>
            </div>
            <div className="brief-bluf">
              <div className="bluf-row">
                <span className="bluf-key" style={{ color: posture.color }}>Bottom line</span>
                <p className="bluf-headline" style={{ color: posture.color }}>{brief.bottom_line}</p>
              </div>
              <div className="bluf-row"><span className="bluf-key">Situation</span><p>{brief.situation}</p></div>
              <div className="bluf-row"><span className="bluf-key">Assessment</span><p>{brief.assessment}</p></div>
              <div className="bluf-row"><span className="bluf-key">Recommendation</span><p>{brief.recommendation}</p></div>
            </div>
          </section>

          {/* ── Stats strip ──────────────────────────────────────────────── */}
          <section className="brief-stats">
            <Stat label="Alerts in window" value={brief.stats.open_alerts} />
            <Stat label="Attack chains"    value={brief.stats.attack_chains} color="#ef4444" />
            <Stat label="Critical"         value={brief.stats.critical} color="#ef4444" />
            <Stat label="High"             value={brief.stats.high} color="#f97316" />
            <Stat label="Genuine"          value={brief.stats.genuine} color="#ef4444" />
            <Stat label="Needs review"     value={brief.stats.needs_review} color="#eab308" />
            <Stat label="Suppressed noise" value={`${brief.stats.likely_false_positive}`} sub={`${brief.stats.noise_reduction_pct}%`} />
            <Stat label="Feeds"            value={Object.keys(brief.stats.sources).length} sub={Object.keys(brief.stats.sources).join(' · ')} />
          </section>

          {/* ── Kill-chain coverage ──────────────────────────────────────── */}
          <section className="brief-card">
            <div className="card-title">MITRE ATT&CK coverage <span className="card-title-count">alerts per tactic, kill-chain order</span></div>
            <TacticCoverage tactics={brief.tactic_coverage} highlight={brief.attack_chains[0]?.tactics || []} />
          </section>

          {/* ── Attack chains ────────────────────────────────────────────── */}
          {brief.attack_chains.length > 0 && (
            <section className="brief-card" id="chains">
              <div className="card-title">
                Active attack chains
                <span className="card-title-count">{brief.attack_chains.length} multi-stage · ≥3 tactics · ≥1 genuine alert</span>
              </div>
              <div className="chain-list">
                {brief.attack_chains.map(c => (
                  <div key={c.source_ip} className="chain-card" style={{ borderLeftColor: c.priority === 'CRITICAL' ? '#ef4444' : '#f97316' }}>
                    <div className="chain-top">
                      <PriorityBadge priority={c.priority} />
                      <span className="mono chain-ip">{c.source_ip}</span>
                      <span className="chain-arrow">→</span>
                      <span className="chain-assets">{c.assets.join(', ') || 'unresolved hosts'}</span>
                      <span className="chain-meta mono">{c.alert_count} alerts · {c.genuine_count} genuine · {fmtTime(c.first_seen)} → {fmtTime(c.last_seen)}</span>
                    </div>
                    <p className="chain-bluf">{c.bottom_line}</p>
                    <div className="chain-stages">
                      {c.tactics.map((t, i) => (
                        <span key={t} className="chain-stage">
                          <span className="chain-stage-pill">{t}</span>
                          {i < c.tactics.length - 1 && <span className="chain-stage-arrow">›</span>}
                        </span>
                      ))}
                    </div>
                    <div className="chain-links">
                      {c.alert_ids.map(id => (
                        <button key={id} className="chain-link" onClick={() => navigate(`/alerts/${id}`)}>#{id}</button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* ── Ranked priorities ────────────────────────────────────────── */}
          <section className="brief-card">
            <div className="card-title">
              Prioritised investigations
              <span className="card-title-count">top {brief.priorities.length} · correlated duplicates collapsed · likely false positives excluded</span>
              <span className="brief-limit">
                {[5, 8, 15].map(n => (
                  <button key={n} className={`status-filter-pill${limit === n ? ' active' : ''}`} onClick={() => setLimit(n)}>{n}</button>
                ))}
              </span>
            </div>

            {brief.priorities.length === 0 && <div className="no-data">Nothing actionable in this window.</div>}

            <ol className="priority-list">
              {brief.priorities.map(p => (
                <li key={p.alert_id} className="priority-item" onClick={() => navigate(`/alerts/${p.alert_id}`)}>
                  <div className="priority-rank mono">{String(p.rank).padStart(2, '0')}</div>
                  <div className="priority-body">
                    <div className="priority-top">
                      <PriorityBadge priority={p.priority} />
                      <VerdictBadge verdict={p.verdict} confidence={p.verdict_confidence} compact />
                      {p.is_attack_chain && <span className="priority-chain">⛓ chain</span>}
                      <span className="priority-event">{p.event_type}</span>
                      {p.mitre_technique_id && (
                        <span className="priority-mitre mono">{p.mitre_technique_id} · {p.mitre_tactic}</span>
                      )}
                      <span className="priority-score mono">{p.risk_score.toFixed(0)}</span>
                    </div>
                    <p className="priority-bluf">{p.bluf.bottom_line}</p>
                    <div className="priority-meta mono">
                      <span>{p.source_ip}</span>
                      <span>→ {p.asset || 'unknown asset'}{p.asset_criticality ? ` (${p.asset_criticality})` : ''}</span>
                      <span>{p.source}</span>
                      <span>{fmtTime(p.timestamp)}</span>
                      <span className="priority-open">#{p.alert_id} →</span>
                    </div>
                    <details className="priority-details" onClick={e => e.stopPropagation()}>
                      <summary>Situation · Assessment · Recommendation</summary>
                      <div className="priority-detail-grid">
                        <div><span className="bluf-key">Situation</span><p>{p.bluf.situation}</p></div>
                        <div><span className="bluf-key">Assessment</span><p>{p.bluf.assessment}</p></div>
                        <div><span className="bluf-key">Recommendation</span><p>{p.bluf.recommendation}</p></div>
                      </div>
                    </details>
                  </div>
                </li>
              ))}
            </ol>
          </section>

          {/* ── Suppressed noise ─────────────────────────────────────────── */}
          {brief.suppressed.length > 0 && (
            <section className="brief-card brief-card-muted">
              <div className="card-title">
                Suppressed as likely false positives
                <span className="card-title-count">{brief.stats.likely_false_positive} in window · shown so nothing is hidden from command</span>
              </div>
              <table className="suppressed-table">
                <thead><tr><th>#</th><th>Event</th><th>Source</th><th>Asset</th><th>Confidence</th><th>Why</th></tr></thead>
                <tbody>
                  {brief.suppressed.map(s => (
                    <tr key={s.alert_id} onClick={() => navigate(`/alerts/${s.alert_id}`)}>
                      <td className="mono muted">#{s.alert_id}</td>
                      <td>{s.event_type}</td>
                      <td className="mono">{s.source_ip}</td>
                      <td>{s.asset || '—'}</td>
                      <td className="mono">{s.verdict_confidence.toFixed(0)}%</td>
                      <td className="muted">{s.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}
        </main>
      )}
    </div>
  )
}

function Stat({ label, value, sub, color }) {
  return (
    <div className="brief-stat">
      <div className="brief-stat-value mono" style={color ? { color } : {}}>{value}</div>
      <div className="brief-stat-label">{label}</div>
      {sub && <div className="brief-stat-sub mono">{sub}</div>}
    </div>
  )
}
