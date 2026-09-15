import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '../services/api.js'
import PriorityBadge       from '../components/PriorityBadge.jsx'
import RiskBreakdownChart  from '../components/RiskBreakdownChart.jsx'
import AttackTimeline      from '../components/AttackTimeline.jsx'
import VerdictBadge, { VERDICT_META } from '../components/VerdictBadge.jsx'
import './AlertDetails.css'

function InfoRow({ label, value, mono, color }) {
  return (
    <div className="info-row">
      <span className="info-label">{label}</span>
      <span className={`info-value${mono ? ' mono' : ''}`} style={color ? { color } : {}}>
        {value ?? '—'}
      </span>
    </div>
  )
}

function Section({ title, children }) {
  return (
    <div className="detail-card">
      <div className="detail-card-title">{title}</div>
      {children}
    </div>
  )
}

const SEVERITY_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e' }
const CRITICALITY_COLORS = SEVERITY_COLORS

function fmtTime(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'medium' })
}

function ReputationBar({ value }) {
  const pct = Math.min(Math.max(value || 0, 0), 100)
  const color = pct >= 80 ? '#ef4444' : pct >= 50 ? '#f97316' : pct >= 20 ? '#eab308' : '#22c55e'
  return (
    <div className="rep-bar-wrap">
      <div className="rep-bar-track">
        <div className="rep-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span style={{ color, fontWeight: 700, fontSize: 13, minWidth: 36 }}>{pct.toFixed(0)}%</span>
    </div>
  )
}

const PRIORITY_COLOR_MAP = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e' }

function BlufBlock({ bluf, priority }) {
  const color = PRIORITY_COLOR_MAP[(priority || 'LOW').toUpperCase()] || '#ccd8e8'
  return (
    <div className="bluf-block">
      {/* Bottom line — the one sentence a commander reads alone */}
      <div className="bluf-bottom-line" style={{ borderLeftColor: color }}>
        <span className="bluf-label" style={{ color }}>BOTTOM LINE</span>
        <p className="bluf-verdict" style={{ color }}>{bluf.bottom_line}</p>
      </div>

      {/* Supporting detail — situation then assessment */}
      <div className="bluf-body">
        <div className="bluf-section">
          <span className="bluf-section-label">Situation</span>
          <p className="bluf-section-text">{bluf.situation}</p>
        </div>
        <div className="bluf-section">
          <span className="bluf-section-label">Assessment</span>
          <p className="bluf-section-text">{bluf.assessment}</p>
        </div>
      </div>
    </div>
  )
}

const FEEDBACK_META = {
  TRUE_POSITIVE:  { label: 'True Positive',  symbol: '✓', color: '#4ade80' },
  FALSE_POSITIVE: { label: 'False Positive', symbol: '✕', color: '#f87171' },
  ESCALATED:      { label: 'Escalated',      symbol: '↑', color: '#fb923c' },
  UNREVIEWED:     { label: 'Unreviewed',     symbol: '·', color: null      },
}
const TRIAGE_BUTTONS = ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'ESCALATED', 'UNREVIEWED']
const STATUS_STEPS = [
  { value: 'OPEN',        label: 'Open'        },
  { value: 'IN_PROGRESS', label: 'In progress' },
  { value: 'RESOLVED',    label: 'Resolved'    },
]

export default function AlertDetails() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [alert, setAlert]       = useState(null)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [feedback, setFeedback] = useState('UNREVIEWED')
  const [fbSaving, setFbSaving] = useState(false)
  const [extractedIocs, setExtractedIocs] = useState(null)   // null = not yet run
  const [iocExtracting, setIocExtracting] = useState(false)

  useEffect(() => {
    api.getAlert(id)
      .then(data => { setAlert(data); setFeedback(data.feedback || 'UNREVIEWED') })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [id])

  function handleExtractIocs() {
    if (iocExtracting) return
    setIocExtracting(true)
    api.extractIocs(id)
      .then(data => setExtractedIocs(data.iocs || []))
      .catch(() => setExtractedIocs([]))
      .finally(() => setIocExtracting(false))
  }

  const [statusSaving, setStatusSaving] = useState(false)
  function handleStatus(value) {
    if (statusSaving || alert?.status === value) return
    setStatusSaving(true)
    api.setStatus(id, value)
      .then(data => setAlert(a => ({ ...a, status: data.status })))
      .catch(() => {})
      .finally(() => setStatusSaving(false))
  }

  function handleFeedback(value) {
    if (fbSaving) return
    setFbSaving(true)
    api.markFeedback(id, value)
      .then(() => { setFeedback(value); return api.getAlert(id) })
      .then(data => setAlert(data))
      .catch(() => {/* silently ignore on hackathon */ })
      .finally(() => setFbSaving(false))
  }

  if (loading) return (
    <div className="detail-page">
      <PageHeader onBack={() => navigate('/')} />
      <div className="detail-loading">Loading alert #{id}…</div>
    </div>
  )

  if (error) return (
    <div className="detail-page">
      <PageHeader onBack={() => navigate('/')} />
      <div className="detail-error">Failed to load alert: {error}</div>
    </div>
  )

  const {
    asset, ioc_info, risk_breakdown, ai_explanation,
    recommendations, threat_events,
    related_events, is_attack_chain, correlation_count,
    verdict_detail, mitre: mitreApi,
  } = alert

  // ai_explanation is either an AIExplanation object or null/legacy string
  const bluf = ai_explanation && typeof ai_explanation === 'object' ? ai_explanation : null
  const blufFallbackText = typeof ai_explanation === 'string' ? ai_explanation : null
  const sevColor  = SEVERITY_COLORS[(alert.severity || 'LOW').toUpperCase()]
  const critColor = CRITICALITY_COLORS[(asset?.criticality || 'LOW').toUpperCase()]

  // Parse recommendations text into bullet list
  const recText   = recommendations?.[0]?.recommendation || ''
  const recBullets = recText
    .split(/(?<=[.!])\s+/)
    .map(s => s.trim())
    .filter(Boolean)

  // MITRE mapping comes from the API (services/mitre_mapper.py is the single
  // source of truth); the static table below only covers older payloads.
  const MITRE_FALLBACK = {
    'Brute Force':        { id: 'T1110', name: 'Brute Force',                  tactic: 'Credential Access' },
    'Lateral Movement':   { id: 'T1021', name: 'Remote Services',              tactic: 'Lateral Movement'  },
    'Ransomware':         { id: 'T1486', name: 'Data Encrypted for Impact',     tactic: 'Impact'            },
    'Data Exfiltration':  { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration'      },
    'Command & Control':  { id: 'T1071', name: 'Application Layer Protocol',   tactic: 'Command & Control' },
    'Malware Execution':  { id: 'T1204', name: 'User Execution',               tactic: 'Execution'         },
    'Port Scan':          { id: 'T1046', name: 'Network Service Discovery',    tactic: 'Discovery'         },
    'Privilege Escalation':{ id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' },
    'Credential Dumping': { id: 'T1003', name: 'OS Credential Dumping',        tactic: 'Credential Access' },
    'SQL Injection':      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
    'Phishing':           { id: 'T1566', name: 'Phishing',                     tactic: 'Initial Access'    },
    'Suspicious Login':   { id: 'T1078', name: 'Valid Accounts',               tactic: 'Defense Evasion'   },
  }
  const mitre = mitreApi
    ? { id: mitreApi.technique_id, name: mitreApi.technique, tactic: mitreApi.tactic, url: mitreApi.url }
    : MITRE_FALLBACK[alert.event_type]
  // Attach tactic to current alert so AttackTimeline can render it uniformly
  const currentAlertForTimeline = {
    ...alert,
    mitre_tactic: mitre?.tactic ?? null,
  }

  return (
    <div className="detail-page">
      <PageHeader onBack={() => navigate('/')} />

      {/* ── Title row ─────────────────────────────────────────────────── */}
      <div className="detail-hero">
        <div className="detail-hero-left">
          <div className="detail-id">Alert <span className="mono">#{ alert.id }</span></div>
          <div className="detail-event">{alert.event_type}</div>
          <div className="detail-badges">
            <PriorityBadge priority={alert.priority} />
            <VerdictBadge verdict={verdict_detail?.verdict || alert.verdict} confidence={verdict_detail?.confidence ?? alert.verdict_confidence} />
            <span className="detail-score">Risk Score <strong>{alert.risk_score?.toFixed(1)}</strong>/100</span>
            <span className="status-workflow" title="Triage workflow">
              {STATUS_STEPS.map((st, i) => (
                <button
                  key={st.value}
                  className={`status-step${alert.status === st.value ? ' status-step-active' : ''}`}
                  onClick={() => handleStatus(st.value)}
                  disabled={statusSaving}
                >
                  {i > 0 && <span className="status-step-arrow">›</span>}{st.label}
                </button>
              ))}
            </span>
            {alert.feed_format && <span className="detail-status" title="Ingested feed format">{alert.source} · {alert.feed_format.toUpperCase()}</span>}
            {feedback !== 'UNREVIEWED' && (
              <span
                className="feedback-badge"
                style={{ color: FEEDBACK_META[feedback]?.color }}
              >
                {FEEDBACK_META[feedback]?.symbol} {FEEDBACK_META[feedback]?.label}
              </span>
            )}
          </div>
          {/* Analyst triage buttons */}
          <div className="triage-row">
            <span className="triage-label">Analyst Triage</span>
            {TRIAGE_BUTTONS.map(val => (
              <button
                key={val}
                className={`triage-btn triage-${val.toLowerCase()}${feedback === val ? ' triage-active' : ''}`}
                onClick={() => handleFeedback(val)}
                disabled={fbSaving}
                title={FEEDBACK_META[val].label}
              >
                {FEEDBACK_META[val].symbol} {FEEDBACK_META[val].label}
              </button>
            ))}
          </div>
        </div>
        <div className="detail-hero-right">
          <div className="detail-time">{fmtTime(alert.timestamp)}</div>
        </div>
      </div>

      <div className="detail-grid">
        {/* ── Alert info ──────────────────────────────────────────────── */}
        <Section title="Alert Details">
          <InfoRow label="Feed / Source"  value={alert.source || 'SIEM'} />
          <InfoRow label="Source IP"      value={alert.source_ip}      mono />
          <InfoRow label="Destination IP" value={alert.destination_ip} mono />
          <InfoRow label="Event Type"     value={alert.event_type} />
          <InfoRow label="Severity"       value={alert.severity}       color={sevColor} />
          <InfoRow label="Status"         value={alert.status} />
          <InfoRow label="Timestamp"      value={fmtTime(alert.timestamp)} />
        </Section>

        {/* ── Asset info ──────────────────────────────────────────────── */}
        <Section title="Targeted Asset">
          {asset ? (
            <>
              <InfoRow label="Hostname"     value={asset.hostname}    mono />
              <InfoRow label="IP Address"   value={asset.ip_address}  mono />
              <InfoRow label="Type"         value={asset.asset_type} />
              <InfoRow label="Department"   value={asset.department} />
              <InfoRow label="Criticality"  value={asset.criticality} color={critColor} />
            </>
          ) : <div className="no-data">No asset linked</div>}
        </Section>

        {/* ── IOC info ────────────────────────────────────────────────── */}
        <Section title="Threat Intelligence / IOC">
          <InfoRow label="IOC Value"    value={ioc_info?.ioc_value  || alert.source_ip} mono />
          <InfoRow label="Type"         value={ioc_info?.ioc_type   || 'IP'} />
          <InfoRow label="Threat Type"  value={ioc_info?.threat_type || 'Unknown'} />
          <InfoRow label="Confidence"   value={ioc_info ? `${ioc_info.confidence?.toFixed(0)}%` : 'N/A'} />
          <div className="info-row">
            <span className="info-label">Reputation</span>
            <ReputationBar value={ioc_info?.reputation || 0} />
          </div>
          <InfoRow label="First Seen"   value={ioc_info?.first_seen ? fmtTime(ioc_info.first_seen) : 'N/A'} />
          <InfoRow label="Last Seen"    value={ioc_info?.last_seen  ? fmtTime(ioc_info.last_seen)  : 'N/A'} />
          {alert.iocs?.length > 0 && (
            <div className="ioc-chips-block">
              <span className="info-label">Indicators in this alert</span>
              <div className="ioc-chips">
                {alert.iocs.map((i, idx) => <IocChip key={idx} ioc={i} />)}
              </div>
            </div>
          )}
        </Section>

        {/* ── MITRE ───────────────────────────────────────────────────── */}
        <Section title="MITRE ATT&CK">
          {mitre ? (
            <>
              <InfoRow label="Technique ID"  value={mitre.id}     mono />
              <InfoRow label="Technique"     value={mitre.name} />
              <InfoRow label="Tactic"        value={mitre.tactic} />
              <a
                href={mitre.url || `https://attack.mitre.org/techniques/${mitre.id}/`}
                target="_blank"
                rel="noreferrer"
                className="mitre-link"
              >
                View on MITRE ATT&amp;CK →
              </a>
            </>
          ) : (
            <div className="no-data">No MITRE mapping for "{alert.event_type}"</div>
          )}
        </Section>
      </div>

      {/* ── Raw Log + IOC extraction ─────────────────────────────────────── */}
      {alert.raw_log && (
        <div className="detail-section-wide">
          <Section title="Raw Log">
            {alert.description && (
              <p className="raw-log-desc">{alert.description}</p>
            )}
            <pre className="raw-log-box">{alert.raw_log}</pre>
            <div className="raw-log-actions">
              <button
                className="extract-btn"
                onClick={handleExtractIocs}
                disabled={iocExtracting}
              >
                {iocExtracting ? 'Extracting…' : 'Extract IOCs'}
              </button>
              {extractedIocs !== null && (
                <span className="extract-count">
                  {extractedIocs.length} IOC{extractedIocs.length !== 1 ? 's' : ''} found
                </span>
              )}
            </div>
            {extractedIocs !== null && extractedIocs.length > 0 && (
              <table className="ioc-extract-table">
                <thead>
                  <tr><th>Type</th><th>Value</th><th>Known</th><th>Reputation</th><th>Threat Type</th></tr>
                </thead>
                <tbody>
                  {extractedIocs.map((ioc, i) => {
                    const repColor = ioc.reputation >= 80 ? '#ef4444'
                                   : ioc.reputation >= 50 ? '#f97316'
                                   : ioc.reputation >= 20 ? '#eab308'
                                   : '#22c55e'
                    return (
                      <tr key={i}>
                        <td><span className="source-tag">{ioc.type}</span></td>
                        <td className="mono ioc-value">{ioc.value}</td>
                        <td>{ioc.found
                          ? <span className="ioc-found">✓ Known</span>
                          : <span className="muted">—</span>}
                        </td>
                        <td>
                          {ioc.found
                            ? <span style={{ color: repColor, fontWeight: 600, fontFamily: 'var(--font-mono)', fontSize: 12 }}>{ioc.reputation?.toFixed(0)}</span>
                            : <span className="muted">—</span>}
                        </td>
                        <td className="muted">{ioc.threat_type || '—'}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
            {extractedIocs !== null && extractedIocs.length === 0 && (
              <div className="no-data" style={{ marginTop: 10 }}>No IOCs extracted from this log.</div>
            )}
          </Section>
        </div>
      )}

      {/* ── Correlation verdict ───────────────────────────────────────── */}
      {verdict_detail && (
        <div className="detail-section-wide">
          <Section title="Correlation Verdict">
            <VerdictPanel verdict={verdict_detail} correlationCount={correlation_count} isAttackChain={is_attack_chain} />
          </Section>
        </div>
      )}

      {/* ── Risk breakdown chart ──────────────────────────────────────── */}
      <div className="detail-section-wide">
        <Section title="Risk Score Breakdown">
          <RiskBreakdownChart breakdown={risk_breakdown} />
          {risk_breakdown && (
            <div className="weights-row">
              {Object.entries(risk_breakdown.weights || {}).map(([k, v]) => (
                <div key={k} className="weight-pill">
                  <span className="weight-key">{k.replace(/_/g, ' ')}</span>
                  <span className="weight-val">{(v * 100).toFixed(0)}%</span>
                </div>
              ))}
            </div>
          )}
        </Section>
      </div>

      {/* ── AI Explanation (BLUF) ─────────────────────────────────────── */}
      <div className="detail-section-wide">
        <Section title="AI Analysis">
          {bluf ? (
            <BlufBlock bluf={bluf} priority={alert.priority} />
          ) : blufFallbackText ? (
            <div className="ai-explanation">
              <span className="ai-icon">🤖</span>
              <p>{blufFallbackText}</p>
            </div>
          ) : (
            <div className="no-data">No explanation available.</div>
          )}
        </Section>
      </div>

      {/* ── Recommended actions ──────────────────────────────────────── */}
      <div className="detail-section-wide">
        <Section title="Recommended Actions">
          {bluf?.recommendation ? (
            <ul className="rec-list">
              {bluf.recommendation
                .split(/(?<=[.!])\s+/)
                .map(s => s.trim())
                .filter(Boolean)
                .map((b, i) => (
                  <li key={i} className="rec-item">
                    <span className="rec-bullet">›</span>
                    {b}
                  </li>
                ))}
            </ul>
          ) : recBullets.length > 0 ? (
            <ul className="rec-list">
              {recBullets.map((b, i) => (
                <li key={i} className="rec-item">
                  <span className="rec-bullet">›</span>
                  {b}
                </li>
              ))}
            </ul>
          ) : (
            <div className="no-data">No recommendations available.</div>
          )}
        </Section>
      </div>

      {/* ── Attack Timeline ──────────────────────────────────────────── */}
      {related_events?.length > 0 && (
        <div className="detail-section-wide">
          <div className="detail-card">
            <div className="detail-card-title">
              Attack Timeline
              {is_attack_chain && (
                <span style={{
                  marginLeft: 10,
                  fontSize: 10,
                  fontWeight: 800,
                  letterSpacing: '0.8px',
                  color: '#ef4444',
                  border: '1px solid rgba(239,68,68,0.4)',
                  background: 'rgba(239,68,68,0.1)',
                  padding: '2px 8px',
                  borderRadius: 4,
                  textTransform: 'uppercase',
                }}>
                  Attack Chain
                </span>
              )}
            </div>
            <AttackTimeline
              currentAlert={currentAlertForTimeline}
              relatedEvents={related_events}
              isAttackChain={is_attack_chain}
            />
          </div>
        </div>
      )}

      {/* ── Threat events ────────────────────────────────────────────── */}
      {threat_events?.length > 0 && (
        <div className="detail-section-wide">
          <Section title="Threat Events">
            <table className="te-table">
              <thead>
                <tr>
                  <th>ID</th><th>Type</th><th>Description</th><th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {threat_events.map(te => (
                  <tr key={te.id}>
                    <td className="mono">#{te.id}</td>
                    <td>{te.event_type}</td>
                    <td className="te-desc">{te.description}</td>
                    <td className="mono muted">{fmtTime(te.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
        </div>
      )}
    </div>
  )
}

function iocColor(rep) {
  return rep >= 80 ? '#ef4444' : rep >= 50 ? '#f97316' : rep >= 20 ? '#eab308' : '#4a6380'
}

function IocChip({ ioc }) {
  const color = ioc.found ? iocColor(ioc.reputation) : '#4a6380'
  const title = ioc.found
    ? `${ioc.type} · reputation ${Number(ioc.reputation).toFixed(0)}/100 · ${ioc.threat_type || 'unclassified'}`
    : `${ioc.type} · not in threat intel`
  return (
    <span className={`ioc-chip${ioc.found ? ' ioc-chip-found' : ''}`} style={{ '--c': color }} title={title}>
      <span className="ioc-chip-type">{ioc.type}</span>
      <span className="mono ioc-chip-value">{ioc.value}</span>
      {ioc.found && <span className="mono ioc-chip-rep">{Number(ioc.reputation).toFixed(0)}</span>}
      {ioc.role === 'source' && <span className="ioc-chip-role">src</span>}
    </span>
  )
}

const VERDICT_COLOR = {
  GENUINE_THREAT:        '#ef4444',
  LIKELY_FALSE_POSITIVE: '#4a6380',
  NEEDS_REVIEW:          '#eab308',
}

function VerdictPanel({ verdict, correlationCount, isAttackChain }) {
  const color = VERDICT_COLOR[verdict.verdict] || '#ccd8e8'
  const meta  = VERDICT_META[verdict.verdict] || VERDICT_META.NEEDS_REVIEW
  const pct   = Math.min(Math.max(verdict.score ?? 0, 0), 100)
  return (
    <div className="verdict-panel">
      <div className="verdict-panel-head">
        <div className="verdict-panel-main" style={{ borderLeftColor: color }}>
          <span className="bluf-label" style={{ color }}>{meta.symbol} {meta.label}</span>
          <span className="verdict-panel-conf mono">{verdict.confidence.toFixed(0)}% confidence</span>
        </div>
        <div className="verdict-gauge">
          <div className="verdict-gauge-labels">
            <span>Likely FP</span><span>Needs review</span><span>Genuine</span>
          </div>
          <div className="verdict-gauge-track">
            <div className="verdict-gauge-zone" style={{ left: 0,    width: '32%', background: 'rgba(74,99,128,0.25)' }} />
            <div className="verdict-gauge-zone" style={{ left: '32%', width: '28%', background: 'rgba(234,179,8,0.18)' }} />
            <div className="verdict-gauge-zone" style={{ left: '60%', width: '40%', background: 'rgba(239,68,68,0.18)' }} />
            <div className="verdict-gauge-marker" style={{ left: `${pct}%`, background: color }} title={`Genuineness score ${pct.toFixed(0)}/100`} />
          </div>
          <div className="verdict-gauge-score mono">score {pct.toFixed(0)} / 100 · {correlationCount ?? 0} correlated alert{correlationCount === 1 ? '' : 's'} in 24 h{isAttackChain ? ' · part of attack chain' : ''}</div>
        </div>
      </div>
      <ul className="verdict-reasons">
        {verdict.reasons.map((r, i) => (
          <li key={i} className="verdict-reason">
            <span className="rec-bullet" style={{ color }}>›</span>{r}
          </li>
        ))}
      </ul>
    </div>
  )
}

function PageHeader({ onBack }) {
  return (
    <header className="detail-header">
      <button className="back-btn" onClick={onBack}>← Back to Dashboard</button>
      <div className="detail-header-title">
        <span className="logo-icon-sm">🛡️</span> THREATNEXUS
      </div>
    </header>
  )
}
