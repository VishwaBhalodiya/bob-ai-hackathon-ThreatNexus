import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import PriorityBadge from './PriorityBadge.jsx'
import VerdictBadge from './VerdictBadge.jsx'
import './AlertTable.css'

const COLUMNS = [
  { key: 'id',           label: '#',            sortable: true  },
  { key: 'timestamp',    label: 'Time',          sortable: true  },
  { key: 'source_ip',    label: 'Source IP',     sortable: false },
  { key: 'destination_ip',label:'Dest IP',       sortable: false },
  { key: 'event_type',   label: 'Event',         sortable: true  },
  { key: 'source',       label: 'Feed',          sortable: true  },
  { key: 'severity',     label: 'Severity',      sortable: true  },
  { key: 'risk_score',   label: 'Risk Score',    sortable: true  },
  { key: 'priority',     label: 'Priority',      sortable: true  },
  { key: 'verdict',      label: 'Verdict',       sortable: true  },
  { key: 'mitre_technique_id', label: 'ATT&CK',  sortable: true  },
  { key: 'status',       label: 'Status',        sortable: true  },
  { key: 'feedback',     label: 'Triage',        sortable: true  },
]

// Feed source abbreviations — keep the table compact
const SOURCE_ABBREV = {
  'SIEM':                 'SIEM',
  'Firewall':             'FW',
  'IDS/IPS':              'IDS',
  'EDR':                  'EDR',
  'Email Security':       'EMAIL',
  'Vulnerability Scanner':'VULN',
  'Threat Intel Feed':    'TI',
}

// Feedback icon config — symbol + colour only, no tooltip text here
const FEEDBACK_META = {
  TRUE_POSITIVE:  { symbol: '✓', color: '#4ade80', title: 'True Positive'  },
  FALSE_POSITIVE: { symbol: '✕', color: '#f87171', title: 'False Positive' },
  ESCALATED:      { symbol: '↑', color: '#fb923c', title: 'Escalated'      },
  UNREVIEWED:     { symbol: '·', color: 'var(--text-muted)', title: 'Unreviewed' },
}

function FeedbackIcon({ feedback }) {
  const fb = (feedback || 'UNREVIEWED').toUpperCase()
  const meta = FEEDBACK_META[fb] || FEEDBACK_META.UNREVIEWED
  return (
    <span
      className="feedback-icon"
      style={{ color: meta.color }}
      title={meta.title}
    >
      {meta.symbol}
    </span>
  )
}

function fmtTime(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('en-GB', {
    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit'
  })
}

function StatusBadge({ status }) {
  const cls = {
    OPEN: 'status-open',
    IN_PROGRESS: 'status-progress',
    RESOLVED: 'status-resolved',
  }[status] || 'status-open'
  return <span className={`status-badge ${cls}`}>{status}</span>
}

function RiskBar({ score }) {
  const pct = Math.min(Math.max(score, 0), 100)
  const color = pct >= 80 ? 'var(--critical)'
              : pct >= 60 ? 'var(--high)'
              : pct >= 30 ? 'var(--medium)'
              :              'var(--low)'
  return (
    <div className="risk-bar-wrap">
      <div className="risk-bar-track">
        <div className="risk-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="risk-bar-val" style={{ color }}>{pct.toFixed(0)}</span>
    </div>
  )
}

export default function AlertTable({ alerts }) {
  const navigate = useNavigate()
  const [sortKey, setSortKey]   = useState('risk_score')
  const [sortDir, setSortDir]   = useState('desc')

  function handleSort(key) {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('desc')
    }
  }

  const sorted = [...(alerts || [])].sort((a, b) => {
    let av = a[sortKey], bv = b[sortKey]
    if (typeof av === 'string') av = av.toLowerCase()
    if (typeof bv === 'string') bv = bv.toLowerCase()
    if (av < bv) return sortDir === 'asc' ? -1 : 1
    if (av > bv) return sortDir === 'asc' ? 1  : -1
    return 0
  })

  const sortIcon = (key) =>
    sortKey === key ? (sortDir === 'asc' ? ' ↑' : ' ↓') : ''

  return (
    <div className="alert-table-wrap">
      <table className="alert-table">
        <thead>
          <tr>
            {COLUMNS.map(col => (
              <th
                key={col.key}
                className={col.sortable ? 'sortable' : ''}
                onClick={col.sortable ? () => handleSort(col.key) : undefined}
              >
                {col.label}{sortIcon(col.key)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map(alert => (
            <tr
              key={alert.id}
              className="alert-row"
              onClick={() => navigate(`/alerts/${alert.id}`)}
            >
              <td className="mono muted">#{alert.id}</td>
              <td className="mono muted nowrap">{fmtTime(alert.timestamp)}</td>
              <td className="mono ip">{alert.source_ip}</td>
              <td className="mono ip muted">{alert.destination_ip || '—'}</td>
              <td className="event-type">{alert.event_type}</td>
              <td>
                <span className="source-tag">{SOURCE_ABBREV[alert.source] || alert.source || 'SIEM'}</span>
              </td>
              <td><SeverityText s={alert.severity} p={alert.priority} /></td>
              <td><RiskBar score={alert.risk_score} /></td>
              <td><PriorityBadge priority={alert.priority} /></td>
              <td><VerdictBadge verdict={alert.verdict} confidence={alert.verdict_confidence} compact /></td>
              <td className="mono muted nowrap" title={alert.mitre_tactic || ''}>{alert.mitre_technique_id || '—'}</td>
              <td><StatusBadge status={alert.status} /></td>
              <td onClick={e => e.stopPropagation()}>
                <FeedbackIcon feedback={alert.feedback} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {(!alerts || alerts.length === 0) && (
        <div className="empty-state">No alerts found.</div>
      )}
    </div>
  )
}

const SEV_RANK = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 }
const SEV_COLORS = { CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--medium)', LOW: 'var(--low)' }

function SeverityText({ s, p }) {
  const sev = (s || 'LOW').toUpperCase()
  const pri = (p || sev).toUpperCase()
  const sevRank = SEV_RANK[sev] ?? 0
  const priRank = SEV_RANK[pri] ?? 0
  const color = SEV_COLORS[sev]

  if (sevRank === priRank) {
    return <span style={{ color, fontWeight: 600, fontSize: 12 }}>{s}</span>
  }

  const raised    = priRank > sevRank
  const adjColor  = SEV_COLORS[pri]
  const tooltip   = raised
    ? 'Priority raised due to asset criticality and threat context'
    : 'Priority lowered due to threat context'

  return (
    <span className="sev-adjusted" title={tooltip}>
      <span style={{ color, fontWeight: 600, fontSize: 12 }}>{s}</span>
      <span className={`sev-adj-arrow ${raised ? 'sev-adj-raised' : 'sev-adj-lowered'}`}
            style={{ color: adjColor }}>
        {raised ? '↑' : '↓'}{pri}
      </span>
    </span>
  )
}
