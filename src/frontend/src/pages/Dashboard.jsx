import { useState, useEffect, useCallback, useRef } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
  ResponsiveContainer,
} from 'recharts'
import { api } from '../services/api.js'
import StatsCards      from '../components/StatsCards.jsx'
import AlertTable      from '../components/AlertTable.jsx'
import FeedIngestPanel from '../components/FeedIngestPanel.jsx'
import TacticCoverage  from '../components/TacticCoverage.jsx'
import AiEngineBadge   from '../components/AiEngineBadge.jsx'
import FusionPanel     from '../components/FusionPanel.jsx'
import { VERDICT_META } from '../components/VerdictBadge.jsx'
import './Dashboard.css'

const PRIORITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
}

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="chart-tooltip">
      <span style={{ color: payload[0].fill }}>{payload[0].name}</span>
      <strong>{payload[0].value}</strong>
    </div>
  )
}

// ── IOC reputation heat-strip ─────────────────────────────────────────────
// Each IOC becomes a small coloured block. Colour encodes reputation score.
// Sorted highest-reputation first so the danger zone clusters top-left.
function iocColor(rep) {
  if (rep >= 80) return '#ef4444'   // critical — malicious
  if (rep >= 60) return '#f97316'   // high
  if (rep >= 35) return '#eab308'   // medium / suspicious
  return '#22c55e'                  // low / clean
}

function iocLabel(ioc) {
  return `${ioc.ioc_value} (${ioc.ioc_type})\nReputation: ${ioc.reputation}/100\nThreat: ${ioc.threat_type || 'unclassified'}`
}

const HEAT_LEGEND = [
  { label: 'Malicious',   color: '#ef4444', min: 80  },
  { label: 'Suspicious',  color: '#f97316', min: 60  },
  { label: 'Low risk',    color: '#eab308', min: 35  },
  { label: 'Clean',       color: '#22c55e', min: 0   },
]

function IocHeatStrip({ iocs }) {
  if (!iocs?.length) {
    return <div className="ioc-strip-empty">No IOCs loaded</div>
  }
  const sorted = [...iocs].sort((a, b) => b.reputation - a.reputation)
  return (
    <div className="ioc-strip-panel">
      <div className="ioc-strip-legend">
        <div className="ioc-strip-legend-labels">
          {HEAT_LEGEND.map(l => (
            <div key={l.label} className="ioc-strip-legend-item">
              <div className="ioc-strip-legend-swatch" style={{ background: l.color }} />
              {l.label}
            </div>
          ))}
        </div>
      </div>
      <div className="ioc-strip-grid">
        {sorted.map(ioc => (
          <div
            key={ioc.id}
            className="ioc-block"
            style={{ background: iocColor(ioc.reputation) + '33', border: `1px solid ${iocColor(ioc.reputation)}55`, outline: `0px solid ${iocColor(ioc.reputation)}` }}
            title={iocLabel(ioc)}
          >
            {/* Inner fill conveys exact reputation intensity */}
            <div style={{
              position: 'absolute', bottom: 0, left: 0, right: 0,
              height: `${ioc.reputation}%`,
              background: iocColor(ioc.reputation),
              opacity: 0.35,
              borderRadius: '1px',
            }} />
          </div>
        ))}
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [stats,        setStats]        = useState(null)
  const [alerts,       setAlerts]       = useState([])
  const [iocCount,     setIocCount]     = useState(0)
  const [loading,      setLoading]      = useState(true)
  const [error,        setError]        = useState(null)
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [verdictFilter, setVerdictFilter] = useState('ALL')
  const [priorityFilter, setPriorityFilter] = useState('ALL')
  const [activeCard,   setActiveCard]   = useState('total')
  const navigate  = useNavigate()
  const tableRef  = useRef(null)
  const iocRef    = useRef(null)
  const [feedFilter,   setFeedFilter]   = useState('ALL')
  const [coverage,     setCoverage]     = useState(null)
  const [refreshing,   setRefreshing]   = useState(false)

  const [iocs, setIocs] = useState([])

  const load = useCallback((silent = false) => {
    if (silent) setRefreshing(true)
    return Promise.all([api.getDashboard(), api.getAlerts(), api.getIOCs(), api.getMitreCoverage()])
      .then(([s, a, iocList, cov]) => {
        setStats(s)
        setAlerts(a)
        setIocCount(iocList.length)
        setIocs(iocList)
        setCoverage(cov)
        setError(null)
      })
      .catch(e => setError(e.message))
      .finally(() => { setLoading(false); setRefreshing(false) })
  }, [])

  useEffect(() => { load() }, [load])

  // Stat-card shortcuts → filters / panels
  function handleCard(key) {
    const scrollTo = ref => ref.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    switch (key) {
      case 'total':    setPriorityFilter('ALL'); setVerdictFilter('ALL'); setStatusFilter('ALL'); setFeedFilter('ALL'); scrollTo(tableRef); break
      case 'critical': setPriorityFilter('CRITICAL'); setVerdictFilter('ALL'); scrollTo(tableRef); break
      case 'high':     setPriorityFilter('HIGH');     setVerdictFilter('ALL'); scrollTo(tableRef); break
      case 'genuine':  setVerdictFilter('GENUINE_THREAT');        setPriorityFilter('ALL'); scrollTo(tableRef); break
      case 'fp':       setVerdictFilter('LIKELY_FALSE_POSITIVE'); setPriorityFilter('ALL'); scrollTo(tableRef); break
      case 'review':   setVerdictFilter('NEEDS_REVIEW');          setPriorityFilter('ALL'); scrollTo(tableRef); break
      case 'chains':   navigate('/brief#chains'); break
      case 'iocs':     scrollTo(iocRef); break
      default: break
    }
  }

  // Highlighted card follows the filters (also when changed via the pills)
  useEffect(() => {
    if (priorityFilter === 'ALL' && verdictFilter === 'ALL') setActiveCard('total')
    else if (priorityFilter === 'CRITICAL' && verdictFilter === 'ALL') setActiveCard('critical')
    else if (priorityFilter === 'HIGH' && verdictFilter === 'ALL') setActiveCard('high')
    else if (verdictFilter === 'GENUINE_THREAT' && priorityFilter === 'ALL') setActiveCard('genuine')
    else if (verdictFilter === 'LIKELY_FALSE_POSITIVE' && priorityFilter === 'ALL') setActiveCard('fp')
    else if (verdictFilter === 'NEEDS_REVIEW' && priorityFilter === 'ALL') setActiveCard('review')
    else setActiveCard(null)
  }, [priorityFilter, verdictFilter])

  const feeds = Array.from(new Set(alerts.map(a => a.source || 'SIEM'))).sort()
  const visibleAlerts = alerts.filter(a =>
    (statusFilter  === 'ALL' || a.status === statusFilter) &&
    (priorityFilter === 'ALL' || a.priority === priorityFilter) &&
    (verdictFilter === 'ALL' || (a.verdict || 'NEEDS_REVIEW') === verdictFilter) &&
    (feedFilter    === 'ALL' || (a.source || 'SIEM') === feedFilter)
  )

  const chartData = stats
    ? [
        { name: 'Critical', value: stats.critical, fill: PRIORITY_COLORS.CRITICAL },
        { name: 'High',     value: stats.high,     fill: PRIORITY_COLORS.HIGH     },
        { name: 'Medium',   value: stats.medium,   fill: PRIORITY_COLORS.MEDIUM   },
        { name: 'Low',      value: stats.low,      fill: PRIORITY_COLORS.LOW      },
      ]
    : []

  return (
    <div className="dashboard">
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <header className="dash-header">
        <div className="dash-logo">
          <span className="logo-icon">🛡️</span>
          <div>
            <div className="logo-title">THREATNEXUS</div>
            <div className="logo-sub">Threat Correlation &amp; BLUF Prioritisation · IBM Bob</div>
          </div>
        </div>
        <div className="dash-meta">
          <AiEngineBadge />
          <Link to="/brief" className="brief-link">▤ Commander Brief</Link>
          <button className="refresh-btn" onClick={() => load(true)} disabled={refreshing} title="Reload data">
            {refreshing ? '…' : '↻'}
          </button>
          <span className="live-dot" />
          <span className="live-label">LIVE</span>
          <span className="dash-time">{new Date().toUTCString()}</span>
        </div>
      </header>

      {error && <div className="error-banner">Backend unreachable: {error}</div>}

      {/* ── Stats ───────────────────────────────────────────────────────── */}
      <section className="dash-section">
        <StatsCards stats={stats} iocCount={iocCount} onSelect={handleCard} active={activeCard} />
      </section>

      {/* ── Feed ingestion ──────────────────────────────────────────────── */}
      <section className="dash-section">
        <FeedIngestPanel onIngested={() => load(true)} />
      </section>

      {/* ── Live Multi-Source Fusion Demo ───────────────────────────────── */}
      <section className="dash-section">
        <FusionPanel />
      </section>

      {/* ── MITRE ATT&CK coverage ───────────────────────────────────────── */}
      <section className="dash-section">
        <div className="dash-card">
          <div className="card-title">
            MITRE ATT&CK coverage
            <span className="card-title-count">alerts per tactic · kill-chain order</span>
            {stats?.attack_chains > 0 && (
              <span className="chain-flag">⛓ {stats.attack_chains} multi-stage chain{stats.attack_chains === 1 ? '' : 's'} active</span>
            )}
          </div>
          {loading ? <div className="chart-skeleton" style={{ height: 64 }} /> : <TacticCoverage tactics={coverage?.tactics} />}
        </div>
      </section>

      {/* ── Charts row ──────────────────────────────────────────────────── */}
      <section className="dash-section dash-charts">
        {/* Bar chart */}
        <div className="dash-card chart-card">
          <div className="card-title">Alert Distribution by Priority</div>
          {loading
            ? <div className="chart-skeleton" />
            : (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={chartData} barSize={36} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
                  <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {chartData.map(d => <Cell key={d.name} fill={d.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
        </div>

        {/* IOC reputation heat-strip */}
        <div className="dash-card chart-card" ref={iocRef}>
          <div className="card-title">
            IOC Reputation
            <span className="card-title-count">{iocs.length} tracked</span>
          </div>
          {loading
            ? <div className="chart-skeleton" />
            : <IocHeatStrip iocs={iocs} />}
        </div>
      </section>

      {/* ── Alert table ─────────────────────────────────────────────────── */}
      <section className="dash-section" ref={tableRef}>
        <div className="dash-card">
          <div className="card-title">
            All Alerts
            <span className="card-title-count">{visibleAlerts.length} of {alerts.length}</span>
          </div>

          {/* Filter pills: status · verdict · feed */}
          {!loading && (
            <div className="filter-rows">
              <div className="status-filter-row">
                <span className="filter-label">Status</span>
                {['ALL', 'OPEN', 'IN_PROGRESS', 'RESOLVED'].map(s => (
                  <button
                    key={s}
                    className={`status-filter-pill${statusFilter === s ? ' active' : ''}`}
                    onClick={() => setStatusFilter(s)}
                  >
                    {s === 'IN_PROGRESS' ? 'In Progress' : s.charAt(0) + s.slice(1).toLowerCase()}
                  </button>
                ))}
              </div>
              <div className="status-filter-row">
                <span className="filter-label">Priority</span>
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(p => (
                  <button
                    key={p}
                    className={`status-filter-pill${priorityFilter === p ? ' active' : ''}`}
                    onClick={() => setPriorityFilter(p)}
                  >
                    {p === 'ALL' ? 'All' : p.charAt(0) + p.slice(1).toLowerCase()}
                  </button>
                ))}
              </div>
              <div className="status-filter-row">
                <span className="filter-label">Verdict</span>
                {['ALL', 'GENUINE_THREAT', 'NEEDS_REVIEW', 'LIKELY_FALSE_POSITIVE'].map(v => (
                  <button
                    key={v}
                    className={`status-filter-pill${verdictFilter === v ? ' active' : ''}`}
                    onClick={() => setVerdictFilter(v)}
                  >
                    {v === 'ALL' ? 'All' : `${VERDICT_META[v].symbol} ${VERDICT_META[v].label}`}
                  </button>
                ))}
              </div>
              <div className="status-filter-row">
                <span className="filter-label">Feed</span>
                {['ALL', ...feeds].map(f => (
                  <button
                    key={f}
                    className={`status-filter-pill${feedFilter === f ? ' active' : ''}`}
                    onClick={() => setFeedFilter(f)}
                  >
                    {f === 'ALL' ? 'All' : f}
                  </button>
                ))}
              </div>
            </div>
          )}

          {loading
            ? <div className="table-skeleton" />
            : <AlertTable alerts={visibleAlerts} />}
        </div>
      </section>
    </div>
  )
}
