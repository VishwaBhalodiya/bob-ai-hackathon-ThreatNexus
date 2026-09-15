import { useEffect, useState } from 'react'
import { api } from '../services/api.js'
import VerdictBadge from './VerdictBadge.jsx'
import PriorityBadge from './PriorityBadge.jsx'
import './FeedIngestPanel.css'

const SOURCES = ['SIEM', 'Firewall', 'IDS/IPS', 'EDR', 'Email Security', 'Vulnerability Scanner', 'Threat Intel Feed']

/**
 * FeedIngestPanel — paste (or load a sample of) a raw feed in any supported
 * format, push it through /api/ingest, and see what came out the other side:
 * how many records were normalised, de-duplicated, and which verdicts /
 * priorities they were assigned.  Calls onIngested() so the dashboard can
 * refresh its data.
 */
export default function FeedIngestPanel({ onIngested }) {
  const [formats, setFormats] = useState([])
  const [samples, setSamples] = useState([])
  const [format,  setFormat]  = useState('auto')
  const [source,  setSource]  = useState('')
  const [payload, setPayload] = useState('')
  const [busy,    setBusy]    = useState(false)
  const [result,  setResult]  = useState(null)
  const [error,   setError]   = useState(null)
  const [open,    setOpen]    = useState(false)
  const [runAllBusy, setRunAllBusy] = useState(false)

  useEffect(() => {
    api.getIngestFormats().then(d => setFormats(d.formats || [])).catch(() => {})
    api.getIngestSamples().then(setSamples).catch(() => {})
  }, [])

  function loadSample(s) {
    setPayload(s.payload)
    setFormat(s.format)
    setSource(s.source)
    setResult(null)
    setError(null)
    setOpen(true)
  }

  async function submit(e) {
    e?.preventDefault()
    if (!payload.trim() || busy) return
    setBusy(true); setError(null); setResult(null)
    try {
      const res = await api.ingest(payload, format, source || null)
      setResult(res)
      onIngested?.(res)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  // Demo helper: ingest every bundled sample in sequence, as if five feeds
  // delivered at once.
  async function runAll() {
    if (runAllBusy || !samples.length) return
    setRunAllBusy(true); setError(null)
    const totals = { received: 0, ingested: 0, duplicates: 0, iocs_added: 0, iocs_updated: 0, alerts_rescored: 0, feeds: 0,
                     summary: { critical: 0, high: 0, medium: 0, low: 0, genuine: 0, likely_false_positive: 0, needs_review: 0, attack_chains: 0 },
                     alerts: [], warnings: [], format: 'multi' }
    try {
      for (const s of samples) {
        const r = await api.ingest(s.payload, s.format, s.source)
        totals.feeds += 1
        for (const k of ['received', 'ingested', 'duplicates', 'iocs_added', 'iocs_updated', 'alerts_rescored']) totals[k] += r[k] || 0
        for (const k of Object.keys(totals.summary)) totals.summary[k] += r.summary?.[k] || 0
        totals.alerts.push(...(r.alerts || []))
        totals.warnings.push(...(r.warnings || []))
      }
      setResult(totals)
      onIngested?.(totals)
    } catch (err) {
      setError(err.message)
    } finally {
      setRunAllBusy(false)
    }
  }

  return (
    <div className="ingest-panel">
      <div className="ingest-head">
        <div className="ingest-title-row">
          <span className="card-title" style={{ marginBottom: 0 }}>
            Feed Ingestion
            <span className="card-title-count">{formats.length ? `${formats.length - 1} formats` : ''}</span>
          </span>
          <div className="ingest-head-actions">
            <button className="ingest-btn ingest-btn-ghost" onClick={runAll} disabled={runAllBusy || !samples.length}>
              {runAllBusy ? 'Ingesting all feeds…' : '⇣ Ingest all sample feeds'}
            </button>
            <button className="ingest-btn ingest-btn-ghost" onClick={() => setOpen(o => !o)}>
              {open ? 'Hide' : 'Paste a feed'}
            </button>
          </div>
        </div>

        {/* Sample chips — one per supported format */}
        <div className="sample-row">
          {samples.map(s => (
            <button key={s.filename} className="sample-chip" onClick={() => loadSample(s)} title={s.description}>
              <span className="sample-fmt">{s.format.toUpperCase()}</span>
              {s.name}
            </button>
          ))}
          {!samples.length && <span className="muted" style={{ fontSize: 12 }}>Backend unreachable — samples unavailable</span>}
        </div>
      </div>

      {open && (
        <form className="ingest-form" onSubmit={submit}>
          <div className="ingest-controls">
            <label className="ingest-field">
              <span>Format</span>
              <select value={format} onChange={e => setFormat(e.target.value)}>
                {(formats.length ? formats : [{ id: 'auto', label: 'Auto-detect' }]).map(f => (
                  <option key={f.id} value={f.id} title={f.description}>{f.label}</option>
                ))}
              </select>
            </label>
            <label className="ingest-field">
              <span>Feed label</span>
              <select value={source} onChange={e => setSource(e.target.value)}>
                <option value="">(infer from records)</option>
                {SOURCES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>
            <button type="submit" className="ingest-btn" disabled={busy || !payload.trim()}>
              {busy ? 'Ingesting…' : '⇣ Ingest'}
            </button>
          </div>
          <textarea
            className="ingest-textarea mono"
            value={payload}
            onChange={e => setPayload(e.target.value)}
            placeholder={'Paste CEF / syslog / JSON / CSV / STIX 2.1 here — or load a sample above.\n\nCEF:0|Vendor|Product|1.0|100|Outbound C2 beacon|9|src=185.220.101.47 dst=10.0.0.10 dhost=DC01'}
            spellCheck={false}
            rows={8}
          />
        </form>
      )}

      {error && <div className="ingest-error">✕ {error}</div>}

      {result && <IngestResult result={result} />}
    </div>
  )
}

function IngestResult({ result }) {
  const s = result.summary || {}
  const isStix = result.format === 'stix'
  return (
    <div className="ingest-result">
      <div className="ingest-result-head">
        <span className="ingest-result-title">
          {result.format === 'multi' ? `${result.feeds} feeds ingested` : `Parsed as ${result.format.toUpperCase()}`}
        </span>
        <div className="ingest-stat-row">
          <Stat label="records" value={result.received} />
          {!isStix && <Stat label="new alerts" value={result.ingested} accent="var(--accent-live)" />}
          {!isStix && <Stat label="de-duplicated" value={result.duplicates} />}
          {(isStix || result.iocs_added || result.iocs_updated) ? (
            <>
              <Stat label="IOCs added" value={result.iocs_added} accent="var(--accent-live)" />
              <Stat label="IOCs updated" value={result.iocs_updated} />
              <Stat label="alerts re-scored" value={result.alerts_rescored} />
            </>
          ) : null}
        </div>
      </div>

      {!isStix && result.ingested > 0 && (
        <div className="ingest-verdict-row">
          <span className="ingest-pill" style={{ '--c': 'var(--critical)' }}>{s.critical} critical</span>
          <span className="ingest-pill" style={{ '--c': 'var(--high)' }}>{s.high} high</span>
          <span className="ingest-pill" style={{ '--c': 'var(--medium)' }}>{s.medium} medium</span>
          <span className="ingest-pill" style={{ '--c': 'var(--low)' }}>{s.low} low</span>
          <span className="ingest-sep" />
          <span className="ingest-pill" style={{ '--c': 'var(--critical)' }}>◆ {s.genuine} genuine</span>
          <span className="ingest-pill" style={{ '--c': 'var(--medium)' }}>◈ {s.needs_review} review</span>
          <span className="ingest-pill" style={{ '--c': 'var(--text-muted)' }}>◇ {s.likely_false_positive} suppressed</span>
          {s.attack_chains > 0 && (
            <span className="ingest-pill ingest-pill-chain">⛓ {s.attack_chains} in attack chains</span>
          )}
        </div>
      )}

      {result.warnings?.length > 0 && (
        <ul className="ingest-warnings">
          {result.warnings.map((w, i) => <li key={i}>⚠ {w}</li>)}
        </ul>
      )}

      {result.alerts?.length > 0 && (
        <table className="ingest-table">
          <thead>
            <tr><th>#</th><th>Feed</th><th>Source IP</th><th>Event → Technique</th><th>Severity → Priority</th><th>Verdict</th></tr>
          </thead>
          <tbody>
            {result.alerts.map(a => (
              <tr key={a.id}>
                <td className="mono muted">#{a.id}</td>
                <td><span className="source-tag">{a.source}</span> <span className="muted mono" style={{ fontSize: 10 }}>{a.feed_format}</span></td>
                <td className="mono">{a.source_ip}</td>
                <td>
                  {a.event_type}
                  {a.mitre_technique_id && <span className="mono muted" style={{ marginLeft: 6, fontSize: 11 }}>{a.mitre_technique_id}</span>}
                </td>
                <td>
                  <span className="muted" style={{ fontSize: 11 }}>{a.severity}</span>
                  <span className="muted" style={{ margin: '0 6px' }}>→</span>
                  <PriorityBadge priority={a.priority} />
                </td>
                <td><VerdictBadge verdict={a.verdict} confidence={a.verdict_confidence} compact /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

function Stat({ label, value, accent }) {
  return (
    <span className="ingest-stat">
      <strong className="mono" style={accent ? { color: accent } : {}}>{value ?? 0}</strong> {label}
    </span>
  )
}
