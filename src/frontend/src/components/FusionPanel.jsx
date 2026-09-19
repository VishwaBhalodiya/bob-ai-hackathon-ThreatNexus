// FusionPanel.jsx — Live 4-Bot Multi-Source Fusion Demo
//
// Demonstrates the full intelligence-fusion loop:
//   1. Click "Run Live Demo" → sends sample data from all 3 source bots
//   2. Backend runs Bot 1 (Cyber), Bot 2 (Intel), Bot 3 (Satellite) and Bot 4 (Fusion)
//   3. Panel shows the live result: Evidence Matrix, risk score, FP probability, MITRE, BLUF
//
// This is the key demo feature that proves multi-source intelligence fusion.

import { useState, useCallback } from 'react'
import { api } from '../services/api.js'
import EvidenceMatrix from './EvidenceMatrix.jsx'
import './FusionPanel.css'

const PRIORITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
}

const FP_COLORS = {
  GENUINE_THREAT:        '#22c55e',
  UNCERTAIN:             '#eab308',
  LIKELY_FALSE_POSITIVE: '#ef4444',
}

function PriorityChip({ priority }) {
  return (
    <span style={{
      background: (PRIORITY_COLORS[priority] || '#94a3b8') + '20',
      color: PRIORITY_COLORS[priority] || '#94a3b8',
      border: `1px solid ${(PRIORITY_COLORS[priority] || '#94a3b8')}44`,
      borderRadius: 4, padding: '2px 10px', fontSize: 11, fontWeight: 700,
      textTransform: 'uppercase', letterSpacing: '0.05em',
    }}>
      {priority}
    </span>
  )
}

export default function FusionPanel() {
  const [result,  setResult]  = useState(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState(null)

  const runDemo = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      // Load sample data from the server and POST it as a fusion run
      const samples = await api.getFusionSamples()
      const res = await api.runFusion(samples.demo_request)
      setResult(res)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  const botCards = result
    ? [
        {
          label:  'Bot 1',
          name:   'Cyber / SIEM Bot',
          count:  result.bot_outputs?.cyber?.length ?? 0,
          unit:   'events',
          active: result.bot_outputs?.cyber?.length > 0,
        },
        {
          label:  'Bot 2',
          name:   'Intelligence Bot',
          count:  result.bot_outputs?.intel?.length ?? 0,
          unit:   'reports',
          active: result.bot_outputs?.intel?.length > 0,
        },
        {
          label:  'Bot 3',
          name:   'Satellite Bot',
          count:  result.bot_outputs?.satellite?.length ?? 0,
          unit:   'telemetry',
          active: result.bot_outputs?.satellite?.length > 0,
        },
      ]
    : [
        { label: 'Bot 1', name: 'Cyber / SIEM Bot',     count: '—', unit: 'events'   },
        { label: 'Bot 2', name: 'Intelligence Bot',     count: '—', unit: 'reports'  },
        { label: 'Bot 3', name: 'Satellite Bot',        count: '—', unit: 'telemetry'},
      ]

  return (
    <div className="fusion-panel">
      <div className="fusion-panel-header">
        <div className="fusion-panel-title">
          <div className="fusion-live-dot" />
          Live Threat Fusion
        </div>
        <button className="fusion-run-btn" onClick={runDemo} disabled={loading}>
          {loading ? '⏳ Running…' : '▶ Run Live Demo'}
        </button>
      </div>

      {/* Bot status row */}
      <div className="fusion-bot-row">
        {botCards.map((b, i) => (
          <>
            <div key={b.label} className={`fusion-bot-card ${b.active ? 'active' : ''}`}>
              <div className="bot-label">{b.label}</div>
              <div className="bot-name">{b.name}</div>
              <div className="bot-count">
                {b.count}
                <span className="bot-count-unit">{b.unit}</span>
              </div>
            </div>
            {i < botCards.length - 1 && <div className="fusion-arrow">→</div>}
          </>
        ))}
        <div className="fusion-arrow">→</div>
        <div className={`fusion-bot-card ${result ? 'active' : ''}`}>
          <div className="bot-label">Bot 4</div>
          <div className="bot-name">Fusion &amp; Decision Bot</div>
          <div className="bot-count" style={{ color: result ? PRIORITY_COLORS[result.risk?.priority] : '#4b5563' }}>
            {result ? `${result.risk?.risk_score?.toFixed(0) ?? '—'}` : '—'}
            <span className="bot-count-unit">risk</span>
          </div>
        </div>
      </div>

      {error && <div className="fusion-error">Error: {error}</div>}

      {!result && !loading && (
        <div className="fusion-empty">
          Click <strong>Run Live Demo</strong> to feed sample data through all 4 bots and see the fusion result.
        </div>
      )}

      {result && (
        <>
          {/* Fusion result card */}
          <div className={`fusion-result-card ${(result.risk?.priority || 'low').toLowerCase()}`}>
            <div className="fusion-result-header">
              <PriorityChip priority={result.risk?.priority} />
              <span className="fusion-result-title">
                Fusion Risk Score: {result.risk?.risk_score?.toFixed(1) ?? '—'}/100
              </span>
              <span style={{ fontSize: 12, color: FP_COLORS[result.fp?.fp_label] }}>
                FP probability: {result.fp?.fp_score?.toFixed(0) ?? '—'}% —{' '}
                {result.fp?.fp_label?.replace(/_/g, ' ')}
              </span>
            </div>

            {/* BLUF bottom line */}
            {result.bluf?.bottom_line && (
              <div className="fusion-bluf-text">{result.bluf.bottom_line}</div>
            )}

            {/* MITRE techniques */}
            {result.mitre_techniques?.length > 0 && (
              <div className="fusion-mitre-list">
                {result.mitre_techniques.map(m => (
                  <span key={m.technique_id} className="mitre-chip" title={`${m.technique} · ${m.tactic}`}>
                    {m.technique_id}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Evidence Matrix */}
          <EvidenceMatrix
            matrix={result.evidence_matrix}
            fp={result.fp}
            corrConfidence={result.correlation_confidence}
            sourcesPresent={result.sources_present}
          />
        </>
      )}
    </div>
  )
}
