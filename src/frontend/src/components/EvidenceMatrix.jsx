// EvidenceMatrix.jsx — shows which source bots contributed to a fusion result
// and provides the key "WHY WAS THIS PRIORITIZED?" explainability feature.
import './EvidenceMatrix.css'

const CORR_COLOR = (pct) => {
  if (pct >= 80) return '#22c55e'
  if (pct >= 55) return '#eab308'
  if (pct >= 30) return '#f97316'
  return '#94a3b8'
}

const FP_META = {
  GENUINE_THREAT:        { color: '#22c55e', label: 'Genuine Threat' },
  UNCERTAIN:             { color: '#eab308', label: 'Uncertain' },
  LIKELY_FALSE_POSITIVE: { color: '#ef4444', label: 'Likely False Positive' },
}

/**
 * EvidenceMatrix — renders a structured evidence summary from a FusionResult.
 *
 * Props:
 *   matrix        — evidence_matrix dict from the Fusion Bot
 *   fp            — { fp_score, fp_label, reasons } from the Fusion Bot
 *   corrConfidence — correlation_confidence (0-100)
 *   sourcesPresent — number of sources corroborating (1-3)
 */
export default function EvidenceMatrix({ matrix, fp, corrConfidence, sourcesPresent }) {
  if (!matrix) return null

  const corrPct    = corrConfidence ?? 0
  const corrColor  = CORR_COLOR(corrPct)
  const fpMeta     = FP_META[fp?.fp_label] || { color: '#94a3b8', label: fp?.fp_label || '—' }

  const sources = [
    {
      key:     'cyber',
      label:   'Cyber Sensor',
      present: matrix.cyber?.present,
      detail: matrix.cyber?.present
        ? `${matrix.cyber.event_count} event(s) · ${(matrix.cyber.event_types || []).join(', ') || '—'}`
        : 'No cyber sensor events',
    },
    {
      key:     'intelligence',
      label:   'Intelligence Report',
      present: matrix.intelligence?.present,
      detail: matrix.intelligence?.present
        ? `${matrix.intelligence.report_count} report(s) · IOC overlap: ${matrix.intelligence.ioc_overlap_pct ?? 0}%`
        : 'No intelligence corroboration',
    },
    {
      key:     'satellite',
      label:   'Satellite Telemetry',
      present: matrix.satellite?.present,
      detail: matrix.satellite?.present
        ? `${matrix.satellite.event_count} event(s) · max anomaly: ${((matrix.satellite.max_anomaly_score || 0) * 100).toFixed(0)}%`
        : 'No satellite anomaly',
    },
  ]

  return (
    <div className="evidence-matrix">
      <div className="evidence-matrix-title">Evidence Matrix</div>

      {/* Source cards */}
      <div className="evidence-sources">
        {sources.map(s => (
          <div key={s.key} className={`evidence-source-card ${s.present ? 'present' : 'absent'}`}>
            <div className="source-header">
              <div className={`source-check ${s.present ? 'present' : 'absent'}`}>
                {s.present ? '✓' : '–'}
              </div>
              <div className="source-name">{s.label}</div>
            </div>
            <div className="source-detail">{s.detail}</div>
          </div>
        ))}
      </div>

      {/* Metrics row */}
      <div className="evidence-metrics">
        <div className="evidence-metric">
          <div className="evidence-metric-value" style={{ color: corrColor }}>
            {sourcesPresent ?? matrix.sources_corroborating ?? 0}/3
          </div>
          <div className="evidence-metric-label">Sources</div>
        </div>

        <div className="corr-bar-wrap">
          <div className="corr-bar-label">
            <span>Cross-source correlation</span>
            <span style={{ color: corrColor }}>{corrPct.toFixed(0)}%</span>
          </div>
          <div className="corr-bar-track">
            <div
              className="corr-bar-fill"
              style={{ width: `${corrPct}%`, background: corrColor }}
            />
          </div>
        </div>

        <div className="evidence-metric">
          <div className="evidence-metric-value" style={{ color: fpMeta.color, fontSize: 13 }}>
            {fpMeta.label}
          </div>
          <div className="evidence-metric-label">FP likelihood {fp?.fp_score?.toFixed(0) ?? '—'}/100</div>
        </div>
      </div>

      {/* WHY WAS THIS PRIORITIZED? */}
      {fp?.reasons?.length > 0 && (
        <div className="why-prioritized">
          <div className="why-title">Why was this prioritized?</div>
          {fp.reasons.map((r, i) => (
            <div key={i} className="why-reason">
              <span className="why-check">✓</span>
              <span>{r}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
