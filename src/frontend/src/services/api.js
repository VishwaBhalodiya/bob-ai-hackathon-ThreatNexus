const BASE = 'http://localhost:8000'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, options)
  if (!res.ok) {
    let detail = `${res.status}`
    try { detail = (await res.json()).detail || detail } catch { /* not JSON */ }
    throw new Error(`API ${path} → ${detail}`)
  }
  return res.json()
}

const json = (method, body) => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export const api = {
  // ── Read ────────────────────────────────────────────────────────────────
  getDashboard:    ()          => request('/api/dashboard'),
  getAlerts:       (params={}) => request(`/api/alerts${qs(params)}`),
  getAlert:        (id)        => request(`/api/alerts/${id}`),
  getIOCs:         ()          => request('/api/iocs'),
  getBrief:        (params={}) => request(`/api/brief${qs(params)}`),
  getAttackChains: (params={}) => request(`/api/attack-chains${qs(params)}`),
  getMitreCoverage:(params={}) => request(`/api/mitre/coverage${qs(params)}`),
  getIngestFormats:()          => request('/api/ingest/formats'),
  getIngestSamples:()          => request('/api/ingest/samples'),
  getAiStatus:     ()          => request('/api/ai/status'),
  getAssets:       ()          => request('/api/assets'),
  lookupIoc:       (value)     => request(`/api/iocs/lookup/${encodeURIComponent(value)}`),

  // ── Write ───────────────────────────────────────────────────────────────
  ingest:       (payload, format='auto', source=null) =>
    request('/api/ingest', json('POST', { payload, format, source })),
  rescore:      ()                  => request('/api/alerts/rescore', { method: 'POST' }),
  analyze:      (body)              => request('/api/analyze', json('POST', body)),
  extractIocs:  (alertId)           => request(`/api/alerts/${alertId}/extract-iocs`, { method: 'POST' }),
  markFeedback: (alertId, feedback) => request(`/api/alerts/${alertId}/feedback`, json('PATCH', { feedback })),
  setStatus:    (alertId, status)   => request(`/api/alerts/${alertId}/status`, json('PATCH', { status })),
  addIoc:       (body)              => request('/api/iocs', json('POST', body)),
  addAsset:     (body)              => request('/api/assets', json('POST', body)),
}

function qs(params) {
  const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '')
  if (!entries.length) return ''
  return '?' + entries.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')
}
