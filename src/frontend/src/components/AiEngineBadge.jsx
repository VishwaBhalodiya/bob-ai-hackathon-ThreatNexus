import { useEffect, useState } from 'react'
import { api } from '../services/api.js'
import './AiEngineBadge.css'

/**
 * Shows which engine is producing BLUF text right now — IBM Bob's inference
 * API, or the deterministic template fallback when Bob is not configured.
 * Polls /api/ai/status so the counters update as summaries are generated.
 */
export default function AiEngineBadge() {
  const [st, setSt] = useState(null)

  useEffect(() => {
    let alive = true
    const tick = () => api.getAiStatus().then(s => alive && setSt(s)).catch(() => alive && setSt(null))
    tick()
    const id = setInterval(tick, 15000)
    return () => { alive = false; clearInterval(id) }
  }, [])

  if (!st) return null
  const live = st.mode === 'bob'
  const title = live
    ? `IBM Bob · ${st.model || 'model'} · ${st.stats.bob_calls} calls, ${st.stats.bob_failures} fallbacks`
    : st.note
  return (
    <span className={`ai-badge${live ? ' ai-badge-live' : ''}`} title={title}>
      <span className="ai-badge-dot" />
      <span className="ai-badge-brand">IBM Bob</span>
      <span className="ai-badge-mode">{live ? (st.model || 'inference') : 'template mode'}</span>
    </span>
  )
}
