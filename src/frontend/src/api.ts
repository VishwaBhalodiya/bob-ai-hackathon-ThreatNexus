// API client — thin wrapper around fetch

const BASE = '/api'

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`)
  if (!res.ok) throw new Error(`API ${res.status}: ${path}`)
  return res.json()
}

async function patch<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { method: 'PATCH' })
  if (!res.ok) throw new Error(`API ${res.status}: ${path}`)
  return res.json()
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`API ${res.status}: ${path}`)
  return res.json()
}

import type { Alert, DashboardStats, ThreatIntel } from './types'

export const api = {
  getDashboard: () => get<DashboardStats>('/dashboard/stats'),
  getAlerts: (params?: { risk_level?: string; acknowledged?: boolean }) => {
    const qs = new URLSearchParams()
    if (params?.risk_level) qs.set('risk_level', params.risk_level)
    if (params?.acknowledged !== undefined) qs.set('acknowledged', String(params.acknowledged))
    const q = qs.toString()
    return get<Alert[]>(`/alerts/${q ? '?' + q : ''}`)
  },
  getAlert: (id: number) => get<Alert>(`/alerts/${id}`),
  acknowledgeAlert: (id: number) => patch<Alert>(`/alerts/${id}/acknowledge`),
  markFalsePositive: (id: number) => patch<Alert>(`/alerts/${id}/false-positive`),
  ingestAlert: (payload: Record<string, unknown>) => post<Alert>('/alerts/ingest', payload),
  getThreats: () => get<ThreatIntel[]>('/threats/?min_reputation=50'),
  getCorrelations: () => get<unknown[]>('/dashboard/correlations'),
}
