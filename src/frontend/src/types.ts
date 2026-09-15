// Shared TypeScript types matching the backend schemas

export interface Asset {
  id: number
  hostname: string
  ip_address: string
  asset_type: string | null
  criticality: number
  owner: string | null
  department: string | null
  tags: string[]
  created_at: string
}

export interface IOCItem {
  type: string
  value: string
}

export interface Alert {
  id: number
  title: string
  description: string | null
  source_system: string | null
  source_severity: string | null
  iocs: IOCItem[]
  asset: Asset | null
  risk_score: number
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'FALSE_POSITIVE'
  ai_explanation: string | null
  investigation_steps: string[]
  correlation_group_id: string | null
  is_acknowledged: boolean
  is_false_positive: boolean
  raw_log: string | null
  timestamp: string
  updated_at: string
}

export interface ThreatIntel {
  id: number
  ioc_type: string
  ioc_value: string
  reputation_score: number
  threat_category: string | null
  source: string | null
  tags: string[]
  first_seen: string | null
  last_seen: string | null
  created_at: string
}

export interface RiskDistribution {
  critical: number
  high: number
  medium: number
  low: number
}

export interface DashboardStats {
  total_alerts: number
  unacknowledged: number
  risk_distribution: RiskDistribution
  top_threats: ThreatIntel[]
  recent_critical: Alert[]
  correlation_groups: number
}
