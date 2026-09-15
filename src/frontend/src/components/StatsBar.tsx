import React from 'react'

type Filter = 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

interface RiskDistribution {
  critical: number
  high: number
  medium: number
  low: number
}

interface DashboardStats {
  total_alerts: number
  unacknowledged: number
  risk_distribution: RiskDistribution
  correlation_groups: number
}

interface StatsBarProps {
  stats: DashboardStats
  onFilterClick: (filter: Filter) => void
  onCorrelationClick: () => void
}

interface StatCardProps {
  label: string
  value: number | string
  color: string
  subtitle?: string
  icon?: string
  onClick: () => void
}

function StatCard({
  label,
  value,
  color,
  subtitle,
  icon,
  onClick,
}: StatCardProps) {
  const [hovered, setHovered] = React.useState(false)

  return (
    <button
      type="button"
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        flex: '1 1 145px',
        minWidth: 145,
        background: hovered
          ? 'var(--surface-2, #161b22)'
          : 'var(--surface, #0d1117)',
        border: `1px solid ${
          hovered ? color : `${color}44`
        }`,
        borderTop: `3px solid ${color}`,
        borderRadius: 8,
        padding: '16px 18px',
        textAlign: 'left',
        cursor: 'pointer',
        transition:
          'transform 0.15s ease, border-color 0.15s ease, background 0.15s ease, box-shadow 0.15s ease',
        transform: hovered ? 'translateY(-2px)' : 'translateY(0)',
        boxShadow: hovered
          ? `0 4px 16px ${color}18`
          : 'none',
        color: 'inherit',
        fontFamily: 'inherit',
        outline: 'none',
      }}
      aria-label={`View ${label.replace(/[🔴🟠🟡🟢🔗]/g, '').trim()}`}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 8,
        }}
      >
        <div
          style={{
            fontSize: 28,
            fontWeight: 700,
            color,
            lineHeight: 1,
          }}
        >
          {value}
        </div>

        {icon && (
          <div
            style={{
              fontSize: 20,
              opacity: hovered ? 1 : 0.75,
            }}
          >
            {icon}
          </div>
        )}
      </div>

      <div
        style={{
          fontSize: 12,
          fontWeight: 600,
          color: 'var(--text, #e6edf3)',
          lineHeight: 1.3,
        }}
      >
        {label}
      </div>

      {subtitle && (
        <div
          style={{
            fontSize: 11,
            color: 'var(--muted, #8b949e)',
            marginTop: 5,
            lineHeight: 1.3,
          }}
        >
          {subtitle}
        </div>
      )}

      <div
        style={{
          fontSize: 9,
          color,
          marginTop: 9,
          opacity: hovered ? 1 : 0,
          transition: 'opacity 0.15s ease',
          fontWeight: 600,
        }}
      >
        CLICK TO VIEW →
      </div>
    </button>
  )
}

export function StatsBar({
  stats,
  onFilterClick,
  onCorrelationClick,
}: StatsBarProps) {
  const {
    total_alerts,
    unacknowledged,
    risk_distribution,
    correlation_groups,
  } = stats

  return (
    <div
      style={{
        display: 'flex',
        gap: 12,
        flexWrap: 'wrap',
        marginBottom: 24,
        width: '100%',
      }}
    >
      <StatCard
        label="Total Alerts"
        value={total_alerts}
        color="#58a6ff"
        icon="📊"
        subtitle={`${unacknowledged} unacknowledged`}
        onClick={() => onFilterClick('ALL')}
      />

      <StatCard
        label="🔴 Critical"
        value={risk_distribution.critical}
        color="#f85149"
        icon="🚨"
        subtitle="Investigate immediately"
        onClick={() => onFilterClick('CRITICAL')}
      />

      <StatCard
        label="🟠 High"
        value={risk_distribution.high}
        color="#e3a346"
        icon="⚠️"
        subtitle="Investigate soon"
        onClick={() => onFilterClick('HIGH')}
      />

      <StatCard
        label="🟡 Medium"
        value={risk_distribution.medium}
        color="#d29922"
        icon="◉"
        subtitle="Monitor / investigate"
        onClick={() => onFilterClick('MEDIUM')}
      />

      <StatCard
        label="🟢 Low"
        value={risk_distribution.low}
        color="#3fb950"
        icon="✓"
        subtitle="Low priority"
        onClick={() => onFilterClick('LOW')}
      />

      <StatCard
        label="🔗 Correlated Groups"
        value={correlation_groups}
        color="#d2a8ff"
        icon="🔗"
        subtitle="Attack stories"
        onClick={onCorrelationClick}
      />
    </div>
  )
}