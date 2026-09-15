// RiskChart — clickable donut-style risk distribution using Recharts

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'

import type { RiskDistribution } from '../types'

type Filter = 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

interface Props {
  dist: RiskDistribution
  onFilterClick: (filter: Filter) => void
}

const ENTRIES = [
  {
    key: 'critical' as const,
    label: 'Critical',
    color: '#f85149',
    filter: 'CRITICAL' as Filter,
  },
  {
    key: 'high' as const,
    label: 'High',
    color: '#e3a346',
    filter: 'HIGH' as Filter,
  },
  {
    key: 'medium' as const,
    label: 'Medium',
    color: '#d29922',
    filter: 'MEDIUM' as Filter,
  },
  {
    key: 'low' as const,
    label: 'Low',
    color: '#3fb950',
    filter: 'LOW' as Filter,
  },
]

export function RiskChart({ dist, onFilterClick }: Props) {
  const data = ENTRIES
    .map(entry => ({
      name: entry.label,
      value: dist[entry.key],
      color: entry.color,
      filter: entry.filter,
    }))
    .filter(entry => entry.value > 0)

  if (data.length === 0) {
    return (
      <div
        style={{
          textAlign: 'center',
          color: 'var(--muted)',
          padding: '40px 0',
          fontSize: 13,
        }}
      >
        No alerts to display
      </div>
    )
  }

  const handleSegmentClick = (entry: {
    name?: string
    filter?: Filter
  }) => {
    if (entry.filter) {
      onFilterClick(entry.filter)
    }
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>

        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={55}
          outerRadius={85}
          paddingAngle={3}
          dataKey="value"
          nameKey="name"
          isAnimationActive={true}
          onClick={(entry) =>
            handleSegmentClick(entry as {
              name?: string
              filter?: Filter
            })
          }
          style={{
            cursor: 'pointer',
          }}
        >
          {data.map((entry, i) => (
            <Cell
              key={`cell-${i}`}
              fill={entry.color}
              style={{
                cursor: 'pointer',
              }}
            />
          ))}
        </Pie>

        <Tooltip
          contentStyle={{
            background: 'var(--surface-2)',
            border: '1px solid var(--border)',
            borderRadius: 4,
            color: 'var(--text)',
            fontSize: 12,
          }}
          formatter={(value, name) => [
            value,
            name,
          ]}
        />

        <Legend
          iconType="circle"
          iconSize={8}
          formatter={(value) => (
            <span
              style={{
                fontSize: 12,
                color: 'var(--text)',
                cursor: 'pointer',
              }}
            >
              {value}
            </span>
          )}
        />

      </PieChart>
    </ResponsiveContainer>
  )
}