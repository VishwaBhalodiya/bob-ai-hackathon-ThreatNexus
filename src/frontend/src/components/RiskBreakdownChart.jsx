import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
  ResponsiveContainer, LabelList,
} from 'recharts'

const COLORS = {
  'IOC Reputation':      '#ef4444',
  'Asset Criticality':   '#f97316',
  'Threat Severity':     '#eab308',
  'Behavior Suspicion':  '#3b82f6',
  'Correlation Score':   '#a855f7',
}

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  const { name, value } = payload[0]
  return (
    <div style={{
      background: '#1a2235', border: '1px solid #1e2d45',
      borderRadius: 6, padding: '8px 12px', fontSize: 12,
    }}>
      <div style={{ color: '#94a3b8', marginBottom: 2 }}>{name}</div>
      <div style={{ color: '#e2e8f0', fontWeight: 700 }}>{value.toFixed(1)} / 100</div>
    </div>
  )
}

export default function RiskBreakdownChart({ breakdown }) {
  if (!breakdown) return null

  const data = [
    { name: 'IOC Reputation',     value: breakdown.ioc_reputation      ?? 0 },
    { name: 'Asset Criticality',  value: breakdown.asset_criticality_score ?? 0 },
    { name: 'Threat Severity',    value: breakdown.threat_severity_score   ?? 0 },
    { name: 'Behavior Suspicion', value: breakdown.behavioral_suspicion    ?? 0 },
    { name: 'Correlation Score',  value: breakdown.correlation_score       ?? 0 },
  ]

  return (
    <div style={{ width: '100%', height: 220 }}>
      <ResponsiveContainer>
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 4, right: 50, left: 130, bottom: 4 }}
          barSize={14}
        >
          <XAxis
            type="number"
            domain={[0, 100]}
            tick={{ fill: '#64748b', fontSize: 11 }}
            axisLine={{ stroke: '#1e2d45' }}
            tickLine={false}
          />
          <YAxis
            type="category"
            dataKey="name"
            width={124}
            tick={{ fill: '#94a3b8', fontSize: 12 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
          <Bar dataKey="value" radius={[0, 4, 4, 0]}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name] || '#3b82f6'} />
            ))}
            <LabelList
              dataKey="value"
              position="right"
              formatter={(v) => v.toFixed(0)}
              style={{ fill: '#94a3b8', fontSize: 11 }}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
