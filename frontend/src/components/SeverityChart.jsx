import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
}

export default function SeverityChart({ results }) {
  const data = [
    { name: 'Critical', value: results.critical_count, color: COLORS.CRITICAL },
    { name: 'High',     value: results.high_count,     color: COLORS.HIGH },
    { name: 'Medium',   value: results.medium_count,   color: COLORS.MEDIUM },
    { name: 'Low',      value: results.low_count,      color: COLORS.LOW },
  ].filter(d => d.value > 0)

  if (data.length === 0) return null

  return (
    <div className="bg-surface border border-slate-700 rounded-xl p-5">
      <h3 className="font-semibold text-white mb-4">Findings by Severity</h3>
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
          >
            {data.map((entry, index) => (
              <Cell key={index} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#e2e8f0'
            }}
          />
          <Legend
            formatter={(value) => (
              <span style={{ color: '#94a3b8', fontSize: '13px' }}>{value}</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}