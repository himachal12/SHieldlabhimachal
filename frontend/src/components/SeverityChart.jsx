import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const COLORS = {
  CRITICAL: '#f43f5e',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
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
    <div className="h-full rounded-2xl border border-slate-700/80 bg-gradient-to-br from-slate-900/95 to-slate-950/70 p-5 shadow-panel">
      <div className="mb-4">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
          Analytics
        </p>
        <h3 className="mt-1 font-semibold text-white">Findings by Severity</h3>
      </div>

      <ResponsiveContainer width="100%" height={240}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={58}
            outerRadius={90}
            paddingAngle={3}
            dataKey="value"
            stroke="rgba(15, 23, 42, 0.9)"
            strokeWidth={2}
          >
            {data.map((entry, index) => (
              <Cell key={index} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: '#0f172a',
              border: '1px solid rgba(148, 163, 184, 0.28)',
              borderRadius: '12px',
              color: '#e2e8f0',
              boxShadow: '0 18px 50px -28px rgba(0, 0, 0, 0.75)',
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
