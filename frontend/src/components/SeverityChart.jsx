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

  return (
    <div className="cyber-command-panel flex min-h-[16rem] flex-col p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <p className="cyber-label mb-1 text-cyan-300/80">Distribution</p>
          <h3 className="font-bold text-white">Findings by Severity</h3>
        </div>
        <div className="rounded-2xl border border-cyan-300/15 bg-cyan-300/5 px-3 py-2 text-center">
          <p className="text-[10px] font-black uppercase tracking-wider text-cyan-200/70">Total</p>
          <p className="text-xl font-black text-cyan-100">{results.total_findings}</p>
        </div>
      </div>

      {data.length === 0 ? (
        <div className="grid flex-1 place-items-center rounded-2xl border border-white/10 bg-white/[0.025] text-sm text-slate-500">
          No severity counts returned.
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={58}
              outerRadius={86}
              paddingAngle={4}
              dataKey="value"
              stroke="rgba(2, 6, 23, 0.9)"
              strokeWidth={3}
            >
              {data.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: 'rgba(2, 6, 23, 0.94)',
                border: '1px solid rgba(148, 163, 184, 0.2)',
                borderRadius: '14px',
                color: '#e2e8f0'
              }}
            />
            <Legend
              formatter={(value) => (
                <span style={{ color: '#94a3b8', fontSize: '12px' }}>{value}</span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
