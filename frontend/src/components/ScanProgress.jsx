import { useEffect, useState } from 'react'
import { getScanStatus } from '../api/client'
import { Activity, CheckCircle, Loader2, Radar, Shield, XCircle } from 'lucide-react'

const PHASES = [
  { label: 'Queued', threshold: 0 },
  { label: 'Analyze', threshold: 15 },
  { label: 'Score', threshold: 60 },
  { label: 'Persist', threshold: 85 },
  { label: 'Complete', threshold: 100 }
]

const SEVERITY_COUNTS = [
  { key: 'critical_count', label: 'Critical', className: 'text-red-300 border-red-300/20 bg-red-500/10' },
  { key: 'high_count', label: 'High', className: 'text-orange-300 border-orange-300/20 bg-orange-500/10' },
  { key: 'medium_count', label: 'Medium', className: 'text-yellow-300 border-yellow-300/20 bg-yellow-500/10' },
  { key: 'low_count', label: 'Low', className: 'text-green-300 border-green-300/20 bg-green-500/10' }
]

export default function ScanProgress({ scanId, onComplete }) {
  const [status, setStatus] = useState(null)

  useEffect(() => {
    if (!scanId) return

    const interval = setInterval(async () => {
      try {
        const res = await getScanStatus(scanId)
        const data = res.data
        setStatus(data)

        if (data.status === 'completed' || data.status === 'failed') {
          clearInterval(interval)
          if (onComplete) onComplete(data)
        }
      } catch (err) {
        console.error('Status poll failed:', err)
      }
    }, 3000) // poll every 3 seconds

    return () => clearInterval(interval)
  }, [scanId, onComplete])

  if (!status) return (
    <div className="scan-console p-6">
      <div className="flex items-center gap-4">
        <div className="relative grid h-14 w-14 place-items-center rounded-2xl border border-cyan-300/20 bg-cyan-300/10 text-cyan-200 shadow-glow-cyan">
          <Radar className="animate-spin-slow" size={28} />
          <span className="absolute inset-0 rounded-2xl border border-cyan-300/30 animate-ping" />
        </div>
        <div>
          <p className="cyber-label mb-1 text-cyan-300/80">Pipeline handshake</p>
          <div className="flex items-center gap-2 text-white">
            <Loader2 className="animate-spin text-cyan-300" size={18} />
            <span className="font-semibold">Initializing scan engine...</span>
          </div>
          <p className="mt-1 text-sm text-slate-500">Waiting for the first status packet from the backend.</p>
        </div>
      </div>
    </div>
  )

  const isComplete = status.status === 'completed'
  const isFailed = status.status === 'failed'
  const progress = Number(status.progress || 0)

  return (
    <div className={`scan-console overflow-hidden ${isFailed ? 'is-failed' : ''} ${isComplete ? 'is-complete' : ''}`}>
      <div className="scanner-beam" />

      <div className="relative z-10 p-5 sm:p-6">
        <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center">
          <div className={`grid h-14 w-14 place-items-center rounded-2xl border ${isComplete ? 'border-green-300/35 bg-green-400/15 text-green-200' : isFailed ? 'border-red-300/35 bg-red-400/15 text-red-200' : 'border-cyan-300/25 bg-cyan-300/10 text-cyan-200 shadow-glow-cyan'}`}>
            {isComplete ? (
              <CheckCircle size={29} />
            ) : isFailed ? (
              <XCircle size={29} />
            ) : (
              <Shield className="animate-pulse" size={29} />
            )}
          </div>

          <div className="min-w-0 flex-1">
            <p className="cyber-label mb-1 text-cyan-300/80">Live scan telemetry</p>
            <h3 className="text-2xl font-black text-white">
              {isComplete ? 'Scan Complete' : isFailed ? 'Scan Failed' : 'Scanning target'}
            </h3>
            <div className="mt-3 rounded-2xl border border-white/10 bg-black/30 px-4 py-3 font-mono text-sm text-slate-300">
              <span className="text-cyan-300">&gt;</span> {status.current_stage || 'Awaiting stage update'}
              {!isComplete && !isFailed && <span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-cyan-300/70" />}
            </div>
          </div>

          <div className="rounded-2xl border border-cyan-300/15 bg-cyan-300/5 px-5 py-4 text-center shadow-glow-cyan">
            <p className="text-[10px] font-black uppercase tracking-[0.22em] text-cyan-200/70">Progress</p>
            <p className="text-4xl font-black text-cyan-100">{progress}%</p>
          </div>
        </div>

        <div className="mb-5 h-3 overflow-hidden rounded-full border border-white/10 bg-slate-950/80">
          <div
            className={`h-full rounded-full transition-all duration-700 ${isFailed ? 'bg-gradient-to-r from-red-500 to-red-300' : 'progress-stripes bg-gradient-to-r from-cyan-400 via-blue-400 to-violet-400'}`}
            style={{ width: `${progress}%` }}
          />
        </div>

        <div className="mb-5 grid grid-cols-5 gap-2">
          {PHASES.map(phase => {
            const active = progress >= phase.threshold || isComplete
            return (
              <div key={phase.label} className={`rounded-xl border px-2 py-2 text-center text-[11px] font-bold uppercase tracking-wider ${active ? 'border-cyan-300/25 bg-cyan-300/10 text-cyan-100' : 'border-white/5 bg-white/[0.025] text-slate-600'}`}>
                {phase.label}
              </div>
            )
          })}
        </div>

        {status.total_findings > 0 ? (
          <div>
            <div className="mb-3 flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-500">
              <Activity size={14} className="text-cyan-300" />
              Live findings
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {SEVERITY_COUNTS.map(item => (
                <div key={item.key} className={`rounded-2xl border px-3 py-3 ${item.className}`}>
                  <p className="text-2xl font-black">{status[item.key]}</p>
                  <p className="text-xs font-bold uppercase tracking-wider opacity-80">{item.label}</p>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="rounded-2xl border border-white/5 bg-white/[0.025] px-4 py-3 text-sm text-slate-500">
            No findings reported yet. Severity counters appear here as soon as the pipeline has live counts.
          </div>
        )}

        {isFailed && status.error && (
          <div className="mt-5 rounded-2xl border border-red-300/25 bg-red-500/10 px-4 py-3 text-sm leading-6 text-red-100">
            {status.error}
          </div>
        )}
      </div>
    </div>
  )
}
