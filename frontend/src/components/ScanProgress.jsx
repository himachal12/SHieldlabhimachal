import { useEffect, useState } from 'react'
import { getScanStatus } from '../api/client'
import { Shield, Loader2, CheckCircle, XCircle } from 'lucide-react'

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
  }, [scanId])

  if (!status) return (
    <div className="flex items-center gap-3 text-slate-400">
      <Loader2 className="animate-spin" size={20} />
      <span>Initializing scan...</span>
    </div>
  )

  const isComplete = status.status === 'completed'
  const isFailed = status.status === 'failed'

  return (
    <div className="bg-surface rounded-xl p-6 border border-slate-700">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        {isComplete ? (
          <CheckCircle className="text-green-400" size={24} />
        ) : isFailed ? (
          <XCircle className="text-red-400" size={24} />
        ) : (
          <Shield className="text-accent animate-pulse" size={24} />
        )}
        <div>
          <h3 className="font-semibold text-white">
            {isComplete ? 'Scan Complete' : isFailed ? 'Scan Failed' : 'Scanning...'}
          </h3>
          <p className="text-sm text-slate-400">{status.current_stage}</p>
        </div>
        <span className="ml-auto text-2xl font-bold text-accent">
          {status.progress}%
        </span>
      </div>

      {/* Progress bar */}
      <div className="w-full bg-slate-700 rounded-full h-2 mb-4">
        <div
          className="h-2 rounded-full transition-all duration-500"
          style={{
            width: `${status.progress}%`,
            backgroundColor: isFailed ? '#ef4444' : '#38bdf8'
          }}
        />
      </div>

      {/* Findings counter (shows live as scan progresses) */}
      {status.total_findings > 0 && (
        <div className="flex gap-4 text-sm">
          <span className="text-red-400">
            {status.critical_count} Critical
          </span>
          <span className="text-orange-400">
            {status.high_count} High
          </span>
          <span className="text-yellow-400">
            {status.medium_count} Medium
          </span>
          <span className="text-green-400">
            {status.low_count} Low
          </span>
        </div>
      )}
    </div>
  )
}