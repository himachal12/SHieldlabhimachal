import { useParams, useNavigate } from 'react-router-dom'
import { Shield } from 'lucide-react'
import ScanProgress from '../components/ScanProgress'

export default function ScanPage() {
  const { scanId } = useParams()
  const navigate = useNavigate()

  const handleComplete = (finalStatus) => {
    if (finalStatus.status === 'completed') {
      // Small delay so user can see the 100% complete state
      setTimeout(() => {
        navigate(`/results/${scanId}`)
      }, 1200)
    }
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4">
      <div className="w-full max-w-lg">
        <div className="flex items-center gap-3 mb-8">
          <Shield className="text-accent" size={28} />
          <h1 className="text-2xl font-bold text-white">ShieldLabs</h1>
        </div>

        <h2 className="text-xl font-semibold text-white mb-2">
          Scan in Progress
        </h2>
        <p className="text-slate-400 mb-6 text-sm">
          Scan ID: <span className="font-mono text-accent">{scanId}</span>
        </p>

        <ScanProgress scanId={scanId} onComplete={handleComplete} />

        <p className="text-slate-600 text-xs text-center mt-6">
          This page auto-advances when the scan completes.
          You can leave and come back using the scan ID. -kaalvex
        </p>
      </div>
    </div>
  )
}