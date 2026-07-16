import { useParams, useNavigate } from 'react-router-dom'
import { RadioTower, Shield } from 'lucide-react'
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
    <main className="cyber-screen min-h-screen overflow-hidden px-4 py-10 text-slate-100 sm:px-6 lg:px-8">
      <div className="cyber-orb cyber-orb-cyan" />
      <div className="cyber-orb cyber-orb-violet" />
      <div className="cyber-grid" />
      <div className="cyber-scanline" />

      <section className="relative z-10 mx-auto flex min-h-[calc(100vh-5rem)] w-full max-w-3xl flex-col justify-center">
        <div className="mb-8 flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <div className="mb-4 flex items-center gap-3">
              <div className="grid h-11 w-11 place-items-center rounded-2xl border border-cyan-300/20 bg-cyan-300/10 shadow-glow-cyan">
                <Shield className="text-cyan-200" size={25} />
              </div>
              <div>
                <h1 className="text-2xl font-black text-white">ShieldLabs</h1>
                <p className="text-xs font-bold uppercase tracking-[0.22em] text-cyan-300/70">Scan control</p>
              </div>
            </div>

            <h2 className="bg-gradient-to-r from-white via-cyan-100 to-violet-200 bg-clip-text text-3xl font-black tracking-tight text-transparent sm:text-5xl">
              Scan in Progress
            </h2>
            <p className="mt-3 max-w-xl text-sm leading-6 text-slate-400">
              Real-time telemetry is polling the backend every few seconds. The page will advance automatically after a successful scan.
            </p>
          </div>

          <div className="rounded-2xl border border-cyan-300/15 bg-cyan-300/5 px-4 py-3 font-mono text-xs text-cyan-100 shadow-glow-cyan">
            <div className="mb-1 flex items-center gap-2 font-sans text-[10px] font-black uppercase tracking-[0.2em] text-cyan-300/70">
              <RadioTower size={13} />
              Scan ID
            </div>
            <span className="break-all">{scanId}</span>
          </div>
        </div>

        <ScanProgress scanId={scanId} onComplete={handleComplete} />

        <p className="mt-6 text-center text-xs leading-6 text-slate-600">
          This page auto-advances when the scan completes. You can leave and come back using the scan ID. -kaalvex
        </p>
      </section>
    </main>
  )
}
