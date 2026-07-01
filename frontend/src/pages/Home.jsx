import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield,  Globe, Layers, AlertTriangle } from 'lucide-react'
import { startCodeScan, startWebScan, startCombinedScan } from '../api/client'

const SCAN_MODES = [
  {
    id: 'code',
    label: 'Code Scan',
    icon: Shield,
    description: 'Scan a GitHub repository for 13+ vulnerability types',
    color: 'border-blue-500/40 hover:border-blue-500'
  },
  {
    id: 'web',
    label: 'Web Scan',
    icon: Globe,
    description: 'Scan a live domain for open ports, misconfigs, exposed files',
    color: 'border-cyan-500/40 hover:border-cyan-500'
  },
  {
    id: 'combined',
    label: 'Full Scan',
    icon: Layers,
    description: 'Code + Web + AI attack chain analysis',
    color: 'border-purple-500/40 hover:border-purple-500',
    badge: 'RECOMMENDED'
  }
]

export default function Home() {
  const navigate = useNavigate()
  const [scanType, setScanType] = useState('code')
  const [repoUrl, setRepoUrl] = useState('')
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleScan = async () => {
    setError('')

    // Validation
    if (scanType === 'code' && !repoUrl) {
      setError('Please enter a GitHub repository URL')
      return
    }
    if (scanType === 'web' && !domain) {
      setError('Please enter a domain to scan')
      return
    }
    if (scanType === 'combined' && (!repoUrl || !domain)) {
      setError('Combined scan requires both a GitHub URL and a domain')
      return
    }

    setLoading(true)
    try {
      let response
      if (scanType === 'code') {
        response = await startCodeScan(repoUrl)
      } else if (scanType === 'web') {
        response = await startWebScan(domain)
      } else {
        response = await startCombinedScan(repoUrl, domain)
      }

      const { scan_id } = response.data
      navigate(`/scan/${scan_id}`)

    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to start scan. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4 py-16">

      {/* Logo + title */}
      <div className="flex items-center gap-3 mb-3">
        <Shield className="text-accent" size={40} />
        <h1 className="text-4xl font-bold text-white">ShieldLabs</h1>
      </div>
      <p className="text-slate-400 text-center mb-10 max-w-md">
        AI-powered security scanning & vulnerability remediation for Nepal startups
      </p>

      {/* Scan mode selector */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 w-full max-w-2xl mb-6">
        {SCAN_MODES.map((mode) => (
          <button
            key={mode.id}
            onClick={() => setScanType(mode.id)}
            className={`
              relative p-4 rounded-xl border-2 text-left transition-all
              bg-surface ${mode.color}
              ${scanType === mode.id ? mode.color.replace('hover:', '') : ''}
            `}
          >
            {mode.badge && (
              <span className="absolute -top-2 -right-2 bg-purple-500 text-white
                             text-xs px-2 py-0.5 rounded-full font-bold">
                {mode.badge}
              </span>
            )}
            <mode.icon
              size={20}
              className={`mb-2 ${scanType === mode.id ? 'text-accent' : 'text-slate-400'}`}
            />
            <p className={`font-semibold text-sm ${scanType === mode.id ? 'text-white' : 'text-slate-300'}`}>
              {mode.label}
            </p>
            <p className="text-xs text-slate-500 mt-1">{mode.description}</p>
          </button>
        ))}
      </div>

      {/* Input fields */}
      <div className="w-full max-w-2xl space-y-3">
        {(scanType === 'code' || scanType === 'combined') && (
          <input
            type="url"
            placeholder="https://github.com/username/repository"
            value={repoUrl}
            onChange={e => setRepoUrl(e.target.value)}
            className="w-full bg-surface border border-slate-600 rounded-xl px-4 py-3
                       text-white placeholder-slate-500 focus:outline-none
                       focus:border-accent transition-colors"
          />
        )}

        {(scanType === 'web' || scanType === 'combined') && (
          <input
            type="text"
            placeholder="example.com  (no https://)"
            value={domain}
            onChange={e => setDomain(e.target.value)}
            className="w-full bg-surface border border-slate-600 rounded-xl px-4 py-3
                       text-white placeholder-slate-500 focus:outline-none
                       focus:border-accent transition-colors"
          />
        )}

        {/* Error */}
        {error && (
          <div className="flex items-center gap-2 text-red-400 text-sm bg-red-500/10
                          border border-red-500/30 rounded-lg px-4 py-3">
            <AlertTriangle size={16} />
            {error}
          </div>
        )}

        {/* Submit */}
        <button
          onClick={handleScan}
          disabled={loading}
          className="w-full bg-accent text-primary font-bold py-3 rounded-xl
                     hover:bg-sky-400 disabled:opacity-50 disabled:cursor-not-allowed
                     transition-colors flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <div className="w-4 h-4 border-2 border-primary/50 border-t-primary
                              rounded-full animate-spin" />
              Starting scan...
            </>
          ) : (
            <>
              <Shield size={18} />
              Start Scan
            </>
          )}
        </button>
      </div>

      {/* Footer note */}
      <p className="text-slate-600 text-xs mt-8 text-center">
        Designed for Nepal's startup ecosystem and Tech community.
      </p>
    </div>
  )
}