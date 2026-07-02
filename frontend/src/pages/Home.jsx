import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield,  Globe, Layers, AlertTriangle } from 'lucide-react'
import { startCodeScan, startWebScan, startCombinedScan } from '../api/client'
import ActiveScanConsent from '../components/ActiveScanConsent'

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

  // Active scan state
  const [activeEnabled, setActiveEnabled] = useState(false)
  const [consentGiven, setConsentGiven] = useState(false)
  const [activeUrls, setActiveUrls] = useState([])

  const showActiveToggle = scanType === 'web' || scanType === 'combined'

  const handleScan = async () => {
    setError('')

    // Validation
    if ((scanType === 'code' || scanType === 'combined') && !repoUrl) {
      setError('Please enter a GitHub repository URL')
      return
    }
    if ((scanType === 'web' || scanType === 'combined') && !domain) {
      setError('Please enter a domain to scan')
      return
    }
    if (activeEnabled && !consentGiven) {
      setError('You must confirm consent before running an active scan')
      return
    }
    if (activeEnabled && consentGiven && activeUrls.length === 0) {
      setError('Active scan requires at least one URL with query parameters')
      return
    }

    const scanMode = activeEnabled && consentGiven ? 'active' : 'passive'

    setLoading(true)
    try {
      let response

      if (scanType === 'code') {
        response = await startCodeScan(repoUrl)
      } else if (scanType === 'web') {
        response = await startWebScan(
          domain,
          scanMode,
          consentGiven,
          activeUrls
        )
      } else {
        // Combined — pass active scan params too
        response = await startCombinedScan(repoUrl, domain, scanMode, consentGiven)
      }

      navigate(`/scan/${response.data.scan_id}`)

    } catch (err) {
      setError(
        err.response?.data?.detail ||
        'Failed to start scan. Is the backend running on port 8000?'
      )
    } finally {
      setLoading(false)
    }
  }

  // Reset active scan state when switching modes
  const handleModeChange = (mode) => {
    setScanType(mode)
    setActiveEnabled(false)
    setConsentGiven(false)
    setActiveUrls([])
    setError('')
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
            onClick={() => handleModeChange(mode.id)}
            className={`
              relative p-4 rounded-xl border-2 text-left transition-all bg-surface
              ${mode.color}
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
            <p className={`font-semibold text-sm
                          ${scanType === mode.id ? 'text-white' : 'text-slate-300'}`}>
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

        {/* Active scan toggle (only for web/combined) */}
        {showActiveToggle && (
          <ActiveScanConsent
            enabled={activeEnabled}
            onToggle={() => {
              setActiveEnabled(!activeEnabled)
              if (activeEnabled) {
                setConsentGiven(false)
                setActiveUrls([])
              }
            }}
            consentGiven={consentGiven}
            onConsentChange={setConsentGiven}
            activeUrls={activeUrls}
            onUrlsChange={setActiveUrls}
          />
        )}

        {/* Error */}
        {error && (
          <div className="flex items-center gap-2 text-red-400 text-sm
                          bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3">
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
              {activeEnabled && consentGiven ? '⚡ Start Active Scan' : 'Start Scan'}
            </>
          )}
        </button>

        {/* Active scan mode badge */}
        {activeEnabled && consentGiven && (
          <p className="text-center text-xs text-orange-400">
            ⚠️ Active mode: real payloads will be sent to {domain || 'target'}
          </p>
        )}
      </div>

      <p className="text-slate-600 text-xs mt-8 text-center">
        100% free & open source · Designed for Nepal's startup ecosystem - By VoidVex
      </p>
    </div>
  )
}