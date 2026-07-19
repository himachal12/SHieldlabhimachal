import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  Check,
  Code2,
  Cpu,
  DatabaseZap,
  Fingerprint,
  Globe,
  Layers,
  LockKeyhole,
  RadioTower,
  Shield,
  Radar,
  Zap
} from 'lucide-react'
import { startCodeScan, startWebScan, startCombinedScan } from '../api/client'
import ActiveScanConsent from '../components/ActiveScanConsent'

const SCAN_MODES = [
  {
    id: 'code',
    label: 'Code Scan',
    eyebrow: 'Static analysis',
    icon: Code2,
    description: 'Scan a GitHub repository for vulnerable patterns, secrets, and remediation hints.',
    accent: 'cyan',
    chips: ['Secrets', 'SQLi', 'XSS']
  },
  {
    id: 'web',
    label: 'Web Scan',
    eyebrow: 'Surface recon',
    icon: Globe,
    description: 'Probe a live domain for ports, headers, SSL posture, and exposed files.',
    accent: 'teal',
    chips: ['Ports', 'SSL', 'Headers']
  },
  {
    id: 'combined',
    label: 'Full Scan',
    eyebrow: 'AI attack chain',
    icon: Layers,
    description: 'Combine code, web, CVSS reasoning, and cross-domain attack-chain analysis.',
    accent: 'violet',
    chips: ['Code', 'Web', 'Chains'],
    badge: 'RECOMMENDED'
  }
]

const FIELD_REQUIREMENTS = {
  repo: 'Repository URL ready',
  domain: 'Domain target ready',
  consent: 'Active-test consent confirmed',
  urls: 'Active payload URLs added'
}

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
  const needsRepo = scanType === 'code' || scanType === 'combined'
  const needsDomain = scanType === 'web' || scanType === 'combined'
  const requirements = [
    ...(needsRepo ? [{ label: FIELD_REQUIREMENTS.repo, met: Boolean(repoUrl.trim()) }] : []),
    ...(needsDomain ? [{ label: FIELD_REQUIREMENTS.domain, met: Boolean(domain.trim()) }] : []),
    ...(activeEnabled ? [
      { label: FIELD_REQUIREMENTS.consent, met: consentGiven },
      { label: FIELD_REQUIREMENTS.urls, met: activeUrls.length > 0 }
    ] : [])
  ]

  const handleScan = async () => {
    setError('')

    // Validation
    if (needsRepo && !repoUrl) {
      setError('Please enter a GitHub repository URL')
      return
    }
    if (needsDomain && !domain) {
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
        response = await startCombinedScan(
          repoUrl,
          domain,
          scanMode,
          consentGiven,
          activeUrls
        )
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
    <main className="cyber-screen min-h-screen overflow-hidden px-4 py-10 text-slate-100 sm:px-6 lg:px-8">
      <div className="cyber-orb cyber-orb-cyan" />
      <div className="cyber-orb cyber-orb-violet" />
      <div className="cyber-grid" />
      <div className="cyber-scanline" />

      <section className="relative z-10 mx-auto flex min-h-[calc(100vh-5rem)] w-full max-w-6xl flex-col items-center justify-center gap-8">
        <div className="max-w-3xl text-center">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-cyan-300/15 bg-cyan-300/5 px-4 py-2 text-xs font-bold uppercase tracking-[0.28em] text-cyan-200 shadow-glow-cyan backdrop-blur">
            <RadioTower size={14} className="animate-pulse" />
            AI security command center
          </div>

          <div className="mb-4 flex items-center justify-center gap-3">
            <div className="relative grid h-14 w-14 place-items-center rounded-2xl border border-cyan-300/20 bg-cyan-300/10 shadow-glow-cyan">
              <Shield className="text-cyan-200" size={32} />
              <span className="absolute inset-0 rounded-2xl border border-cyan-200/30 animate-ping" />
            </div>
            <h1 className="bg-gradient-to-r from-white via-cyan-100 to-violet-200 bg-clip-text text-4xl font-black tracking-tight text-transparent sm:text-6xl">
              ShieldLabs
            </h1>
          </div>

          <p className="mx-auto max-w-2xl text-base leading-7 text-slate-400 sm:text-lg">
            Launch code, web, and AI attack-chain scans from a dark cyber console built for fast vulnerability triage and remediation.
          </p>
        </div>

        <button
          onClick={() => navigate('/threat-radar')}
          className="group cyber-command-panel w-full max-w-5xl overflow-hidden p-5 text-left transition-all hover:-translate-y-1 hover:border-cyan-300/30 hover:shadow-glow-cyan sm:p-6"
        >
          <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-start gap-4">
              <div className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl border border-cyan-300/20 bg-cyan-300/10 text-cyan-200 shadow-glow-cyan">
                <Radar size={26} />
              </div>
              <div>
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <p className="cyber-label text-cyan-300/80">Global threat pulse</p>
                  <span className="rounded-full border border-rose-300/25 bg-rose-500/10 px-2.5 py-1 text-[10px] font-black tracking-widest text-rose-100">NEW</span>
                </div>
                <h2 className="text-2xl font-black text-white">Open Threat Radar</h2>
                <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
                  Monitor recent critical CVEs, read AI-assisted developer impact summaries, and decide what deserves immediate stack review.
                </p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2 text-xs lg:justify-end">
              {['NVD feed', 'CVSS', 'AI summaries', 'Critical CVEs'].map(item => (
                <span key={item} className="rounded-full border border-cyan-300/15 bg-cyan-300/5 px-3 py-1 font-semibold text-cyan-100/90">
                  {item}
                </span>
              ))}
            </div>
          </div>
        </button>

        <div className="cyber-command-panel w-full max-w-5xl p-5 sm:p-6 lg:p-8">
          <div className="mb-6 flex flex-col gap-4 border-b border-white/10 pb-6 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="cyber-label mb-2 text-cyan-300/80">Target acquisition</p>
              <h2 className="text-2xl font-bold text-white">Initialize security scan</h2>
              <p className="mt-2 text-sm text-slate-400">Choose a scan profile, add the target, and deploy the scanner pipeline.</p>
            </div>
            <div className="flex flex-wrap gap-2 text-xs">
              {['Passive-first', 'CVSS scoring', 'AI fixes'].map(item => (
                <span key={item} className="rounded-full border border-cyan-300/15 bg-cyan-300/5 px-3 py-1 font-semibold text-cyan-100/90">
                  {item}
                </span>
              ))}
            </div>
          </div>

          {/* Scan mode selector */}
          <div className="mb-6 grid grid-cols-1 gap-3 md:grid-cols-3">
            {SCAN_MODES.map((mode) => {
              const selected = scanType === mode.id
              return (
                <button
                  key={mode.id}
                  onClick={() => handleModeChange(mode.id)}
                  className={`scan-mode-card scan-mode-${mode.accent} ${selected ? 'is-selected' : ''}`}
                >
                  {mode.badge && (
                    <span className="absolute right-4 top-4 rounded-full border border-violet-300/30 bg-violet-400/15 px-2.5 py-1 text-[10px] font-black tracking-widest text-violet-100 shadow-[0_0_24px_rgba(139,92,246,0.22)]">
                      {mode.badge}
                    </span>
                  )}
                  <div className="mb-4 flex items-center gap-3">
                    <span className="scan-mode-icon">
                      <mode.icon size={20} />
                    </span>
                    <span className="text-[10px] font-black uppercase tracking-[0.24em] text-slate-500">
                      {mode.eyebrow}
                    </span>
                  </div>
                  <p className="text-left text-lg font-bold text-white">{mode.label}</p>
                  <p className="mt-2 text-left text-sm leading-6 text-slate-400">{mode.description}</p>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {mode.chips.map(chip => (
                      <span key={chip} className="rounded-full bg-white/[0.06] px-2.5 py-1 text-[11px] font-semibold text-slate-300">
                        {chip}
                      </span>
                    ))}
                  </div>
                </button>
              )
            })}
          </div>

          {/* Input fields */}
          <div className="grid gap-4 lg:grid-cols-[1fr_0.72fr]">
            <div className="space-y-4">
              {needsRepo && (
                <label className="block">
                  <span className="cyber-label mb-2 block">Repository target</span>
                  <div className="cyber-field-wrap">
                    <DatabaseZap size={18} className="text-cyan-300" />
                    <input
                      type="url"
                      placeholder="https://github.com/username/repository"
                      value={repoUrl}
                      onChange={e => setRepoUrl(e.target.value)}
                      className="cyber-field"
                    />
                  </div>
                </label>
              )}

              {needsDomain && (
                <label className="block">
                  <span className="cyber-label mb-2 block">Domain target</span>
                  <div className="cyber-field-wrap">
                    <Fingerprint size={18} className="text-teal-300" />
                    <input
                      type="text"
                      placeholder="example.com  (no https://)"
                      value={domain}
                      onChange={e => setDomain(e.target.value)}
                      className="cyber-field"
                    />
                  </div>
                </label>
              )}

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
            </div>

            <aside className="rounded-2xl border border-white/10 bg-black/20 p-4 shadow-inner shadow-cyan-950/20 backdrop-blur">
              <div className="mb-4 flex items-center gap-2 text-sm font-bold text-white">
                <Cpu size={17} className="text-cyan-300" />
                Scan readiness
              </div>
              <div className="space-y-3">
                {requirements.map(item => (
                  <div key={item.label} className="flex items-center gap-3 rounded-xl border border-white/5 bg-white/[0.035] px-3 py-2.5">
                    <span className={`grid h-5 w-5 place-items-center rounded-full border ${item.met ? 'border-green-300/40 bg-green-400/15 text-green-300' : 'border-slate-500/40 bg-slate-700/30 text-slate-500'}`}>
                      {item.met ? <Check size={12} /> : <LockKeyhole size={11} />}
                    </span>
                    <span className={item.met ? 'text-sm text-slate-200' : 'text-sm text-slate-500'}>{item.label}</span>
                  </div>
                ))}
              </div>

              {error && (
                <div className="mt-4 flex items-start gap-2 rounded-xl border border-red-400/25 bg-red-500/10 px-4 py-3 text-sm text-red-200 shadow-glow-critical">
                  <AlertTriangle size={16} className="mt-0.5 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <button
                onClick={handleScan}
                disabled={loading}
                className="cyber-launch-button mt-5 w-full"
              >
                {loading ? (
                  <>
                    <span className="h-4 w-4 rounded-full border-2 border-cyber-950/30 border-t-cyber-950 animate-spin" />
                    Starting scan...
                  </>
                ) : (
                  <>
                    <Zap size={18} />
                    {activeEnabled && consentGiven ? 'Launch active scan' : 'Launch scan'}
                  </>
                )}
              </button>

              {activeEnabled && consentGiven && (
                <p className="mt-3 rounded-xl border border-orange-300/20 bg-orange-400/10 px-3 py-2 text-center text-xs font-semibold text-orange-200">
                  ⚠️ Active mode: real payloads will be sent to {domain || 'target'}
                </p>
              )}
            </aside>
          </div>
        </div>

        <p className="text-center text-xs text-slate-600">
          100% free & open source · Designed for Nepal&apos;s startup ecosystem · By VoidVex
        </p>
      </section>
    </main>
  )
}
