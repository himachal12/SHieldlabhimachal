import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  BrainCircuit,
  ExternalLink,
  Filter,
  Radar,
  RefreshCw,
  Search,
  Shield,
  Sparkles,
  Zap,
} from 'lucide-react'
import { getThreatIntel } from '../api/client'

const SEVERITY_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'ALL']
const WINDOW_OPTIONS = [1, 7, 30]
const SEVERITY_STYLES = {
  CRITICAL: 'border-rose-300/30 bg-rose-500/10 text-rose-100',
  HIGH: 'border-orange-300/30 bg-orange-500/10 text-orange-100',
  MEDIUM: 'border-amber-300/30 bg-amber-500/10 text-amber-100',
  LOW: 'border-green-300/30 bg-green-500/10 text-green-100',
  UNKNOWN: 'border-slate-300/20 bg-slate-500/10 text-slate-200',
}

const formatDate = (value) => {
  if (!value) return 'Unknown'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Unknown'
  return date.toLocaleString()
}

const severityClass = (severity) => SEVERITY_STYLES[severity] || SEVERITY_STYLES.UNKNOWN

export default function ThreatRadar() {
  const navigate = useNavigate()
  const [feed, setFeed] = useState(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [severity, setSeverity] = useState('CRITICAL')
  const [days, setDays] = useState(7)
  const [query, setQuery] = useState('')
  const [sortBy, setSortBy] = useState('cvss')

  const loadThreatIntel = async ({ soft = false } = {}) => {
    if (soft) setRefreshing(true)
    else setLoading(true)
    setError('')

    try {
      const response = await getThreatIntel({ severity, days, limit: 20, ai: true })
      setFeed(response.data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Unable to load the threat intelligence feed.')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => {
    loadThreatIntel()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [severity, days])

  const items = useMemo(() => feed?.items || [], [feed])

  const filteredItems = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    const filtered = items.filter((item) => {
      if (!normalizedQuery) return true
      return [
        item.cve_id,
        item.severity,
        item.description,
        item.why_this_matters,
        item.recommended_action,
        ...(item.affected_keywords || []),
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
        .includes(normalizedQuery)
    })

    return [...filtered].sort((a, b) => {
      if (sortBy === 'newest') {
        return new Date(b.published || 0) - new Date(a.published || 0)
      }
      return (b.cvss_score || 0) - (a.cvss_score || 0)
    })
  }, [items, query, sortBy])

  const counts = useMemo(() => items.reduce((acc, item) => {
    acc[item.severity] = (acc[item.severity] || 0) + 1
    return acc
  }, {}), [items])

  const latestPublished = useMemo(() => {
    if (!items.length) return null
    return [...items].sort((a, b) => new Date(b.published || 0) - new Date(a.published || 0))[0]?.published
  }, [items])

  return (
    <main className="cyber-screen min-h-screen overflow-hidden px-4 py-8 text-slate-100 sm:px-6 lg:px-8">
      <div className="cyber-orb cyber-orb-cyan" />
      <div className="cyber-orb cyber-orb-violet" />
      <div className="cyber-grid" />
      <div className="cyber-scanline" />

      <section className="relative z-10 mx-auto w-full max-w-7xl">
        <header className="mb-7 flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <button
              onClick={() => navigate('/')}
              className="mb-5 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.035] px-3 py-2 text-sm font-semibold text-slate-300 transition-colors hover:border-cyan-300/30 hover:text-white"
            >
              <ArrowLeft size={16} />
              Back to scanner
            </button>

            <div className="mb-4 flex items-center gap-3">
              <div className="relative grid h-12 w-12 place-items-center rounded-2xl border border-cyan-300/20 bg-cyan-300/10 shadow-glow-cyan">
                <Radar className="text-cyan-200" size={27} />
                <span className="absolute inset-0 rounded-2xl border border-cyan-200/30 animate-ping" />
              </div>
              <div>
                <p className="cyber-label text-cyan-300/80">Global vulnerability intelligence</p>
                <h1 className="bg-gradient-to-r from-white via-cyan-100 to-violet-200 bg-clip-text text-3xl font-black tracking-tight text-transparent sm:text-5xl">
                  Threat Radar
                </h1>
              </div>
            </div>
            <p className="max-w-3xl text-sm leading-6 text-slate-400">
              Track recent CVEs from public vulnerability intelligence, prioritize critical risks, and read AI-assisted developer impact summaries before you scan your own stack.
            </p>
          </div>

          <div className="rounded-2xl border border-cyan-300/15 bg-cyan-300/5 p-4 text-xs shadow-glow-cyan sm:min-w-80">
            <div className="mb-2 flex items-center gap-2 font-bold text-cyan-100">
              <Activity size={15} />
              Feed status
            </div>
            <div className="space-y-2 text-slate-400">
              <div className="flex justify-between gap-4"><span>Source</span><span className="text-right font-mono text-slate-200">{feed?.source || 'NVD CVE API 2.0'}</span></div>
              <div className="flex justify-between gap-4"><span>Updated</span><span className="text-right text-slate-200">{formatDate(feed?.updated_at)}</span></div>
              <div className="flex justify-between gap-4"><span>Cache</span><span className="text-right text-slate-200">{feed?.cached ? 'Cached' : 'Live / fresh'}</span></div>
            </div>
          </div>
        </header>

        <div className="mb-6 grid gap-4 lg:grid-cols-4">
          <div className="cyber-command-panel p-5">
            <p className="cyber-label mb-2 text-rose-300/80">Critical</p>
            <p className="text-3xl font-black text-white">{counts.CRITICAL || 0}</p>
            <p className="mt-2 text-xs text-slate-500">Highest urgency CVEs in this view.</p>
          </div>
          <div className="cyber-command-panel p-5">
            <p className="cyber-label mb-2 text-orange-300/80">High</p>
            <p className="text-3xl font-black text-white">{counts.HIGH || 0}</p>
            <p className="mt-2 text-xs text-slate-500">Serious issues that may need fast triage.</p>
          </div>
          <div className="cyber-command-panel p-5">
            <p className="cyber-label mb-2 text-cyan-300/80">Latest published</p>
            <p className="text-lg font-black text-white">{formatDate(latestPublished)}</p>
            <p className="mt-2 text-xs text-slate-500">Newest CVE currently returned.</p>
          </div>
          <div className="cyber-command-panel p-5">
            <p className="cyber-label mb-2 text-violet-300/80">AI summaries</p>
            <p className="text-3xl font-black text-white">{items.filter((item) => item.ai_enriched).length}</p>
            <p className="mt-2 text-xs text-slate-500">Developer-focused impact notes.</p>
          </div>
        </div>

        <section className="cyber-command-panel mb-6 p-5">
          <div className="mb-4 flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
            <div>
              <p className="cyber-label mb-1 text-cyan-300/80">Threat controls</p>
              <h2 className="text-xl font-black text-white">{filteredItems.length} CVE{filteredItems.length === 1 ? '' : 's'} in radar view</h2>
            </div>
            <button
              onClick={() => loadThreatIntel({ soft: true })}
              disabled={refreshing || loading}
              className="cyber-button-secondary"
            >
              <RefreshCw size={16} className={refreshing ? 'animate-spin' : ''} />
              Refresh feed
            </button>
          </div>

          <div className="grid gap-3 lg:grid-cols-[1fr_0.8fr_0.8fr_0.8fr]">
            <label className="flex min-w-0 items-center gap-2 rounded-2xl border border-white/10 bg-black/20 px-3 py-2 focus-within:border-cyan-300/40">
              <Search size={16} className="text-slate-500" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search CVE ID, vendor, product, impact..."
                className="min-w-0 flex-1 bg-transparent text-sm text-white placeholder:text-slate-600 focus:outline-none"
              />
            </label>

            <label className="flex items-center gap-2 rounded-2xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-slate-300">
              <AlertTriangle size={16} className="text-slate-500" />
              <select value={severity} onChange={(event) => setSeverity(event.target.value)} className="w-full bg-transparent text-sm text-white focus:outline-none">
                {SEVERITY_OPTIONS.map((option) => <option key={option} value={option} className="bg-slate-900 text-white">{option}</option>)}
              </select>
            </label>

            <label className="flex items-center gap-2 rounded-2xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-slate-300">
              <Filter size={16} className="text-slate-500" />
              <select value={days} onChange={(event) => setDays(Number(event.target.value))} className="w-full bg-transparent text-sm text-white focus:outline-none">
                {WINDOW_OPTIONS.map((option) => <option key={option} value={option} className="bg-slate-900 text-white">Last {option} day{option > 1 ? 's' : ''}</option>)}
              </select>
            </label>

            <label className="flex items-center gap-2 rounded-2xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-slate-300">
              <Zap size={16} className="text-slate-500" />
              <select value={sortBy} onChange={(event) => setSortBy(event.target.value)} className="w-full bg-transparent text-sm text-white focus:outline-none">
                <option value="cvss" className="bg-slate-900 text-white">Highest CVSS</option>
                <option value="newest" className="bg-slate-900 text-white">Newest first</option>
              </select>
            </label>
          </div>
        </section>

        {feed?.warning && (
          <div className="mb-6 rounded-2xl border border-amber-300/25 bg-amber-500/10 p-4 text-sm text-amber-100">
            {feed.warning}
          </div>
        )}

        {error && (
          <div className="mb-6 rounded-2xl border border-red-300/25 bg-red-500/10 p-4 text-sm text-red-100">
            {error}
          </div>
        )}

        {loading ? (
          <div className="scan-console py-16 text-center">
            <Radar className="mx-auto mb-4 animate-spin-slow text-cyan-200" size={46} />
            <p className="cyber-label mb-2 text-cyan-300/80">Loading threat feed</p>
            <h2 className="text-2xl font-black text-white">Synchronizing with vulnerability intelligence...</h2>
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="scan-console py-16 text-center text-slate-500">
            <Shield className="mx-auto mb-4 text-slate-600" size={42} />
            No CVEs match the current Threat Radar filters.
          </div>
        ) : (
          <div className="grid gap-4">
            {filteredItems.map((item) => (
              <article key={item.cve_id} className="cyber-command-panel overflow-hidden p-5">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                  <div className="min-w-0">
                    <div className="mb-3 flex flex-wrap items-center gap-2">
                      <span className="font-mono text-lg font-black text-white">{item.cve_id}</span>
                      <span className={`rounded-full border px-2.5 py-1 text-[11px] font-black ${severityClass(item.severity)}`}>{item.severity}</span>
                      {item.cvss_score !== null && item.cvss_score !== undefined && (
                        <span className="rounded-full border border-cyan-300/25 bg-cyan-300/10 px-2.5 py-1 text-[11px] font-black text-cyan-100">CVSS {Number(item.cvss_score).toFixed(1)}</span>
                      )}
                      {item.ai_enriched && (
                        <span className="inline-flex items-center gap-1 rounded-full border border-violet-300/25 bg-violet-400/10 px-2.5 py-1 text-[11px] font-black text-violet-100">
                          <Sparkles size={12} /> AI enriched
                        </span>
                      )}
                    </div>
                    <p className="text-sm leading-6 text-slate-300">{item.description}</p>
                  </div>

                  <div className="shrink-0 rounded-2xl border border-white/10 bg-black/20 p-3 text-xs text-slate-400 lg:w-64">
                    <div className="mb-2 flex justify-between gap-3"><span>Published</span><span className="text-right text-slate-200">{formatDate(item.published)}</span></div>
                    <div className="flex justify-between gap-3"><span>Modified</span><span className="text-right text-slate-200">{formatDate(item.last_modified)}</span></div>
                  </div>
                </div>

                {item.affected_keywords?.length > 0 && (
                  <div className="mt-4 flex flex-wrap gap-2">
                    {item.affected_keywords.map((keyword) => (
                      <span key={keyword} className="rounded-full bg-white/[0.06] px-2.5 py-1 text-[11px] font-semibold text-slate-300">{keyword}</span>
                    ))}
                  </div>
                )}

                <div className="mt-5 grid gap-3 lg:grid-cols-2">
                  <div className="rounded-2xl border border-violet-300/15 bg-violet-400/5 p-4">
                    <div className="mb-2 flex items-center gap-2 text-sm font-bold text-violet-100">
                      <BrainCircuit size={16} /> Why developers should care
                    </div>
                    <p className="text-sm leading-6 text-slate-300">{item.why_this_matters}</p>
                  </div>
                  <div className="rounded-2xl border border-green-300/15 bg-green-400/5 p-4">
                    <div className="mb-2 flex items-center gap-2 text-sm font-bold text-green-100">
                      <Shield size={16} /> Recommended action
                    </div>
                    <p className="text-sm leading-6 text-slate-300">{item.recommended_action}</p>
                  </div>
                </div>

                <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-white/10 pt-4">
                  <p className="text-xs text-slate-500">AI summaries are guidance only. Confirm exposure against your actual dependencies and vendor advisories.</p>
                  <a href={item.source_url} target="_blank" rel="noreferrer" className="cyber-button-secondary">
                    View advisory <ExternalLink size={15} />
                  </a>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </main>
  )
}
