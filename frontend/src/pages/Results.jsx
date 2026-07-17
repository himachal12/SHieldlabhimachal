import AutoPRPanel from '../components/AutoPRPanel'
import AttackChainCard from '../components/AttackChainCard'
import FindingCard from '../components/FindingCard'
import SeverityBadge from '../components/SeverityBadge'
import SeverityChart from '../components/SeverityChart'
import { getScanResults } from '../api/client'
import { Component, useEffect, useMemo, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  ArrowDownWideNarrow,
  ArrowLeft,
  Clock3,
  FileCode2,
  Filter,
  Link2,
  ListChecks,
  Radar,
  Search,
  Shield,
  Target,
  TrendingUp,
  Wrench,
  XCircle,
} from 'lucide-react'

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const SEVERITY_SCORE = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 }

const SORT_OPTIONS = [
  { value: 'cvss', label: 'Highest CVSS' },
  { value: 'severity', label: 'Severity first' },
  { value: 'fixable', label: 'Fix available' },
]

const getFindingLocation = (finding) => {
  if (finding.file_path) {
    return `${finding.file_path}${finding.line_number ? `:${finding.line_number}` : ''}`
  }
  if (finding.url) return finding.url
  if (finding.port) return `Port ${finding.port}`
  return 'No location provided'
}

const getRiskLevel = (results) => {
  if (results.critical_count > 0) return 'CRITICAL'
  if (results.high_count > 0) return 'HIGH'
  if (results.medium_count > 0) return 'MEDIUM'
  if (results.low_count > 0) return 'LOW'
  return 'INFO'
}

const getRiskNarrative = (results) => {
  if (results.critical_count > 0) {
    return 'Critical findings are present in the backend results. Review exploitable paths and fix critical issues first.'
  }
  if (results.high_count > 0) {
    return 'High severity findings are present. Prioritize the highest CVSS items and any chained findings before lower severity work.'
  }
  if (results.medium_count > 0) {
    return 'Medium severity findings are present. Use the finding explorer to plan hardening and remediation.'
  }
  if (results.total_findings > 0) {
    return 'Only low or informational findings were returned. Review them for hardening and hygiene improvements.'
  }
  return 'No findings were returned by the backend for this scan.'
}

const formatDate = (value) => {
  if (!value) return 'Not available'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Not available'
  return date.toLocaleString()
}

class AutoPRPanelErrorBoundary extends Component {
  state = { hasError: false }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidUpdate(previousProps) {
    if (previousProps.scanId !== this.props.scanId && this.state.hasError) {
      this.setState({ hasError: false })
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <section className="mb-6 rounded-xl border border-yellow-500/30 bg-yellow-500/10 p-4 text-sm text-yellow-100">
          <p className="font-semibold">Auto-Fix Pull Request is temporarily unavailable.</p>
          <p className="mt-1 text-xs text-yellow-200/80">
            Your scan results are still available. Refresh after updating the frontend before using Auto PR.
          </p>
        </section>
      )
    }

    return this.props.children
  }
}

export default function Results() {
  const { scanId } = useParams()
  const navigate = useNavigate()

  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('ALL')
  const [query, setQuery] = useState('')
  const [sortBy, setSortBy] = useState('cvss')
  const [showFixableOnly, setShowFixableOnly] = useState(false)
  const [showChainsOnly, setShowChainsOnly] = useState(false)

  useEffect(() => {
    const fetchResults = async () => {
      try {
        const res = await getScanResults(scanId)
        setResults(res.data)
      } catch (err) {
        if (err.response?.status === 202) {
          setError('Scan still in progress. Go back and wait for completion.')
        } else {
          setError(err.response?.data?.detail || 'Failed to load results')
        }
      } finally {
        setLoading(false)
      }
    }

    fetchResults()
  }, [scanId])

  const findings = useMemo(() => results?.findings || [], [results])

  const severityCounts = useMemo(() => {
    const fromFindings = findings.reduce((acc, finding) => {
      acc[finding.severity] = (acc[finding.severity] || 0) + 1
      return acc
    }, {})

    if (!results) return fromFindings

    return {
      ...fromFindings,
      CRITICAL: results.critical_count,
      HIGH: results.high_count,
      MEDIUM: results.medium_count,
      LOW: results.low_count,
    }
  }, [findings, results])

  const filteredAndSorted = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()

    const filtered = findings.filter((finding) => {
      const matchesSeverity = filter === 'ALL' || finding.severity === filter
      const matchesFixable = !showFixableOnly || Boolean(finding.fixed_code)
      const matchesChain = !showChainsOnly || Boolean(finding.is_cross_domain)
      const searchTarget = [
        finding.vuln_type,
        finding.description,
        finding.file_path,
        finding.url,
        finding.port ? String(finding.port) : '',
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
      const matchesQuery = !normalizedQuery || searchTarget.includes(normalizedQuery)

      return matchesSeverity && matchesFixable && matchesChain && matchesQuery
    })

    return [...filtered].sort((a, b) => {
      if (sortBy === 'severity') {
        return (SEVERITY_SCORE[b.severity] || 0) - (SEVERITY_SCORE[a.severity] || 0) || (b.cvss_score || 0) - (a.cvss_score || 0)
      }
      if (sortBy === 'fixable') {
        return Number(Boolean(b.fixed_code)) - Number(Boolean(a.fixed_code)) || (b.cvss_score || 0) - (a.cvss_score || 0)
      }
      return (b.cvss_score || 0) - (a.cvss_score || 0)
    })
  }, [findings, filter, query, showChainsOnly, showFixableOnly, sortBy])

  const priorityFindings = useMemo(() => {
    return [...findings]
      .sort((a, b) => {
        const aScore = (SEVERITY_SCORE[a.severity] || 0) * 20 + (a.cvss_score || 0) + (a.is_cross_domain ? 8 : 0) + (a.fixed_code ? 3 : 0)
        const bScore = (SEVERITY_SCORE[b.severity] || 0) * 20 + (b.cvss_score || 0) + (b.is_cross_domain ? 8 : 0) + (b.fixed_code ? 3 : 0)
        return bScore - aScore
      })
      .slice(0, 5)
  }, [findings])

  const riskLevel = results ? getRiskLevel(results) : 'LOW'
  const suggestedFixCount = findings.filter((finding) => (
    finding.fixed_code && (!finding.remediation_status || finding.remediation_status === 'suggested')
  )).length
  const chainFindingCount = findings.filter((finding) => finding.is_cross_domain).length
  const hasAttackChains = Boolean(results?.attack_chains?.length)

  if (loading) {
    return (
      <main className="cyber-screen min-h-screen overflow-hidden px-4 py-10 text-slate-100">
        <div className="cyber-orb cyber-orb-cyan" />
        <div className="cyber-orb cyber-orb-violet" />
        <div className="cyber-grid" />
        <section className="relative z-10 mx-auto flex min-h-[calc(100vh-5rem)] max-w-xl items-center justify-center">
          <div className="scan-console w-full p-6 text-center">
            <Radar className="mx-auto mb-4 animate-spin-slow text-cyan-200" size={44} />
            <p className="cyber-label mb-2 text-cyan-300/80">Loading report</p>
            <h1 className="text-2xl font-black text-white">Fetching security intelligence...</h1>
            <p className="mt-2 text-sm text-slate-500">Waiting for the backend results payload.</p>
          </div>
        </section>
      </main>
    )
  }

  if (error) {
    return (
      <main className="cyber-screen min-h-screen overflow-hidden px-4 py-10 text-slate-100">
        <div className="cyber-orb cyber-orb-cyan" />
        <div className="cyber-orb cyber-orb-violet" />
        <div className="cyber-grid" />
        <section className="relative z-10 mx-auto flex min-h-[calc(100vh-5rem)] max-w-xl items-center justify-center">
          <div className="scan-console w-full border-red-300/25 p-6 text-center">
            <AlertTriangle className="mx-auto mb-4 text-red-300" size={44} />
            <p className="cyber-label mb-2 text-red-300/80">Results unavailable</p>
            <h1 className="text-2xl font-black text-white">Could not load scan results</h1>
            <p className="mt-3 text-sm leading-6 text-red-100/90">{error}</p>
            <button
              onClick={() => navigate('/')}
              className="cyber-button-secondary mt-6"
            >
              ← Back to scanner
            </button>
          </div>
        </section>
      </main>
    )
  }

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
              <div className="grid h-12 w-12 place-items-center rounded-2xl border border-cyan-300/20 bg-cyan-300/10 shadow-glow-cyan">
                <Shield className="text-cyan-200" size={27} />
              </div>
              <div>
                <p className="cyber-label text-cyan-300/80">Results console</p>
                <h1 className="bg-gradient-to-r from-white via-cyan-100 to-violet-200 bg-clip-text text-3xl font-black tracking-tight text-transparent sm:text-5xl">
                  Security Intelligence Report
                </h1>
              </div>
            </div>
            <p className="max-w-3xl text-sm leading-6 text-slate-400">
              Results below are rendered from the completed backend scan payload. Use the triage controls to focus on the findings that matter first.
            </p>
          </div>

          <div className="grid gap-2 rounded-2xl border border-cyan-300/15 bg-cyan-300/5 p-4 text-xs shadow-glow-cyan sm:min-w-80">
            <div className="flex items-center justify-between gap-4">
              <span className="text-slate-500">Scan ID</span>
              <span className="break-all font-mono text-cyan-100">{scanId}</span>
            </div>
            <div className="flex items-center justify-between gap-4">
              <span className="text-slate-500">Scan type</span>
              <span className="font-bold uppercase text-white">{results.scan_type}</span>
            </div>
            <div className="flex items-center justify-between gap-4">
              <span className="text-slate-500">Completed</span>
              <span className="text-right text-slate-300">{formatDate(results.completed_at)}</span>
            </div>
          </div>
        </header>

        <div className="mb-6 grid gap-4 lg:grid-cols-[1.1fr_0.9fr_0.9fr]">
          <div className="cyber-command-panel p-5">
            <div className="mb-4 flex items-start justify-between gap-4">
              <div>
                <p className="cyber-label mb-2 text-cyan-300/80">Executive risk</p>
                <SeverityBadge severity={riskLevel} />
              </div>
              <Target className="text-cyan-300" size={24} />
            </div>
            <p className="text-sm leading-6 text-slate-300">{getRiskNarrative(results)}</p>
            <div className="mt-5 grid grid-cols-3 gap-2">
              <div className="rounded-2xl border border-white/10 bg-white/[0.035] p-3">
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Total</p>
                <p className="text-2xl font-black text-white">{results.total_findings}</p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/[0.035] p-3">
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Suggestions</p>
                <p className="text-2xl font-black text-green-300">{suggestedFixCount}</p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/[0.035] p-3">
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Chains</p>
                <p className="text-2xl font-black text-red-300">{results.attack_chains?.length || 0}</p>
              </div>
            </div>
          </div>

          <SeverityChart results={results} />

          <div className="cyber-command-panel p-5">
            <div className="mb-4 flex items-center gap-2">
              <Wrench size={17} className="text-green-300" />
              <h2 className="font-bold text-white">Fix plan</h2>
            </div>
            <div className="space-y-3 text-sm">
              <div className="flex items-center justify-between rounded-xl border border-white/10 bg-white/[0.035] px-3 py-2">
                <span className="text-slate-400">Suggested patches</span>
                <span className="font-bold text-green-300">{suggestedFixCount}</span>
              </div>
              <div className="flex items-center justify-between rounded-xl border border-white/10 bg-white/[0.035] px-3 py-2">
                <span className="text-slate-400">Chain-linked findings</span>
                <span className="font-bold text-red-300">{chainFindingCount}</span>
              </div>
              <div className="flex items-center justify-between rounded-xl border border-white/10 bg-white/[0.035] px-3 py-2">
                <span className="text-slate-400">Report path</span>
                <span className="max-w-36 truncate font-mono text-xs text-slate-300">{results.report_path || 'Not returned'}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
          <button
            onClick={() => setFilter('ALL')}
            className={`result-stat-card ${filter === 'ALL' ? 'is-selected' : ''}`}
          >
            <span>All</span>
            <strong>{findings.length}</strong>
          </button>
          {SEVERITY_ORDER.map((severity) => {
            const count = severityCounts[severity] || 0
            if (count === 0 && filter !== severity) return null
            return (
              <button
                key={severity}
                onClick={() => setFilter(severity)}
                className={`result-stat-card severity-${severity.toLowerCase()} ${filter === severity ? 'is-selected' : ''}`}
              >
                <span>{severity}</span>
                <strong>{count}</strong>
              </button>
            )
          })}
        </div>

        {results.scan_type !== 'web' && (
          <AutoPRPanelErrorBoundary scanId={scanId}>
            <AutoPRPanel
              scanId={scanId}
              repoUrl={results.repo_url}
              scanType={results.scan_type}
              findings={findings}
            />
          </AutoPRPanelErrorBoundary>
        )}

        {hasAttackChains && (
          <section className="mb-6">
            <div className="mb-3 flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-2">
                <Link2 size={18} className="text-red-300" />
                <h2 className="text-lg font-black text-white">Threat Path Spotlight</h2>
              </div>
              <span className="rounded-full border border-red-300/25 bg-red-500/10 px-2.5 py-1 text-xs font-black text-red-200">
                {results.attack_chains.length} chain{results.attack_chains.length > 1 ? 's' : ''}
              </span>
              <p className="text-xs text-slate-500">Only shown when attack-chain data is returned by the backend.</p>
            </div>

            <div>
              {results.attack_chains.map((chain, index) => (
                <AttackChainCard
                  key={chain.chain_id}
                  chain={chain}
                  index={index}
                />
              ))}
            </div>
          </section>
        )}

        {priorityFindings.length > 0 && (
          <section className="cyber-command-panel mb-6 p-5">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <ListChecks size={18} className="text-cyan-300" />
                <h2 className="font-black text-white">Priority queue</h2>
              </div>
              <p className="text-xs text-slate-500">Sorted from returned severity, CVSS, chain marker, and fix availability.</p>
            </div>
            <div className="grid gap-2 lg:grid-cols-5">
              {priorityFindings.map((finding, index) => (
                <button
                  key={finding.finding_id}
                  onClick={() => {
                    setFilter('ALL')
                    setQuery(finding.vuln_type || '')
                  }}
                  className="rounded-2xl border border-white/10 bg-white/[0.035] p-3 text-left transition-all hover:-translate-y-0.5 hover:border-cyan-300/25 hover:bg-cyan-300/5"
                >
                  <div className="mb-3 flex items-center justify-between gap-2">
                    <span className="text-xs font-black text-slate-500">#{index + 1}</span>
                    <SeverityBadge severity={finding.severity} />
                  </div>
                  <p className="truncate text-sm font-bold text-white">{finding.vuln_type}</p>
                  <p className="mt-1 truncate text-xs text-slate-500">{getFindingLocation(finding)}</p>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {finding.cvss_score !== null && finding.cvss_score !== undefined && (
                      <span className="rounded-full bg-cyan-300/10 px-2 py-0.5 text-[10px] font-bold text-cyan-200">CVSS {finding.cvss_score.toFixed(1)}</span>
                    )}
                    {finding.fixed_code && <span className="rounded-full bg-green-400/10 px-2 py-0.5 text-[10px] font-bold text-green-200">Fix</span>}
                    {finding.is_cross_domain && <span className="rounded-full bg-red-400/10 px-2 py-0.5 text-[10px] font-bold text-red-200">Chain</span>}
                  </div>
                </button>
              ))}
            </div>
          </section>
        )}

        <section className="cyber-command-panel mb-6 p-5">
          <div className="mb-4 flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
            <div>
              <p className="cyber-label mb-1 text-cyan-300/80">Finding explorer</p>
              <h2 className="text-xl font-black text-white">
                {filteredAndSorted.length} Finding{filteredAndSorted.length !== 1 ? 's' : ''}
                {filter !== 'ALL' && ` · ${filter}`}
              </h2>
            </div>

            <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
              <label className="flex min-w-0 items-center gap-2 rounded-2xl border border-white/10 bg-black/20 px-3 py-2 focus-within:border-cyan-300/40 lg:w-80">
                <Search size={16} className="text-slate-500" />
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search type, file, URL, description..."
                  className="min-w-0 flex-1 bg-transparent text-sm text-white placeholder:text-slate-600 focus:outline-none"
                />
              </label>

              <label className="flex items-center gap-2 rounded-2xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-slate-300">
                <ArrowDownWideNarrow size={16} className="text-slate-500" />
                <select
                  value={sortBy}
                  onChange={(event) => setSortBy(event.target.value)}
                  className="bg-transparent text-sm text-white focus:outline-none"
                >
                  {SORT_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value} className="bg-slate-900 text-white">
                      {option.label}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          </div>

          <div className="flex flex-wrap gap-2 border-t border-white/10 pt-4">
            <button
              onClick={() => setShowFixableOnly(!showFixableOnly)}
              className={`result-toggle ${showFixableOnly ? 'is-active' : ''}`}
            >
              <Wrench size={14} />
              Has suggestion ({suggestedFixCount})
            </button>
            <button
              onClick={() => setShowChainsOnly(!showChainsOnly)}
              className={`result-toggle ${showChainsOnly ? 'is-active' : ''}`}
            >
              <Link2 size={14} />
              Chain findings ({chainFindingCount})
            </button>
            <button
              onClick={() => {
                setFilter('ALL')
                setQuery('')
                setShowFixableOnly(false)
                setShowChainsOnly(false)
                setSortBy('cvss')
              }}
              className="result-toggle"
            >
              <Filter size={14} />
              Reset filters
            </button>
          </div>
        </section>

        <div>
          {filteredAndSorted.length === 0 ? (
            <div className="cyber-command-panel py-14 text-center text-slate-500">
              <XCircle className="mx-auto mb-3 text-slate-600" size={34} />
              No findings match the current filters.
            </div>
          ) : (
            filteredAndSorted.map((finding) => (
              <FindingCard
                key={finding.finding_id}
                finding={finding}
              />
            ))
          )}
        </div>

        <div className="mt-8 grid gap-3 text-xs text-slate-500 md:grid-cols-3">
          <div className="flex items-center gap-2 rounded-2xl border border-white/5 bg-white/[0.025] px-4 py-3">
            <Clock3 size={14} /> Created: {formatDate(results.created_at)}
          </div>
          <div className="flex items-center gap-2 rounded-2xl border border-white/5 bg-white/[0.025] px-4 py-3">
            <TrendingUp size={14} /> Status: {results.status}
          </div>
          <div className="flex items-center gap-2 rounded-2xl border border-white/5 bg-white/[0.025] px-4 py-3">
            <FileCode2 size={14} /> Repo: {results.repo_url || 'Not returned'}
          </div>
        </div>
      </section>
    </main>
  )
}
