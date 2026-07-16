import AutoPRPanel from '../components/AutoPRPanel'
import AttackChainCard from '../components/AttackChainCard'
import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Shield,
  AlertTriangle,
  ArrowLeft,
  Filter,
  TrendingUp,
  Link2,
  BarChart3,
  Sparkles,
  GitPullRequest,
} from 'lucide-react'
import { getScanResults } from '../api/client'
import FindingCard from '../components/FindingCard'
import SeverityChart from '../components/SeverityChart'
import SeverityBadge from '../components/SeverityBadge'

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export default function Results() {
  const { scanId } = useParams()
  const navigate = useNavigate()

  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('ALL')

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

  if (loading)
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <Shield
            className="text-accent mx-auto animate-pulse mb-3"
            size={40}
          />
          <p className="text-slate-400">Loading results...</p>
        </div>
      </div>
    )

  if (error)
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="text-center">
          <AlertTriangle className="text-red-400 mx-auto mb-3" size={40} />
          <p className="text-red-400">{error}</p>

          <button
            onClick={() => navigate('/')}
            className="mt-4 text-accent hover:underline text-sm"
          >
            ← Back to scanner
          </button>
        </div>
      </div>
    )

  const findings = results?.findings || []

  const filtered =
    filter === 'ALL'
      ? findings
      : findings.filter((f) => f.severity === filter)

  // Sort by CVSS score descending
  const sorted = [...filtered].sort(
    (a, b) => (b.cvss_score || 0) - (a.cvss_score || 0)
  )

  // Risk level label
  const riskLevel =
    results.critical_count > 0
      ? 'CRITICAL'
      : results.high_count > 0
        ? 'HIGH'
        : results.medium_count > 0
          ? 'MEDIUM'
          : 'LOW'

  const aiFixCount = findings.filter((f) => f.fixed_code).length
  const attackChainCount = results.attack_chains?.length || 0
  const severitySummary = [
    { label: 'critical', value: results.critical_count },
    { label: 'high', value: results.high_count },
    { label: 'medium', value: results.medium_count },
    { label: 'low', value: results.low_count },
  ].filter((item) => item.value > 0)

  return (
    <div className="min-h-screen px-4 py-8 sm:px-6 lg:px-8">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-10">

        {/* Header */}
        <header className="rounded-2xl border border-slate-700/70 bg-surface/80 p-5 shadow-panel backdrop-blur sm:p-6">
          <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
            <div className="flex items-start gap-4">
              <button
                onClick={() => navigate('/')}
                className="mt-1 rounded-xl border border-slate-700 bg-slate-900/70 p-2 text-slate-400 transition-all hover:-translate-y-0.5 hover:border-slate-500 hover:text-white"
                aria-label="Back to scanner"
              >
                <ArrowLeft size={18} />
              </button>

              <div>
                <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-accent">
                  <Shield size={16} />
                  Security Assessment
                </div>
                <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
                  Scan Results
                </h1>
                <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
                  Prioritized vulnerabilities, exploitability context, attack chains, and remediation readiness for this scan.
                </p>
              </div>
            </div>

            <div className="rounded-xl border border-slate-700/80 bg-slate-950/50 px-4 py-3">
              <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
                Scan ID
              </p>
              <p className="mt-1 font-mono text-sm text-accent">
                {scanId}
              </p>
            </div>
          </div>
        </header>

        {/* Security Overview */}
        <section className="space-y-4">
          <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                Security Overview
              </p>
              <h2 className="mt-1 text-xl font-semibold text-white">
                Risk posture summary
              </h2>
            </div>
            <p className="text-sm text-slate-500">
              Counts are based on completed scan findings.
            </p>
            <h2 className="mt-1 text-xl font-semibold text-white">
              What this scan found
            </h2>
          </div>

          {/* Summary cards */}
          <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
            <div className="col-span-2 rounded-2xl border border-slate-700/80 bg-surface/90 p-5 shadow-panel transition-all hover:-translate-y-0.5 hover:border-slate-600 md:col-span-1">
              <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
                Risk Level
              </p>

              <div className="mt-4">
                <SeverityBadge severity={riskLevel} />
              </div>
            </div>

            {[
              {
                label: 'Total',
                value: results.total_findings,
                color: 'text-white',
              },
              {
                label: 'Critical',
                value: results.critical_count,
                color: 'text-red-400',
              },
              {
                label: 'High',
                value: results.high_count,
                color: 'text-orange-400',
              },
              {
                label: 'Medium',
                value: results.medium_count,
                color: 'text-yellow-400',
              },
            ].map((stat) => (
              <div
                key={stat.label}
                className="rounded-2xl border border-slate-700/80 bg-surface/90 p-5 shadow-panel transition-all hover:-translate-y-0.5 hover:border-slate-600"
              >
                <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
                  {stat.label}
                </p>

                <p className={`mt-3 text-3xl font-bold tracking-tight ${stat.color}`}>
                  {stat.value}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* Charts & Analytics */}
        <section className="space-y-4">
          <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                Charts & Analytics
              </p>
              <h2 className="mt-1 text-xl font-semibold text-white">
                Severity distribution and filters
              </h2>
            </div>
            <p className="text-sm text-slate-500">
              Filter findings without changing scan data.
            </p>
          </div>

          {/* Chart + Filter */}
          <div className="grid gap-5 lg:grid-cols-3">
            <div className="lg:col-span-1 [&>div]:h-full [&>div]:rounded-2xl [&>div]:border-slate-700/80 [&>div]:bg-surface/90 [&>div]:shadow-panel">
              <SeverityChart results={results} />
            </div>

            <div className="rounded-2xl border border-slate-700/80 bg-surface/90 p-6 shadow-panel lg:col-span-2">
              <div className="flex items-center gap-2 mb-5">
                <div className="rounded-lg bg-slate-800 p-2">
                  <Filter size={16} className="text-slate-300" />
                </div>
                <div>
                  <h3 className="font-semibold text-white">
                    Filter by Severity
                  </h3>
                  <p className="text-xs text-slate-500">
                    Narrow the findings list by risk level.
                  </p>
                </div>
              </div>

              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => setFilter('ALL')}
                  className={`rounded-xl px-3.5 py-2 text-sm font-semibold transition-all hover:-translate-y-0.5
                  ${filter === 'ALL'
                      ? 'bg-accent text-primary shadow-glow-cyan'
                      : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                    }`}
                >
                  All ({findings.length})
                </button>

                {SEVERITY_ORDER.map((sev) => {
                  const count = findings.filter(
                    (f) => f.severity === sev
                  ).length

                  if (count === 0) return null

                  return (
                    <button
                      key={sev}
                      onClick={() => setFilter(sev)}
                      className={`rounded-xl px-3.5 py-2 text-sm font-semibold transition-all hover:-translate-y-0.5
                      ${filter === sev
                          ? 'bg-accent text-primary shadow-glow-cyan'
                          : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                        }`}
                    >
                      {sev} ({count})
                    </button>
                  )
                })}
              </div>

              {/* Quick stats */}
              <div className="mt-6 grid gap-3 border-t border-slate-700/80 pt-5 sm:grid-cols-2">
                <div className="flex items-center gap-2 rounded-xl bg-slate-900/50 px-3 py-2 text-sm text-slate-400">
                  <TrendingUp size={14} />
                  <span>
                    {sorted.filter((f) => f.fixed_code).length} findings have AI-generated fixes
                  </span>
                </div>

                {results.attack_chains?.length > 0 && (
                  <div className="flex items-center gap-2 rounded-xl bg-red-950/20 px-3 py-2 text-sm text-red-300">
                    <Link2 size={14} />
                    <span>
                      {results.attack_chains.length} cross-domain attack chain
                      {results.attack_chains.length > 1 ? 's' : ''} identified
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>

        {/* Attack Chains */}
        {results.attack_chains && results.attack_chains.length > 0 && (
          <section className="space-y-4">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-3">
                <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-2">
                  <Link2 size={18} className="text-red-400" />
                </div>

                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-xl font-semibold text-white">
                      Attack Chains Detected
                    </h2>

                    <span className="rounded-full bg-red-500 px-2 py-0.5 text-xs font-bold text-white">
                      {results.attack_chains.length}
                    </span>
                  </div>

                  <p className="mt-1 text-sm text-slate-500">
                    Multiple findings compound into higher risk.
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              {results.attack_chains.map((chain, i) => (
                <AttackChainCard
                  key={chain.chain_id}
                  chain={chain}
                  index={i}
                />
              ))}
            </div>
          </section>
        )}

        {/* Findings */}
        <section className="space-y-4">
          <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                Findings
              </p>
              <h2 className="mt-1 text-xl font-semibold text-white">
                {sorted.length} Finding
                {sorted.length !== 1 ? 's' : ''}
                {filter !== 'ALL' && ` (filtered: ${filter})`}
              </h2>
            </div>
            <p className="text-sm text-slate-500">
              Sorted by CVSS score from highest to lowest.
            </p>
          </div>

          <div className="rounded-2xl border border-slate-700/70 bg-slate-950/20 p-3 shadow-panel sm:p-4">
            {sorted.length === 0 ? (
              <div className="rounded-xl border border-dashed border-slate-700 py-14 text-center text-slate-500">
                No findings for this filter
              </div>
            ) : (
              <div className="space-y-3">
                {sorted.map((finding) => (
                  <FindingCard
                    key={finding.finding_id}
                    finding={finding}
                  />
                ))}
              </div>
            )}
          </div>
        </section>

        {/* Auto-PR Panel — only for code/combined scans */}
        {results.scan_type !== 'web' && (
          <section className="space-y-4">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                Remediation
              </p>
              <h2 className="mt-1 text-xl font-semibold text-white">
                Auto-fix pull request
              </h2>
              <p className="mt-1 text-sm text-slate-500">
                Apply eligible AI-generated fixes to the scanned repository.
              </p>
            </div>

            <AutoPRPanel
              scanId={scanId}
              repoUrl={results.repo_url}
              scanType={results.scan_type}
            />
          </section>
        )}
      </div>
    </div>
  )
}