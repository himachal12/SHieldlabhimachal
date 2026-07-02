import AttackChainCard from '../components/AttackChainCard'
import { Link2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Shield,
  AlertTriangle,
  ArrowLeft,
  Filter,
  TrendingUp,
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

  return (
    <div className="min-h-screen px-4 py-8 max-w-5xl mx-auto">

      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <button
          onClick={() => navigate('/')}
          className="text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft size={20} />
        </button>

        <Shield className="text-accent" size={24} />

        <h1 className="text-xl font-bold text-white">
          Scan Results
        </h1>

        <span className="font-mono text-xs text-slate-500 ml-1">
          {scanId}
        </span>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">

        <div className="bg-surface border border-slate-700 rounded-xl p-4 col-span-2 md:col-span-1">
          <p className="text-xs text-slate-500 mb-1">
            Risk Level
          </p>

          <SeverityBadge severity={riskLevel} />
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
            className="bg-surface border border-slate-700 rounded-xl p-4"
          >
            <p className="text-xs text-slate-500 mb-1">
              {stat.label}
            </p>

            <p className={`text-2xl font-bold ${stat.color}`}>
              {stat.value}
            </p>
          </div>
        ))}
      </div>

      {/* Chart + Filter */}
      <div className="grid md:grid-cols-3 gap-4 mb-6">

        <div className="md:col-span-1">
          <SeverityChart results={results} />
        </div>

        <div className="md:col-span-2 bg-surface border border-slate-700 rounded-xl p-5">

          <div className="flex items-center gap-2 mb-4">
            <Filter size={16} className="text-slate-400" />
            <h3 className="font-semibold text-white text-sm">
              Filter by Severity
            </h3>
          </div>

          <div className="flex flex-wrap gap-2">

            <button
              onClick={() => setFilter('ALL')}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors
              ${
                filter === 'ALL'
                  ? 'bg-accent text-primary'
                  : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
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
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors
                  ${
                    filter === sev
                      ? 'bg-accent text-primary'
                      : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  {sev} ({count})
                </button>
              )
            })}
          </div>

          {/* Quick stats */}
          <div className="mt-4 pt-4 border-t border-slate-700">

            <div className="flex items-center gap-2 text-sm text-slate-400">
              <TrendingUp size={14} />
              <span>
                {sorted.filter((f) => f.fixed_code).length} findings have AI-generated fixes
              </span>
            </div>

            {results.attack_chains?.length > 0 && (
              <div className="flex items-center gap-2 text-sm text-red-400 mt-1">
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

      {/* Attack Chains */}
      {results.attack_chains && results.attack_chains.length > 0 && (
        <div className="mb-6">

          <div className="flex items-center gap-2 mb-3">
            <Link2 size={18} className="text-red-400" />

            <h3 className="font-semibold text-white">
              Attack Chains Detected
            </h3>

            <span className="bg-red-500 text-white text-xs px-2 py-0.5 rounded-full font-bold">
              {results.attack_chains.length}
            </span>

            <span className="text-xs text-slate-500 ml-1">
              — Multiple findings compound into higher risk
            </span>
          </div>

          {results.attack_chains.map((chain, i) => (
            <AttackChainCard
              key={chain.chain_id}
              chain={chain}
              index={i}
            />
          ))}

        </div>
      )}

      {/* Findings */}
      <div>

        <h3 className="font-semibold text-white mb-3">
          {sorted.length} Finding
          {sorted.length !== 1 ? 's' : ''}
          {filter !== 'ALL' && ` (filtered: ${filter})`}
        </h3>

        {sorted.length === 0 ? (
          <div className="text-center py-12 text-slate-500">
            No findings for this filter
          </div>
        ) : (
          sorted.map((finding) => (
            <FindingCard
              key={finding.finding_id}
              finding={finding}
            />
          ))
        )}

      </div>

    </div>
  )
}