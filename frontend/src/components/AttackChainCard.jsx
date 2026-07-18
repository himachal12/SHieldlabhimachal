import { useState } from 'react'
import {
  AlertOctagon,
  ChevronDown,
  ChevronUp,
  Clock,
  FileCode2,
  Globe,
  Link2,
  ListChecks,
  MapPin,
  Route,
  ShieldCheck,
  Zap,
} from 'lucide-react'
import SeverityBadge from './SeverityBadge'
import CvssScore from './CvssScore'

const getEvidenceLocation = (evidence) => {
  if (evidence.location) return evidence.location
  if (evidence.file_path) return `${evidence.file_path}${evidence.line_number ? `:${evidence.line_number}` : ''}`
  if (evidence.url) return evidence.url
  if (evidence.port) return `Port ${evidence.port}`
  return 'Location unavailable'
}

const familyClass = (family) => {
  if (family === 'code') return 'border-cyan-300/20 bg-cyan-300/10 text-cyan-100'
  if (family === 'web') return 'border-violet-300/20 bg-violet-400/10 text-violet-100'
  return 'border-slate-400/20 bg-slate-400/10 text-slate-200'
}

const modeClass = (mode) => {
  if (mode === 'active') return 'border-red-300/25 bg-red-500/10 text-red-100'
  if (mode === 'passive') return 'border-green-300/20 bg-green-500/10 text-green-100'
  if (mode === 'code') return 'border-cyan-300/20 bg-cyan-300/10 text-cyan-100'
  return 'border-slate-400/20 bg-slate-400/10 text-slate-200'
}

function EvidenceCard({ evidence, index }) {
  const family = evidence.scanner_family || 'unknown'
  const mode = evidence.scan_mode || family
  const Icon = family === 'code' ? FileCode2 : Globe

  return (
    <article className="rounded-2xl border border-white/10 bg-black/20 p-4">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 flex-1 items-start gap-3">
          <div className="grid h-9 w-9 flex-shrink-0 place-items-center rounded-xl border border-white/10 bg-white/[0.035] text-slate-200">
            <Icon size={17} />
          </div>
          <div className="min-w-0">
            <p className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">Connected finding #{index + 1}</p>
            <h4 className="mt-1 truncate text-sm font-black text-white">{evidence.vuln_type || 'Unknown finding'}</h4>
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <span className={`rounded-full border px-2 py-0.5 text-[10px] font-black uppercase tracking-wider ${familyClass(family)}`}>
            {family}
          </span>
          <span className={`rounded-full border px-2 py-0.5 text-[10px] font-black uppercase tracking-wider ${modeClass(mode)}`}>
            {mode}
          </span>
        </div>
      </div>

      <dl className="grid gap-2 text-xs sm:grid-cols-2">
        <div>
          <dt className="text-slate-500">Scanner</dt>
          <dd className="mt-0.5 font-mono text-slate-200">{evidence.source || 'unknown'}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Location</dt>
          <dd className="mt-0.5 break-all font-mono text-slate-200">{getEvidenceLocation(evidence)}</dd>
        </div>
        {evidence.cvss_score !== null && evidence.cvss_score !== undefined && (
          <div>
            <dt className="text-slate-500">CVSS</dt>
            <dd className="mt-0.5"><CvssScore score={evidence.cvss_score} /></dd>
          </div>
        )}
        {evidence.confidence !== null && evidence.confidence !== undefined && (
          <div>
            <dt className="text-slate-500">Confidence</dt>
            <dd className="mt-0.5 font-bold text-slate-200">{evidence.confidence}</dd>
          </div>
        )}
      </dl>

      {(evidence.vulnerable_code || evidence.description) && (
        <div className="mt-3 rounded-xl border border-white/10 bg-white/[0.025] p-3">
          <p className="mb-1 text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">Evidence</p>
          {evidence.vulnerable_code ? (
            <pre className="whitespace-pre-wrap break-words text-xs text-red-100">{evidence.vulnerable_code}</pre>
          ) : (
            <p className="text-xs leading-5 text-slate-300">{evidence.description}</p>
          )}
        </div>
      )}
    </article>
  )
}

function StructuredStep({ step, index }) {
  const locations = [step.location, ...(step.locations || [])].filter(Boolean)
  return (
    <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
      <div className="mb-2 flex items-start gap-3">
        <div className="grid h-7 w-7 flex-shrink-0 place-items-center rounded-full border border-red-300/35 bg-red-500/15 text-xs font-black text-red-200">
          {step.step || index + 1}
        </div>
        <div className="min-w-0 flex-1">
          <h4 className="font-bold text-white">{step.title || `Attack step ${index + 1}`}</h4>
          <p className="mt-1 text-sm leading-6 text-slate-300">{step.description}</p>
        </div>
      </div>
      <div className="ml-10 flex flex-wrap gap-2 text-[10px] font-bold uppercase tracking-wider">
        {step.scanner_family && (
          <span className={`rounded-full border px-2 py-0.5 ${familyClass(step.scanner_family)}`}>{step.scanner_family}</span>
        )}
        {step.source && <span className="rounded-full border border-slate-400/20 bg-slate-400/10 px-2 py-0.5 text-slate-200">{step.source}</span>}
        {locations.map((location) => (
          <span key={location} className="inline-flex items-center gap-1 rounded-full border border-yellow-300/20 bg-yellow-400/10 px-2 py-0.5 text-yellow-100">
            <MapPin size={10} />
            {location}
          </span>
        ))}
      </div>
    </div>
  )
}

export default function AttackChainCard({ chain, index }) {
  const [expanded, setExpanded] = useState(true)
  const evidence = chain.evidence || []
  const structuredSteps = chain.attack_steps || []
  const sourceSummary = chain.source_summary || {}
  const summaryModes = sourceSummary.scan_modes || []
  const evidenceType = sourceSummary.evidence_type || (evidence.length ? 'mixed' : null)
  const groupedChainCount = sourceSummary.grouped_chain_count || 1

  return (
    <div className="attack-chain-card mb-4 overflow-hidden">
      <button
        className="w-full p-4 text-left transition-colors hover:bg-red-500/[0.035]"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex flex-col gap-4 md:flex-row md:items-center">
          <div className="flex min-w-0 flex-1 items-center gap-3">
            <div className="grid h-11 w-11 flex-shrink-0 place-items-center rounded-2xl border border-red-300/25 bg-red-500/10 text-red-200">
              <Link2 size={20} />
            </div>
            <div className="min-w-0">
              <div className="mb-1 flex flex-wrap items-center gap-2">
                <span className="font-black text-white">Threat Path #{index + 1}</span>
                <SeverityBadge severity={chain.severity} />
                {chain.confidence && (
                  <span className="rounded-full border border-white/10 bg-white/[0.035] px-2 py-0.5 text-[10px] font-black uppercase tracking-wider text-slate-300">
                    {chain.confidence} confidence
                  </span>
                )}
              </div>
              <p className="truncate text-xs text-slate-400">
                {chain.finding_types?.join(' + ') || evidence.map((item) => item.vuln_type).join(' + ') || 'Multiple findings compound'}
              </p>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {evidenceType && <span className={`rounded-full border px-2 py-0.5 text-[10px] font-black uppercase tracking-wider ${familyClass(evidenceType)}`}>{evidenceType}</span>}
                {summaryModes.map((mode) => (
                  <span key={mode} className={`rounded-full border px-2 py-0.5 text-[10px] font-black uppercase tracking-wider ${modeClass(mode)}`}>{mode}</span>
                ))}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3 md:flex-shrink-0">
            {groupedChainCount > 1 && (
              <div className="inline-flex items-center gap-1.5 rounded-full border border-red-300/20 bg-red-500/10 px-3 py-1.5 text-xs font-semibold text-red-100">
                <Route size={13} />
                Grouped from {groupedChainCount} paths
              </div>
            )}
            {chain.time_to_exploit && (
              <div className="inline-flex items-center gap-1.5 rounded-full border border-orange-300/20 bg-orange-400/10 px-3 py-1.5 text-xs font-semibold text-orange-200">
                <Clock size={13} />
                {chain.time_to_exploit}
              </div>
            )}
            {expanded
              ? <ChevronUp size={18} className="text-slate-400" />
              : <ChevronDown size={18} className="text-slate-400" />
            }
          </div>
        </div>
      </button>

      {expanded && (
        <div className="space-y-4 border-t border-red-300/15 px-4 pb-4 pt-4">
          {evidence.length > 0 && (
            <section>
              <div className="mb-3 flex items-center gap-2 text-xs font-black uppercase tracking-[0.18em] text-cyan-300">
                <ShieldCheck size={14} />
                Connected evidence
              </div>
              <div className="grid gap-3 lg:grid-cols-2">
                {evidence.map((item, itemIndex) => (
                  <EvidenceCard key={item.finding_id || itemIndex} evidence={item} index={itemIndex} />
                ))}
              </div>
            </section>
          )}

          {(structuredSteps.length > 0 || chain.attack_chain?.length > 0) && (
            <section>
              <div className="mb-3 flex items-center gap-2 text-xs font-black uppercase tracking-[0.18em] text-yellow-300">
                <Route size={14} />
                Attack path
              </div>
              <div className="space-y-3">
                {structuredSteps.length > 0 ? (
                  structuredSteps.map((step, i) => <StructuredStep key={`${step.step || i}-${step.title || i}`} step={step} index={i} />)
                ) : (
                  chain.attack_chain.map((step, i) => (
                    <div key={i} className="flex gap-3 rounded-2xl border border-white/10 bg-black/20 p-3">
                      <div className="grid h-7 w-7 flex-shrink-0 place-items-center rounded-full border border-red-300/35 bg-red-500/15 text-xs font-black text-red-200">
                        {i + 1}
                      </div>
                      <p className="pt-0.5 text-sm leading-6 text-slate-300">
                        {step.replace(/^Step \d+:\s*/i, '')}
                      </p>
                    </div>
                  ))
                )}
              </div>
            </section>
          )}

          {chain.impact && (
            <section className="rounded-2xl border border-red-300/25 bg-red-500/10 p-4">
              <div className="mb-2 flex items-center gap-2 text-xs font-black uppercase tracking-[0.18em] text-red-200">
                <AlertOctagon size={14} />
                Worst-case impact
              </div>
              <p className="text-sm leading-6 text-red-100/90">{chain.impact}</p>
            </section>
          )}

          {(chain.reasoning || chain.priority_rationale) && (
            <section className="rounded-2xl border border-yellow-300/15 bg-yellow-400/10 p-4">
              <div className="mb-2 flex items-center gap-2 text-xs font-black uppercase tracking-[0.18em] text-yellow-200">
                <Zap size={14} />
                Why this chain matters
              </div>
              {chain.reasoning && <p className="text-sm leading-6 text-yellow-100/90">{chain.reasoning}</p>}
              {chain.priority_rationale && <p className="mt-2 text-sm leading-6 text-yellow-100/80">{chain.priority_rationale}</p>}
            </section>
          )}

          {chain.recommended_fix_order?.length > 0 && (
            <section className="rounded-2xl border border-green-300/15 bg-green-400/10 p-4">
              <div className="mb-3 flex items-center gap-2 text-xs font-black uppercase tracking-[0.18em] text-green-200">
                <ListChecks size={14} />
                Recommended fix order
              </div>
              <ol className="space-y-2 text-sm text-green-100/90">
                {chain.recommended_fix_order.map((item, itemIndex) => (
                  <li key={`${item}-${itemIndex}`} className="flex gap-2">
                    <span className="font-black text-green-200">{itemIndex + 1}.</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ol>
            </section>
          )}
        </div>
      )}
    </div>
  )
}
