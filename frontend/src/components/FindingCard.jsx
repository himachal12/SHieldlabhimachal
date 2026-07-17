import { useState } from 'react'
import {
  ChevronDown,
  ChevronUp,
  Clock3,
  Code2,
  FileCode2,
  Globe,
  Link2,
  ShieldCheck,
  Wrench,
} from 'lucide-react'

import SeverityBadge from './SeverityBadge'
import CvssScore from './CvssScore'

const getLocation = (finding) => {
  if (finding.file_path) {
    return `${finding.file_path}${finding.line_number ? `:${finding.line_number}` : ''}`
  }
  if (finding.url) return finding.url
  if (finding.port) return `Port ${finding.port}`
  return 'No location'
}

export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false)
  const isCodeFinding = Boolean(finding.file_path)
  const hasSuggestion = Boolean(finding.fixed_code)
  const remediationStatus = finding.remediation_status || (hasSuggestion ? 'suggested' : 'manual_review_required')

  return (
    <div className="finding-card mb-3 overflow-hidden">
      <button
        className="w-full p-4 text-left transition-colors hover:bg-white/[0.025]"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center">
          <div className="flex min-w-0 flex-1 items-start gap-3">
            <div className="mt-0.5 grid h-10 w-10 flex-shrink-0 place-items-center rounded-2xl border border-cyan-300/15 bg-cyan-300/5 text-cyan-200">
              {isCodeFinding ? <FileCode2 size={18} /> : <Globe size={18} />}
            </div>

            <div className="min-w-0 flex-1">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                {finding.is_cross_domain && (
                  <span className="inline-flex items-center gap-1 rounded-full border border-red-400/25 bg-red-500/10 px-2 py-0.5 text-xs font-bold text-red-200">
                    <Link2 size={10} />
                    Chain
                  </span>
                )}
                {hasSuggestion && (
                  <span className="inline-flex items-center gap-1 rounded-full border border-green-400/25 bg-green-500/10 px-2 py-0.5 text-xs font-bold text-green-200">
                    <Wrench size={10} />
                    {remediationStatus === 'validated_locally' ? 'Validated fix' : 'Suggested fix'}
                  </span>
                )}
                {remediationStatus === 'manual_review_required' && (
                  <span className="inline-flex items-center gap-1 rounded-full border border-amber-400/25 bg-amber-500/10 px-2 py-0.5 text-xs font-bold text-amber-100">
                    Manual review
                  </span>
                )}
              </div>

              <p className="truncate text-base font-black text-white">{finding.vuln_type}</p>
              <p className="mt-1 truncate font-mono text-xs text-slate-500">{getLocation(finding)}</p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 lg:flex-shrink-0">
            <div className="rounded-2xl border border-white/10 bg-black/20 px-3 py-2 text-center">
              <p className="text-[10px] font-black uppercase tracking-wider text-slate-500">CVSS</p>
              <CvssScore score={finding.cvss_score} />
            </div>

            {finding.remediation_time && (
              <div className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.035] px-3 py-1.5 text-xs font-semibold text-slate-300">
                <Clock3 size={13} />
                {finding.remediation_time}
              </div>
            )}

            {expanded ? (
              <ChevronUp size={18} className="text-slate-400" />
            ) : (
              <ChevronDown size={18} className="text-slate-400" />
            )}
          </div>
        </div>
      </button>

      {expanded && (
        <div className="space-y-4 border-t border-white/10 px-4 pb-4 pt-4">
          <section className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
            <div className="mb-2 flex items-center gap-2 text-xs font-black uppercase tracking-[0.18em] text-cyan-300/80">
              <ShieldCheck size={14} />
              Overview
            </div>
            <p className="text-sm leading-6 text-slate-300">{finding.description}</p>
          </section>

          {finding.vulnerable_code && (
            <section>
              <div className="mb-2 flex items-center gap-2 text-xs font-black uppercase tracking-[0.18em] text-red-300">
                <Code2 size={14} />
                Vulnerable code
              </div>
              <pre className="text-xs text-red-200">{finding.vulnerable_code}</pre>
            </section>
          )}

          {finding.fixed_code && (
            <section>
              <div className="mb-2 flex items-center gap-2 text-xs font-black uppercase tracking-[0.18em] text-green-300">
                <Wrench size={14} />
                Suggested fix
              </div>
              <pre className="text-xs text-green-200">{finding.fixed_code}</pre>
            </section>
          )}

          {finding.fix_explanation && (
            <section className="rounded-2xl border border-green-300/15 bg-green-400/10 p-4">
              <p className="text-sm leading-6 text-green-100/90">{finding.fix_explanation}</p>
            </section>
          )}
        </div>
      )}
    </div>
  )
}
