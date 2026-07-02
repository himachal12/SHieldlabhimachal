import { useState } from 'react'
import {
  ChevronDown,
  ChevronUp,
  Code2,
  Wrench,
  Link2,
} from 'lucide-react'

import SeverityBadge from './SeverityBadge'
import CvssScore from './CvssScore'

export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div
      className="bg-surface border border-slate-700 rounded-xl overflow-hidden mb-3
                 hover:border-slate-500 transition-colors"
    >
      {/* Summary row */}
      <button
        className="w-full text-left p-4 flex items-center gap-3"
        onClick={() => setExpanded(!expanded)}
      >
        <SeverityBadge severity={finding.severity} />

        {/* Attack Chain Badge */}
        {finding.is_cross_domain && (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full
                       text-xs font-bold bg-red-500/20 text-red-400
                       border border-red-500/30"
          >
            <Link2 size={10} />
            Chain
          </span>
        )}

        <div className="flex-1 min-w-0">
          <p className="font-semibold text-white truncate">
            {finding.vuln_type}
          </p>

          <p className="text-sm text-slate-400 truncate">
            {finding.file_path
              ? `${finding.file_path}${
                  finding.line_number ? `:${finding.line_number}` : ''
                }`
              : finding.url || 'No location'}
          </p>
        </div>

        <CvssScore score={finding.cvss_score} />

        {expanded ? (
          <ChevronUp
            size={16}
            className="text-slate-400 ml-2 flex-shrink-0"
          />
        ) : (
          <ChevronDown
            size={16}
            className="text-slate-400 ml-2 flex-shrink-0"
          />
        )}
      </button>

      {/* Expanded Details */}
      {expanded && (
        <div className="px-4 pb-4 border-t border-slate-700 space-y-4">

          {/* Description */}
          <div className="pt-3">
            <p className="text-sm text-slate-300">
              {finding.description}
            </p>
          </div>

          {/* Vulnerable Code */}
          {finding.vulnerable_code && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Code2 size={14} className="text-red-400" />
                <span className="text-xs font-semibold text-red-400 uppercase tracking-wide">
                  Vulnerable Code
                </span>
              </div>

              <pre className="text-red-300 text-xs">
                {finding.vulnerable_code}
              </pre>
            </div>
          )}

          {/* Fixed Code */}
          {finding.fixed_code && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Wrench size={14} className="text-green-400" />
                <span className="text-xs font-semibold text-green-400 uppercase tracking-wide">
                  Suggested Fix
                </span>
              </div>

              <pre className="text-green-300 text-xs">
                {finding.fixed_code}
              </pre>
            </div>
          )}

          {/* Fix Explanation */}
          {finding.fix_explanation && (
            <div className="bg-slate-800 rounded-lg p-3">
              <p className="text-xs text-slate-300 leading-relaxed">
                {finding.fix_explanation}
              </p>
            </div>
          )}

          {/* Estimated Remediation Time */}
          {finding.remediation_time && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-500">
                Est. fix time:
              </span>

              <span className="text-xs text-accent font-medium">
                {finding.remediation_time}
              </span>
            </div>
          )}

        </div>
      )}
    </div>
  )
}