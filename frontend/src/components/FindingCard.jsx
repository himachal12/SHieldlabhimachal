import { useState } from 'react'
import { ChevronDown, ChevronUp, Code2, Wrench } from 'lucide-react'
import SeverityBadge from './SeverityBadge'
import CvssScore from './CvssScore'

export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="bg-surface border border-slate-700 rounded-xl overflow-hidden mb-3
                    hover:border-slate-500 transition-colors">
      {/* Summary row — always visible */}
      <button
        className="w-full text-left p-4 flex items-center gap-3"
        onClick={() => setExpanded(!expanded)}
      >
        <SeverityBadge severity={finding.severity} />

        <div className="flex-1 min-w-0">
          <p className="font-semibold text-white truncate">{finding.vuln_type}</p>
          <p className="text-sm text-slate-400 truncate">
            {finding.file_path
              ? `${finding.file_path}${finding.line_number ? `:${finding.line_number}` : ''}`
              : finding.url || 'No location'}
          </p>
        </div>

        <CvssScore score={finding.cvss_score} />

        {expanded
          ? <ChevronUp size={16} className="text-slate-400 ml-2 flex-shrink-0" />
          : <ChevronDown size={16} className="text-slate-400 ml-2 flex-shrink-0" />
        }
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 pb-4 border-t border-slate-700 space-y-4">

          {/* Description */}
          <div className="pt-3">
            <p className="text-sm text-slate-300">{finding.description}</p>
          </div>

          {/* Vulnerable code */}
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

          {/* Fixed code */}
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

          {/* Fix explanation */}
          {finding.fix_explanation && (
            <div className="bg-slate-800 rounded-lg p-3">
              <p className="text-xs text-slate-300 leading-relaxed">
                {finding.fix_explanation}
              </p>
            </div>
          )}

          {/* Remediation time */}
          {finding.remediation_time && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-500">Est. fix time:</span>
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