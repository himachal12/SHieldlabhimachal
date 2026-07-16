import { useState } from 'react'
import { 
  Link2, ChevronDown, ChevronUp, 
  Clock, Zap, AlertOctagon 
} from 'lucide-react'
import SeverityBadge from './SeverityBadge'

export default function AttackChainCard({ chain, index }) {
  const [expanded, setExpanded] = useState(true) // open by default -- this is your headline feature

  return (
    <div className="mb-4 overflow-hidden rounded-2xl border border-red-500/40 bg-gradient-to-br from-red-950/35 via-slate-950/70 to-slate-900/80 shadow-panel transition-all duration-200 hover:border-red-400/60">
      
      {/* Header */}
      <button
        className="flex w-full items-center gap-3 p-4 text-left sm:p-5"
        onClick={() => setExpanded(!expanded)}
      >
        {/* Chain icon */}
        <div className="flex-shrink-0 rounded-xl border border-red-500/30 bg-red-500/15 p-2">
          <Link2 size={18} className="text-red-400" />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-bold text-white">
              Attack Chain #{index + 1}
            </span>
            <SeverityBadge severity={chain.severity} />
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            {chain.finding_types?.join(' + ') || 'Multiple findings compound'}
          </p>
        </div>

        {/* Quick stats */}
        <div className="flex items-center gap-3 flex-shrink-0">
          <div className="flex items-center gap-1 text-orange-400 text-xs">
            <Clock size={12} />
            <span>{chain.time_to_exploit}</span>
          </div>
          {expanded
            ? <ChevronUp size={16} className="text-slate-400" />
            : <ChevronDown size={16} className="text-slate-400" />
          }
        </div>
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="space-y-4 border-t border-red-500/20 bg-slate-950/25 px-4 pb-4 pt-3 sm:px-5 sm:pb-5">

          {/* Attack chain steps */}
          {chain.attack_chain && chain.attack_chain.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Zap size={14} className="text-yellow-400" />
                <span className="text-xs font-bold text-yellow-400 uppercase tracking-wide">
                  Attack Path
                </span>
              </div>
              <div className="space-y-2">
                {chain.attack_chain.map((step, i) => (
                  <div key={i} className="flex gap-3">
                    {/* Step number */}
                    <div className="flex-shrink-0 w-6 h-6 rounded-full bg-red-500/30
                                    border border-red-500/50 flex items-center justify-center">
                      <span className="text-xs font-bold text-red-400">{i + 1}</span>
                    </div>
                    <p className="text-sm text-slate-300 pt-0.5 leading-relaxed">
                      {step.replace(/^Step \d+:\s*/i, '')}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Impact */}
          {chain.impact && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3">
              <div className="flex items-center gap-2 mb-1">
                <AlertOctagon size={14} className="text-red-400" />
                <span className="text-xs font-bold text-red-400 uppercase tracking-wide">
                  Worst-Case Impact
                </span>
              </div>
              <p className="text-sm text-red-300">{chain.impact}</p>
            </div>
          )}

        </div>
      )}
    </div>
  )
}