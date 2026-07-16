import { useState } from 'react'
import {
  AlertOctagon,
  ChevronDown,
  ChevronUp,
  Clock,
  Link2,
  Route,
  Zap,
} from 'lucide-react'
import SeverityBadge from './SeverityBadge'

export default function AttackChainCard({ chain, index }) {
  const [expanded, setExpanded] = useState(true)

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
              </div>
              <p className="truncate text-xs text-slate-400">
                {chain.finding_types?.join(' + ') || 'Multiple findings compound'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 md:flex-shrink-0">
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
          {chain.attack_chain && chain.attack_chain.length > 0 && (
            <section>
              <div className="mb-3 flex items-center gap-2 text-xs font-black uppercase tracking-[0.18em] text-yellow-300">
                <Route size={14} />
                Attack path
              </div>
              <div className="space-y-3">
                {chain.attack_chain.map((step, i) => (
                  <div key={i} className="flex gap-3 rounded-2xl border border-white/10 bg-black/20 p-3">
                    <div className="grid h-7 w-7 flex-shrink-0 place-items-center rounded-full border border-red-300/35 bg-red-500/15 text-xs font-black text-red-200">
                      {i + 1}
                    </div>
                    <p className="pt-0.5 text-sm leading-6 text-slate-300">
                      {step.replace(/^Step \d+:\s*/i, '')}
                    </p>
                  </div>
                ))}
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

          {chain.reasoning && (
            <section className="rounded-2xl border border-yellow-300/15 bg-yellow-400/10 p-4">
              <div className="mb-2 flex items-center gap-2 text-xs font-black uppercase tracking-[0.18em] text-yellow-200">
                <Zap size={14} />
                Reasoning
              </div>
              <p className="text-sm leading-6 text-yellow-100/90">{chain.reasoning}</p>
            </section>
          )}
        </div>
      )}
    </div>
  )
}
