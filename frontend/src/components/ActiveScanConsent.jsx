import { useState } from 'react'
import { AlertTriangle, CheckCircle2, Plus, ShieldAlert, X } from 'lucide-react'

export default function ActiveScanConsent({
  enabled,
  onToggle,
  consentGiven,
  onConsentChange,
  activeUrls,
  onUrlsChange
}) {
  const [urlInput, setUrlInput] = useState('')

  const addUrl = () => {
    const trimmed = urlInput.trim()
    if (trimmed && !activeUrls.includes(trimmed)) {
      onUrlsChange([...activeUrls, trimmed])
      setUrlInput('')
    }
  }

  const removeUrl = (url) => {
    onUrlsChange(activeUrls.filter(u => u !== url))
  }

  return (
    <div className={`active-scan-panel ${enabled ? 'is-armed' : ''}`}>
      <button
        onClick={onToggle}
        className="flex w-full items-center justify-between gap-4 p-4 text-left transition-colors hover:bg-white/[0.035]"
      >
        <div className="flex items-center gap-3">
          <div className={`grid h-10 w-10 place-items-center rounded-2xl border ${enabled ? 'border-orange-300/35 bg-orange-400/15 text-orange-200' : 'border-slate-600/60 bg-slate-800/60 text-slate-500'}`}>
            <ShieldAlert size={19} />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <p className={`text-sm font-black uppercase tracking-[0.16em] ${enabled ? 'text-orange-200' : 'text-slate-400'}`}>
                Active payload mode
              </p>
              <span className={`rounded-full px-2 py-0.5 text-[10px] font-black tracking-widest ${enabled ? 'bg-orange-400/15 text-orange-200' : 'bg-slate-700/50 text-slate-500'}`}>
                {enabled ? 'ARMED' : 'PASSIVE'}
              </span>
            </div>
            <p className="mt-1 text-xs leading-5 text-slate-500">
              sqlmap SQLi testing sends real payloads — only use on targets you own.
            </p>
          </div>
        </div>

        <div className={`relative h-7 w-12 flex-shrink-0 rounded-full border transition-all ${enabled ? 'border-orange-200/40 bg-orange-500 shadow-[0_0_28px_rgba(249,115,22,0.24)]' : 'border-slate-500/40 bg-slate-700'}`}>
          <div className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow-lg transition-transform ${enabled ? 'translate-x-6' : 'translate-x-1'}`} />
        </div>
      </button>

      {enabled && (
        <div className="space-y-4 border-t border-orange-300/15 bg-orange-950/20 p-4">
          <div className="flex gap-3 rounded-2xl border border-orange-400/25 bg-orange-400/10 p-3">
            <AlertTriangle size={17} className="mt-0.5 flex-shrink-0 text-orange-300" />
            <p className="text-xs leading-6 text-orange-100/90">
              Active scanning sends real SQL injection payloads to the target. This is legal only on systems you own or have explicit written permission to test. Unauthorized scanning may violate laws.
            </p>
          </div>

          <label className="flex cursor-pointer items-start gap-3 rounded-2xl border border-white/10 bg-black/20 p-3 transition-colors hover:bg-white/[0.035]">
            <input
              type="checkbox"
              checked={consentGiven}
              onChange={e => onConsentChange(e.target.checked)}
              className="mt-1 h-4 w-4 accent-orange-500"
            />
            <span className="text-sm leading-6 text-slate-300">
              I confirm I own this target or have explicit written permission to perform active security testing on it.
            </span>
          </label>

          {consentGiven && (
            <div className="rounded-2xl border border-white/10 bg-black/20 p-3">
              <div className="mb-3 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.18em] text-orange-200">
                <CheckCircle2 size={15} />
                Payload URLs
              </div>
              <p className="mb-3 text-xs leading-5 text-slate-500">
                Add URLs with query parameters for sqlmap to test.
              </p>

              <div className="mb-3 flex gap-2">
                <input
                  type="url"
                  placeholder="http://target.com/search?q=test"
                  value={urlInput}
                  onChange={e => setUrlInput(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && addUrl()}
                  className="min-w-0 flex-1 rounded-xl border border-orange-300/15 bg-slate-950/70 px-3 py-2 text-sm text-white placeholder:text-slate-600 transition-colors focus:border-orange-300/60 focus:outline-none focus:ring-4 focus:ring-orange-400/10"
                />
                <button
                  onClick={addUrl}
                  className="rounded-xl bg-orange-500 px-3 py-2 text-white shadow-[0_0_24px_rgba(249,115,22,0.22)] transition-colors hover:bg-orange-400"
                >
                  <Plus size={16} />
                </button>
              </div>

              {activeUrls.length > 0 && (
                <div className="space-y-2">
                  {activeUrls.map(url => (
                    <div key={url} className="flex items-center justify-between gap-3 rounded-xl border border-white/5 bg-slate-950/65 px-3 py-2">
                      <span className="truncate font-mono text-xs text-slate-300">{url}</span>
                      <button
                        onClick={() => removeUrl(url)}
                        className="flex-shrink-0 rounded-lg p-1 text-slate-500 transition-colors hover:bg-red-400/10 hover:text-red-300"
                      >
                        <X size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
