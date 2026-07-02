import { useState } from 'react'
import { AlertTriangle, Plus, X, ShieldAlert } from 'lucide-react'

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
    <div className="border border-slate-600 rounded-xl overflow-hidden">
      
      {/* Toggle row */}
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-4
                   bg-slate-800 hover:bg-slate-750 transition-colors"
      >
        <div className="flex items-center gap-3">
          <ShieldAlert 
            size={18} 
            className={enabled ? 'text-orange-400' : 'text-slate-500'} 
          />
          <div className="text-left">
            <p className={`text-sm font-semibold ${enabled ? 'text-orange-400' : 'text-slate-400'}`}>
              Active Scanning (sqlmap SQLi testing)
            </p>
            <p className="text-xs text-slate-500">
              Sends real attack payloads — only use on targets you own
            </p>
          </div>
        </div>

        {/* Toggle pill */}
        <div className={`
          w-11 h-6 rounded-full transition-colors relative flex-shrink-0
          ${enabled ? 'bg-orange-500' : 'bg-slate-600'}
        `}>
          <div className={`
            absolute top-1 w-4 h-4 rounded-full bg-white transition-transform
            ${enabled ? 'translate-x-6' : 'translate-x-1'}
          `}/>
        </div>
      </button>

      {/* Active scan details (only when enabled) */}
      {enabled && (
        <div className="p-4 border-t border-slate-600 space-y-4 bg-orange-950/20">
          
          {/* Warning banner */}
          <div className="flex gap-2 bg-orange-500/10 border border-orange-500/30
                          rounded-lg p-3">
            <AlertTriangle size={16} className="text-orange-400 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-orange-300 leading-relaxed">
              Active scanning sends real SQL injection payloads to the target.
              This is legal only on systems you own or have explicit written 
              permission to test. Unauthorized scanning may violate laws.
            </p>
          </div>

          {/* Consent checkbox */}
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={consentGiven}
              onChange={e => onConsentChange(e.target.checked)}
              className="mt-0.5 w-4 h-4 accent-orange-500"
            />
            <span className="text-sm text-slate-300">
              I confirm I own this target or have explicit written permission 
              to perform active security testing on it.
            </span>
          </label>

          {/* Active URL inputs */}
          {consentGiven && (
            <div>
              <p className="text-xs text-slate-400 mb-2">
                Add URLs with query parameters for sqlmap to test:
              </p>
              
              {/* URL input row */}
              <div className="flex gap-2 mb-2">
                <input
                  type="url"
                  placeholder="http://target.com/search?q=test"
                  value={urlInput}
                  onChange={e => setUrlInput(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && addUrl()}
                  className="flex-1 bg-slate-800 border border-slate-600 rounded-lg
                             px-3 py-2 text-sm text-white placeholder-slate-500
                             focus:outline-none focus:border-orange-500"
                />
                <button
                  onClick={addUrl}
                  className="bg-orange-500 hover:bg-orange-400 text-white
                             px-3 py-2 rounded-lg transition-colors"
                >
                  <Plus size={16} />
                </button>
              </div>

              {/* Added URLs list */}
              {activeUrls.length > 0 && (
                <div className="space-y-1">
                  {activeUrls.map(url => (
                    <div key={url} 
                         className="flex items-center justify-between bg-slate-800
                                    rounded-lg px-3 py-2">
                      <span className="text-xs font-mono text-slate-300 truncate">
                        {url}
                      </span>
                      <button
                        onClick={() => removeUrl(url)}
                        className="text-slate-500 hover:text-red-400 ml-2 flex-shrink-0"
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