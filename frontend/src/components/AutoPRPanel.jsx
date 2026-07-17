import { useState } from 'react'
import { GitPullRequest, ExternalLink, CheckCircle, 
         XCircle, Loader2, Eye, EyeOff, Info } from 'lucide-react'

function ValidationDetails({ details }) {
  if (!details?.length) return null

  return (
    <div className="mt-3 text-xs text-slate-400">
      <p className="font-medium mb-1">Validation results:</p>
      {details.map((detail, index) => (
        <p key={index} className="text-slate-500 break-words">
          • <span className="font-mono">{detail.file}</span>: {detail.status} — {detail.reason}
        </p>
      ))}
    </div>
  )
}

export default function AutoPRPanel({ scanId, repoUrl, scanType }) {
  const [token, setToken] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  // Only show for scans that have code findings
  if (scanType === 'web') return null

  const handleCreatePR = async () => {
    setError('')
    setResult(null)

    if (!token.trim()) {
      setError('GitHub token is required')
      return
    }
    if (!repoUrl) {
      setError('No repository URL found for this scan')
      return
    }

    setLoading(true)
    try {
      const res = await fetch('/api/pr/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_id: scanId,
          github_token: token.trim(),
          repo_url: repoUrl
        })
      })

      const data = await res.json()

      if (!res.ok) {
        setError(data.detail || 'Failed to create PR')
        return
      }

      setResult(data)

    } catch {
      setError('Network error — is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-surface border border-slate-700 rounded-xl overflow-hidden mb-6">

      {/* Header */}
      <div className="flex items-center gap-3 p-4 border-b border-slate-700">
        <div className="bg-purple-500/20 p-2 rounded-lg">
          <GitPullRequest size={18} className="text-purple-400" />
        </div>
        <div>
          <h3 className="font-semibold text-white text-sm">
            Auto-Fix Pull Request
          </h3>
          <p className="text-xs text-slate-400">
            Apply AI-generated fixes directly to your repository
          </p>
        </div>
      </div>

      <div className="p-4">

        {/* Success state */}
        {result?.success && (
          <div className="bg-green-500/10 border border-green-500/30
                          rounded-xl p-4 mb-4">
            <div className="flex items-center gap-2 mb-3">
              <CheckCircle size={18} className="text-green-400" />
              <span className="font-semibold text-green-400">
                PR Created Successfully!
              </span>
            </div>

            {/* PR Link */}
            <a
              href={result.pr_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 bg-green-500 hover:bg-green-400
                         text-white font-bold px-4 py-2.5 rounded-lg
                         transition-colors w-full justify-center mb-3"
            >
              <ExternalLink size={16} />
              View Pull Request #{result.pr_number} on GitHub
            </a>

            {/* Stats */}
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="bg-green-500/10 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-green-400">
                  {result.fixes_applied}
                </p>
                <p className="text-xs text-slate-400">Fixes Applied</p>
              </div>
              <div className="bg-yellow-500/10 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-yellow-400">
                  {result.fixes_skipped}
                </p>
                <p className="text-xs text-slate-400">Manual Review</p>
              </div>
            </div>

            {/* Skipped details */}
            {result.skipped_details?.length > 0 && (
              <div className="mt-3 text-xs text-slate-400">
                <p className="font-medium mb-1">
                  Not applied — manual review required:
                </p>
                {result.skipped_details.map((s, i) => (
                  <p key={i} className="text-slate-500 break-words">
                    • {s.vuln_type} ({s.status || 'manual_review'}): {s.reason}
                  </p>
                ))}
              </div>
            )}

            <ValidationDetails details={result.validation_details} />
          </div>
        )}

        {/* Error state */}
        {(result && !result.success) && (
          <div className="bg-red-500/10 border border-red-500/30
                          rounded-xl p-4 mb-4">
            <div className="flex items-center gap-2 mb-2">
              <XCircle size={16} className="text-red-400" />
              <span className="font-semibold text-red-400 text-sm">
                PR Creation Failed
              </span>
            </div>
            <p className="text-xs text-red-300">{result.error}</p>
            {result.skipped_details?.length > 0 && (
              <div className="mt-3 text-xs text-red-200">
                {result.skipped_details.map((s, i) => (
                  <p key={i} className="break-words">
                    • {s.vuln_type} ({s.status || 'manual_review'}): {s.reason}
                  </p>
                ))}
              </div>
            )}
            <ValidationDetails details={result.validation_details} />
          </div>
        )}

        {/* API error */}
        {error && !result && (
          <div className="bg-red-500/10 border border-red-500/30
                          rounded-lg px-3 py-2 mb-3">
            <p className="text-xs text-red-400">{error}</p>
          </div>
        )}

        {/* Input form (hide after success) */}
        {!result?.success && (
          <>
            {/* Info note */}
            <div className="flex gap-2 bg-blue-500/10 border border-blue-500/20
                            rounded-lg p-3 mb-3">
              <Info size={14} className="text-blue-400 flex-shrink-0 mt-0.5" />
              <p className="text-xs text-blue-300 leading-relaxed">
                Needs a GitHub token with <strong>repo</strong> write access.
                Create one at{' '}
                <a href="https://github.com/settings/tokens"
                   target="_blank" rel="noopener noreferrer"
                   className="underline hover:text-blue-200">
                  github.com/settings/tokens
                </a>
                . Your token is never stored — used once and discarded.
              </p>
            </div>

            {/* Token input */}
            <div className="relative mb-3">
              <input
                type={showToken ? 'text' : 'password'}
                placeholder="ghp_your_github_personal_access_token"
                value={token}
                onChange={e => setToken(e.target.value)}
                className="w-full bg-slate-800 border border-slate-600 rounded-xl
                           px-4 py-3 pr-10 text-white placeholder-slate-500 text-sm
                           focus:outline-none focus:border-purple-500 transition-colors
                           font-mono"
              />
              <button
                onClick={() => setShowToken(!showToken)}
                className="absolute right-3 top-3.5 text-slate-400
                           hover:text-slate-200 transition-colors"
              >
                {showToken
                  ? <EyeOff size={16} />
                  : <Eye size={16} />
                }
              </button>
            </div>

            {/* Repo URL display */}
            {repoUrl && (
              <p className="text-xs text-slate-500 mb-3 font-mono truncate">
                Target: {repoUrl}
              </p>
            )}

            {/* Submit button */}
            <button
              onClick={handleCreatePR}
              disabled={loading || !token.trim()}
              className="w-full bg-purple-600 hover:bg-purple-500 disabled:opacity-50
                         disabled:cursor-not-allowed text-white font-bold py-2.5
                         rounded-xl transition-colors flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Creating PR...
                </>
              ) : (
                <>
                  <GitPullRequest size={16} />
                  Create Fix PR
                </>
              )}
            </button>
          </>
        )}
      </div>
    </div>
  )
}
