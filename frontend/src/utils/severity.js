/**
 * Severity display utilities
 * Centralizes color/label logic so it's consistent everywhere
 */

export const SEVERITY_COLORS = {
  CRITICAL: {
    bg: 'bg-rose-500/15',
    border: 'border-rose-400/60',
    text: 'text-rose-300',
    badge: 'bg-rose-500/15 border border-rose-400/50 text-rose-200 shadow-glow-critical',
    hex: '#f43f5e'
  },
  HIGH: {
    bg: 'bg-orange-500/15',
    border: 'border-orange-400/60',
    text: 'text-orange-300',
    badge: 'bg-orange-500/15 border border-orange-400/50 text-orange-200',
    hex: '#f97316'
  },
  MEDIUM: {
    bg: 'bg-amber-500/15',
    border: 'border-amber-400/60',
    text: 'text-amber-300',
    badge: 'bg-amber-500/15 border border-amber-400/50 text-amber-200',
    hex: '#f59e0b'
  },
  LOW: {
    bg: 'bg-emerald-500/15',
    border: 'border-emerald-400/60',
    text: 'text-emerald-300',
    badge: 'bg-emerald-500/15 border border-emerald-400/50 text-emerald-200',
    hex: '#22c55e'
  },
  INFO: {
    bg: 'bg-sky-500/15',
    border: 'border-sky-400/60',
    text: 'text-sky-300',
    badge: 'bg-sky-500/15 border border-sky-400/50 text-sky-200',
    hex: '#38bdf8'
  }
}

export const getSeverityColors = (severity) =>
  SEVERITY_COLORS[severity?.toUpperCase()] || SEVERITY_COLORS.INFO

export const cvssToSeverity = (score) => {
  if (score >= 9.0) return 'CRITICAL'
  if (score >= 7.0) return 'HIGH'
  if (score >= 4.0) return 'MEDIUM'
  if (score > 0.0)  return 'LOW'
  return 'INFO'
}

export const cvssColor = (score) => {
  if (score >= 9.0) return '#f43f5e'
  if (score >= 7.0) return '#f97316'
  if (score >= 4.0) return '#f59e0b'
  return '#22c55e'
}
