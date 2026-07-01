/**
 * Severity display utilities
 * Centralizes color/label logic so it's consistent everywhere
 */

export const SEVERITY_COLORS = {
  CRITICAL: {
    bg: 'bg-red-500/20',
    border: 'border-red-500',
    text: 'text-red-400',
    badge: 'bg-red-500',
    hex: '#ef4444'
  },
  HIGH: {
    bg: 'bg-orange-500/20',
    border: 'border-orange-500',
    text: 'text-orange-400',
    badge: 'bg-orange-500',
    hex: '#f97316'
  },
  MEDIUM: {
    bg: 'bg-yellow-500/20',
    border: 'border-yellow-500',
    text: 'text-yellow-400',
    badge: 'bg-yellow-500',
    hex: '#eab308'
  },
  LOW: {
    bg: 'bg-green-500/20',
    border: 'border-green-500',
    text: 'text-green-400',
    badge: 'bg-green-500',
    hex: '#22c55e'
  },
  INFO: {
    bg: 'bg-blue-500/20',
    border: 'border-blue-500',
    text: 'text-blue-400',
    badge: 'bg-blue-500',
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
  if (score >= 9.0) return '#ef4444'
  if (score >= 7.0) return '#f97316'
  if (score >= 4.0) return '#eab308'
  return '#22c55e'
}