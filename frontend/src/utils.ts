import type { Severity } from './api'

// ── Colour helpers keyed by severity ─────────────────────────────────────────

export const SEVERITY_STYLES: Record<Severity, { badge: string; dot: string }> = {
  Critical: {
    badge: 'bg-red-900/60 text-red-300 border border-red-700',
    dot:   'bg-red-500',
  },
  High: {
    badge: 'bg-orange-900/60 text-orange-300 border border-orange-700',
    dot:   'bg-orange-400',
  },
  Medium: {
    badge: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700',
    dot:   'bg-yellow-400',
  },
  Low: {
    badge: 'bg-blue-900/60 text-blue-300 border border-blue-700',
    dot:   'bg-blue-400',
  },
}

// ── Threat band helpers ───────────────────────────────────────────────────────

export interface ThreatBand {
  label:    string
  color:    string       // Tailwind text colour class
  barColor: string       // Tailwind bg colour class for gauge bar
  emoji:    string
  border:   string
}

export function getThreatBand(score: number): ThreatBand {
  if (score >= 70) return { label: 'Critical Fraud Detected',  color: 'text-red-400',    barColor: 'bg-red-500',    emoji: '🚨', border: 'border-red-500' }
  if (score >= 35) return { label: 'Suspicious / Elevated Risk', color: 'text-amber-400', barColor: 'bg-amber-400', emoji: '⚠️', border: 'border-amber-400' }
  return              { label: 'Verified Safe',              color: 'text-green-400',  barColor: 'bg-green-500',  emoji: '✅', border: 'border-green-500' }
}

export function formatDate(iso: string | null): string {
  if (!iso) return 'Unknown'
  return new Date(iso).toLocaleDateString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
  })
}
