import { type FC } from 'react'
import type { ScoreBreakdown } from '../api'

const CATEGORIES: Array<{ key: keyof ScoreBreakdown; label: string; icon: string; max: number }> = [
  { key: 'financial_payment',   label: 'Financial / Payment',   icon: '💰', max: 25 },
  { key: 'urgency_coercion',    label: 'Urgency / Coercion',    icon: '⏰', max: 10 },
  { key: 'recruitment_anomaly', label: 'Recruitment Anomaly',   icon: '🎯', max: 10 },
  { key: 'email_provider',      label: 'Email Provider',        icon: '📧', max: 10 },
  { key: 'org_mismatch',        label: 'Org / Domain Mismatch', icon: '🏢', max: 15 },
  { key: 'domain_intelligence', label: 'Domain Intelligence',   icon: '🌐', max: 15 },
  { key: 'url_risk',            label: 'URL Risk',              icon: '🔗', max: 10 },
  { key: 'ai_semantic',         label: 'AI Semantic',           icon: '🤖', max:  5 },
]

function barColor(pct: number): string {
  if (pct >= 0.8) return 'bg-red-500'
  if (pct >= 0.5) return 'bg-orange-500'
  if (pct >= 0.3) return 'bg-amber-400'
  return 'bg-blue-500'
}

interface Props {
  breakdown: ScoreBreakdown
}

const RiskBreakdown: FC<Props> = ({ breakdown }) => (
  <div className="space-y-2">
    {CATEGORIES.map(({ key, label, icon, max }) => {
      const val = Number(breakdown[key]) || 0
      const pct = max > 0 ? val / max : 0
      return (
        <div key={key} className="flex items-center gap-2">
          <span className="text-sm w-4">{icon}</span>
          <span className="text-xs text-slate-400 w-36 shrink-0">{label}</span>
          <div className="flex-1 h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${barColor(pct)}`}
              style={{ width: `${pct * 100}%` }}
            />
          </div>
          <span className="text-xs text-slate-400 w-12 text-right shrink-0">
            {val}<span className="text-slate-600">/{max}</span>
          </span>
        </div>
      )
    })}
    <div className="pt-2 border-t border-slate-700 flex justify-between">
      <span className="text-xs font-semibold text-slate-300">TOTAL THREAT INDEX</span>
      <span className="text-sm font-bold text-white">{breakdown.total.toFixed(0)}<span className="text-slate-500">/100</span></span>
    </div>
  </div>
)

export default RiskBreakdown
