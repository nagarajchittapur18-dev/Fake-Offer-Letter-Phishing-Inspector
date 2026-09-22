import { type FC } from 'react'
import type { DomainIntelligence as DomainIntelligenceType } from '../api'
import { formatDate } from '../utils'

interface Props {
  intel: DomainIntelligenceType
}

function AgeBadge({ days }: { days: number | null }) {
  if (days === null) return <span className="text-slate-500 text-xs">Unknown</span>
  if (days < 30)  return <span className="text-xs font-semibold text-red-400">{days}d 🔴 Very New</span>
  if (days < 90)  return <span className="text-xs font-semibold text-orange-400">{days}d 🟠 Recent</span>
  if (days < 365) return <span className="text-xs font-semibold text-amber-400">{days}d 🟡 &lt;1yr</span>
  return <span className="text-xs font-semibold text-green-400">{Math.floor(days / 365)}yr {days % 365}d 🟢 Established</span>
}

const DomainIntelligence: FC<Props> = ({ intel }) => (
  <div className="space-y-2">
    <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
      <span className="text-slate-400">Domain</span>
      <span className="text-slate-200 font-mono">{intel.domain ?? '—'}</span>

      <span className="text-slate-400">Provider Type</span>
      <span className={intel.provider_type === 'Free Email Provider' ? 'text-red-400 font-semibold' : 'text-slate-200'}>
        {intel.provider_type}
      </span>

      <span className="text-slate-400">Registrar</span>
      <span className="text-slate-200">{intel.registrar ?? 'Unknown'}</span>

      <span className="text-slate-400">Registered</span>
      <span className="text-slate-200">{formatDate(intel.created)}</span>

      <span className="text-slate-400">Age</span>
      <AgeBadge days={intel.age_days} />

      <span className="text-slate-400">Risk Score</span>
      <span className={`font-semibold ${intel.score_contribution >= 10 ? 'text-red-400' : intel.score_contribution >= 5 ? 'text-amber-400' : 'text-green-400'}`}>
        +{intel.score_contribution} pts
      </span>
    </div>

    {intel.notes.length > 0 && (
      <div className="border-t border-slate-700 pt-2 space-y-1">
        {intel.notes.map((n, i) => (
          <p key={i} className="text-xs text-slate-400 leading-relaxed">⚠ {n}</p>
        ))}
      </div>
    )}
  </div>
)

export default DomainIntelligence
