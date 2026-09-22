import { type FC } from 'react'
import type { RiskSignal } from '../api'
import { SEVERITY_STYLES } from '../utils'

interface Props {
  signal: RiskSignal
}

const EvidenceCard: FC<Props> = ({ signal }) => {
  const sty = SEVERITY_STYLES[signal.severity]
  return (
    <div className="border border-slate-700 rounded-lg p-3 bg-slate-800/50 space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${sty.badge}`}>
          {signal.severity}
        </span>
        <span className="text-xs text-slate-400 font-medium">{signal.category}</span>
        <span className="ml-auto text-xs text-slate-500">+{signal.score_contribution} pts</span>
      </div>
      <p className="text-xs text-amber-300 italic leading-relaxed font-mono">{signal.evidence}</p>
      <p className="text-xs text-slate-300 leading-relaxed">{signal.explanation}</p>
    </div>
  )
}

export default EvidenceCard
