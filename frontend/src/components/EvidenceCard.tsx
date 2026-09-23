import { type FC, useState } from 'react'
import type { RiskSignal } from '../api'
import { SEVERITY_STYLES } from '../utils'

interface Props {
  signal: RiskSignal
}

const EVIDENCE_TRUNCATE = 120

const EvidenceCard: FC<Props> = ({ signal }) => {
  const sty = SEVERITY_STYLES[signal.severity]
  const [expanded, setExpanded] = useState(false)

  const raw     = signal.evidence.replace(/^"|"$/g, '')   // strip outer quotes
  const isLong  = raw.length > EVIDENCE_TRUNCATE
  const display = !isLong || expanded ? raw : raw.slice(0, EVIDENCE_TRUNCATE).trimEnd() + '…'

  return (
    <div className="border border-slate-700 rounded-lg p-3 bg-slate-800/50 space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${sty.badge}`}>
          {signal.severity}
        </span>
        <span className="ml-auto text-xs text-slate-500">+{signal.score_contribution} pts</span>
      </div>
      {/* Evidence quote */}
      <div className="text-xs text-amber-300/90 italic leading-relaxed font-mono bg-slate-900/60 rounded px-2 py-1.5">
        "{display}"
        {isLong && (
          <button
            onClick={() => setExpanded(e => !e)}
            className="ml-1.5 text-slate-500 hover:text-slate-300 not-italic font-sans"
          >
            {expanded ? 'Show less' : 'Show more'}
          </button>
        )}
      </div>
      {/* Explanation */}
      <p className="text-xs text-slate-300 leading-relaxed">{signal.explanation}</p>
    </div>
  )
}

export default EvidenceCard
