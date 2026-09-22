import React from 'react'
import type { Flag } from '../api'
import { SEVERITY_STYLES } from '../utils'

interface FlagCardProps {
  flag: Flag
}

export const FlagCard: React.FC<FlagCardProps> = ({ flag }) => {
  const styles = SEVERITY_STYLES[flag.severity]
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-800/60 p-4 flex gap-3">
      <div className="mt-1 flex-shrink-0">
        <span className={`inline-block w-2.5 h-2.5 rounded-full ${styles.dot}`} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex flex-wrap items-center gap-2 mb-1">
          <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${styles.badge}`}>
            {flag.severity}
          </span>
          <span className="text-sm font-medium text-slate-200">{flag.category}</span>
        </div>
        <p className="text-sm text-slate-400 italic leading-relaxed">
          &ldquo;{flag.evidence}&rdquo;
        </p>
      </div>
    </div>
  )
}
