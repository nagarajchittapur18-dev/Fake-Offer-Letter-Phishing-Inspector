import React from 'react'
import type { DomainDetails as DDType } from '../api'
import { Globe, Calendar, Clock, AlertTriangle, CheckCircle } from 'lucide-react'
import { formatDate } from '../utils'

interface DomainDetailsProps {
  details: DDType
}

export const DomainDetailsPanel: React.FC<DomainDetailsProps> = ({ details }) => {
  const isRisky = details.penalty >= 15

  return (
    <div className="rounded-2xl border border-slate-700 bg-slate-800/80 p-5 space-y-4">
      <div className="flex items-center gap-2">
        <Globe className="w-4 h-4 text-slate-400" />
        <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">Domain Intelligence</h3>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {/* Domain name */}
        <div className="rounded-xl bg-slate-900/60 border border-slate-700 p-3">
          <div className="text-xs text-slate-500 mb-1">Domain</div>
          <div className="text-sm font-mono text-slate-200 truncate">
            {details.domain ?? '—'}
          </div>
        </div>

        {/* Registration date */}
        <div className="rounded-xl bg-slate-900/60 border border-slate-700 p-3">
          <div className="flex items-center gap-1 text-xs text-slate-500 mb-1">
            <Calendar className="w-3 h-3" /> Registered
          </div>
          <div className="text-sm font-medium text-slate-200">
            {formatDate(details.creation_date)}
          </div>
        </div>

        {/* Age */}
        <div className="rounded-xl bg-slate-900/60 border border-slate-700 p-3">
          <div className="flex items-center gap-1 text-xs text-slate-500 mb-1">
            <Clock className="w-3 h-3" /> Age
          </div>
          <div className={`text-sm font-bold ${
            details.age_in_days == null         ? 'text-slate-400'
            : details.age_in_days < 30         ? 'text-red-400'
            : details.age_in_days < 90         ? 'text-yellow-400'
            : 'text-green-400'
          }`}>
            {details.age_in_days != null ? `${details.age_in_days} days` : 'Unknown'}
          </div>
        </div>
      </div>

      {/* Risk indicator */}
      <div className={`flex items-start gap-2 rounded-lg px-3 py-2 text-sm
        ${isRisky ? 'bg-red-900/30 border border-red-800 text-red-300' : 'bg-green-900/30 border border-green-800 text-green-300'}`}>
        {isRisky
          ? <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          : <CheckCircle   className="w-4 h-4 mt-0.5 flex-shrink-0" />}
        <span>
          {isRisky
            ? `Domain risk penalty: +${details.penalty} pts — recently registered or suspicious TLD.`
            : `Domain age looks legitimate. Penalty: ${details.penalty} pts.`}
        </span>
      </div>
    </div>
  )
}
