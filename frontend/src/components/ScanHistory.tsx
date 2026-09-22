import { type FC } from 'react'
import type { ScanHistoryItem } from '../api'
import { getThreatBand, formatRelative } from '../utils'
import { Trash2 } from 'lucide-react'

interface Props {
  items: ScanHistoryItem[]
  onSelect: (id: string) => void
  onDelete: (id: string) => void
  loading: boolean
}

const ScanHistory: FC<Props> = ({ items, onSelect, onDelete, loading }) => {
  if (loading) return <p className="text-xs text-slate-500 text-center py-4">Loading history…</p>

  if (items.length === 0)
    return <p className="text-xs text-slate-500 text-center py-4">No scans yet. Run your first scan above.</p>

  return (
    <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
      {items.map((item) => {
        const band = getThreatBand(item.threat_index)
        return (
          <div
            key={item.scan_id}
            className="flex items-center gap-2 p-2 rounded-lg bg-slate-800/60 hover:bg-slate-700/60 cursor-pointer transition-colors border border-slate-700/50 group"
            onClick={() => onSelect(item.scan_id)}
          >
            <span className="text-base">{band.emoji}</span>
            <div className="flex-1 min-w-0">
              <p className={`text-xs font-semibold ${band.color}`}>
                {item.threat_index.toFixed(0)}/100 — {band.label}
              </p>
              <p className="text-xs text-slate-500 truncate">
                {item.source_name ?? item.input_type.toUpperCase()}
                {item.domain ? ` · @${item.domain}` : ''}
              </p>
            </div>
            <div className="flex flex-col items-end gap-1">
              <span className="text-xs text-slate-600">{formatRelative(item.created_at)}</span>
              <span className="text-xs text-slate-600">{item.signal_count} signals</span>
            </div>
            <button
              onClick={(e) => { e.stopPropagation(); onDelete(item.scan_id) }}
              className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:text-red-400 text-slate-600"
              title="Delete scan"
            >
              <Trash2 size={12} />
            </button>
          </div>
        )
      })}
    </div>
  )
}

export default ScanHistory
