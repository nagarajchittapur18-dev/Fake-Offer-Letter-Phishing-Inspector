import { type FC } from 'react'
import type { HealthResponse } from '../api'

interface Props {
  health: HealthResponse | null
  loading: boolean
}

function Dot({ status }: { status?: string }) {
  if (status === 'online')   return <span className="w-2 h-2 rounded-full bg-green-500 inline-block animate-pulse" />
  if (status === 'degraded') return <span className="w-2 h-2 rounded-full bg-yellow-400 inline-block animate-pulse" />
  return <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />
}

const LABELS: Record<string, string> = {
  gemini_ai:     '🤖 AI Engine',
  domain_lookup: '🌐 Domain Intel',
  ocr:           '📄 OCR',
  database:      '🗄️ History DB',
  pdf_parser:    '📃 PDF Parser',
}

const StatusBar: FC<Props> = ({ health, loading }) => {
  if (loading) {
    return (
      <div className="flex items-center gap-2 text-xs text-slate-500">
        <span className="animate-spin">⚙️</span> Checking system status…
      </div>
    )
  }

  if (!health) {
    return (
      <div className="flex items-center gap-2 text-xs text-red-400">
        <span className="w-2 h-2 rounded-full bg-red-500 inline-block" /> Backend offline
      </div>
    )
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      {Object.entries(health.components).map(([key, comp]) => (
        <div key={key} className="flex items-center gap-1.5 text-xs text-slate-400" title={comp.message}>
          <Dot status={comp.status} />
          <span>{LABELS[key] ?? key}</span>
        </div>
      ))}
      <span className="text-xs text-slate-600 ml-auto">v{health.version}</span>
    </div>
  )
}

export default StatusBar
