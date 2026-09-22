import { type FC } from 'react'
import { Shield } from 'lucide-react'

const ScanningOverlay: FC = () => (
  <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex flex-col items-center justify-center z-50 gap-6">
    <div className="relative">
      <Shield size={64} className="text-blue-400 animate-pulse" />
      <span className="absolute inset-0 flex items-center justify-center text-2xl">🔍</span>
    </div>
    <div className="text-center space-y-2">
      <p className="text-lg font-bold text-white">Analysing Document…</p>
      <p className="text-sm text-slate-400">Running heuristics, domain lookup, and AI analysis</p>
    </div>
    <div className="flex gap-1.5">
      {[0, 1, 2].map(i => (
        <span
          key={i}
          className="w-2 h-2 rounded-full bg-blue-500 animate-bounce"
          style={{ animationDelay: `${i * 0.15}s` }}
        />
      ))}
    </div>
  </div>
)

export default ScanningOverlay
