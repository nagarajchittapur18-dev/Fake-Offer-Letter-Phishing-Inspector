import React, { useEffect, useState } from 'react'

// Scanning status steps with realistic timing
const STEPS = [
  { label: 'Parsing Document',         ms: 800  },
  { label: 'Checking Domain WHOIS',    ms: 2000 },
  { label: 'Running Heuristic Scan',   ms: 1200 },
  { label: 'Running Gemini Analysis',  ms: 0    },  // stays until complete
]

export const ScanningOverlay: React.FC = () => {
  const [step, setStep] = useState(0)

  useEffect(() => {
    let t: ReturnType<typeof setTimeout>
    const advance = (i: number) => {
      if (i >= STEPS.length - 1) return
      t = setTimeout(() => { setStep(i + 1); advance(i + 1) }, STEPS[i].ms)
    }
    advance(0)
    return () => clearTimeout(t)
  }, [])

  return (
    <div className="flex flex-col items-center gap-5 py-6">
      {/* Pulsing radar rings */}
      <div className="relative w-16 h-16 flex items-center justify-center">
        <div className="absolute w-16 h-16 rounded-full border border-violet-500 opacity-30 animate-ping" />
        <div className="absolute w-12 h-12 rounded-full border border-violet-500 opacity-50 animate-ping"
          style={{ animationDelay: '0.3s' }} />
        <div className="w-8 h-8 rounded-full bg-violet-600 flex items-center justify-center shadow-lg shadow-violet-900/50">
          <svg viewBox="0 0 24 24" className="w-4 h-4 text-white animate-spin" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
          </svg>
        </div>
      </div>

      {/* Step list */}
      <div className="space-y-2 w-full max-w-xs">
        {STEPS.map((s, i) => (
          <div key={i} className={`flex items-center gap-3 text-sm transition-all duration-500
            ${i < step ? 'text-green-400' : i === step ? 'text-violet-300' : 'text-slate-600'}`}>
            <span className={`w-4 h-4 rounded-full border flex items-center justify-center flex-shrink-0 text-[10px] font-bold
              ${i < step  ? 'bg-green-500 border-green-500 text-white'
              : i === step ? 'border-violet-500 text-violet-400 animate-pulse'
              : 'border-slate-700 text-slate-700'}`}>
              {i < step ? '✓' : i + 1}
            </span>
            {s.label}
            {i === step && <span className="text-xs text-violet-500 animate-pulse ml-auto">running…</span>}
            {i < step  && <span className="text-xs text-green-600 ml-auto">done</span>}
          </div>
        ))}
      </div>
    </div>
  )
}
