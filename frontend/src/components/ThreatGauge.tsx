import React, { useEffect, useState } from 'react'
import type { ScoreBreakdown } from '../api'
import { getThreatBand } from '../utils'

interface ThreatGaugeProps {
  score:     number
  breakdown: ScoreBreakdown
}

// Animated counter hook
function useCounter(target: number, duration = 1200) {
  const [val, setVal] = useState(0)
  useEffect(() => {
    let start: number | null = null
    const step = (ts: number) => {
      if (!start) start = ts
      const progress = Math.min((ts - start) / duration, 1)
      // ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3)
      setVal(Math.round(eased * target))
      if (progress < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
  }, [target, duration])
  return val
}

export const ThreatGauge: React.FC<ThreatGaugeProps> = ({ score, breakdown }) => {
  const band    = getThreatBand(score)
  const display = useCounter(score)

  // Semi-circular SVG gauge
  const radius    = 80
  const cx        = 110
  const cy        = 110
  const startAngle = 180
  const endAngle   = 0
  const totalDeg   = 180
  const fillDeg    = (score / 100) * totalDeg

  const toRad = (deg: number) => (deg * Math.PI) / 180
  const px = (angle: number) => cx + radius * Math.cos(toRad(angle))
  const py = (angle: number) => cy + radius * Math.sin(toRad(angle))

  // Arc from 180° → (180 - fillDeg)°
  const arcEnd  = startAngle - fillDeg
  const large   = fillDeg > 180 ? 1 : 0
  const arcPath = fillDeg > 0
    ? `M ${px(startAngle)} ${py(startAngle)} A ${radius} ${radius} 0 ${large} 1 ${px(arcEnd)} ${py(arcEnd)}`
    : ''

  const components = [
    { label: 'AI Semantic',    value: breakdown.ai_component,           max: 40, color: '#8b5cf6' },
    { label: 'Payment Flags',  value: breakdown.payment_penalty,        max: 30, color: '#ef4444' },
    { label: 'Domain Risk',    value: breakdown.domain_penalty,         max: 30, color: '#f97316' },
    { label: 'Process Bypass', value: breakdown.process_bypass_penalty, max: 10, color: '#eab308' },
  ]

  return (
    <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-6">
      <div className="flex flex-col sm:flex-row items-center gap-8">

        {/* Semi-circular gauge */}
        <div className="relative flex-shrink-0">
          <svg width="220" height="130" viewBox="0 0 220 130">
            {/* Track */}
            <path
              d={`M ${px(startAngle)} ${py(startAngle)} A ${radius} ${radius} 0 0 1 ${px(endAngle)} ${py(endAngle)}`}
              fill="none" stroke="#1e293b" strokeWidth="18" strokeLinecap="round"
            />
            {/* Zone segments  */}
            {[
              { from: 180, to: 180 - 34 * 1.8,   color: '#22c55e33' },
              { from: 180 - 34 * 1.8, to: 180 - 69 * 1.8, color: '#f59e0b33' },
              { from: 180 - 69 * 1.8, to: 0,     color: '#ef444433' },
            ].map((seg, i) => {
              const lf = seg.from - seg.to > 180 ? 1 : 0
              return (
                <path key={i}
                  d={`M ${px(seg.from)} ${py(seg.from)} A ${radius} ${radius} 0 ${lf} 1 ${px(seg.to)} ${py(seg.to)}`}
                  fill="none" stroke={seg.color} strokeWidth="18"
                />
              )
            })}
            {/* Active fill */}
            {arcPath && (
              <path
                d={arcPath}
                fill="none"
                stroke={score >= 70 ? '#ef4444' : score >= 35 ? '#f59e0b' : '#22c55e'}
                strokeWidth="18"
                strokeLinecap="round"
                style={{ transition: 'all 1s cubic-bezier(0.34, 1.56, 0.64, 1)' }}
              />
            )}
          </svg>
          {/* Score label centred below arc midpoint */}
          <div className="absolute inset-0 flex flex-col items-center justify-end pb-1">
            <div className={`text-4xl font-black tabular-nums ${band.color}`}>{display}</div>
            <div className="text-xs text-slate-500 tracking-widest uppercase">/ 100</div>
          </div>
        </div>

        {/* Band label + breakdown bars */}
        <div className="flex-1 w-full space-y-4">
          <div>
            <div className={`text-2xl font-bold ${band.color}`}>{band.emoji} {band.label}</div>
            <p className="text-xs text-slate-500 mt-0.5 uppercase tracking-wider">Scam Threat Index</p>
          </div>

          <div className="space-y-2.5">
            {components.map(c => (
              <div key={c.label} className="flex items-center gap-3 text-sm">
                <span className="w-32 text-slate-400 text-xs flex-shrink-0">{c.label}</span>
                <div className="flex-1 h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${(c.value / c.max) * 100}%`, backgroundColor: c.color }}
                  />
                </div>
                <span className="w-7 text-right text-xs font-mono font-bold"
                  style={{ color: c.value > 0 ? c.color : '#475569' }}>
                  {c.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
