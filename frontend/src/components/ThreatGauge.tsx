import { type FC } from 'react'

interface Props {
  score: number
  size?: number
}

const ThreatGauge: FC<Props> = ({ score, size = 140 }) => {
  const r     = 54
  const cx    = 80
  const cy    = 80
  const half  = Math.PI * r      // semi-circle arc length
  const progress = Math.min(score / 100, 1) * half

  const strokeColor =
    score >= 75 ? '#ef4444' :
    score >= 50 ? '#f97316' :
    score >= 25 ? '#f59e0b' :
                  '#22c55e'

  return (
    <svg width={size} height={size * 0.6} viewBox="0 0 160 96" className="overflow-visible">
      {/* Background arc */}
      <path
        d={`M ${cx - r},${cy} a ${r},${r} 0 0,1 ${r * 2},0`}
        fill="none" stroke="#1e293b" strokeWidth="12" strokeLinecap="round"
      />
      {/* Progress arc */}
      <path
        d={`M ${cx - r},${cy} a ${r},${r} 0 0,1 ${r * 2},0`}
        fill="none"
        stroke={strokeColor}
        strokeWidth="12"
        strokeLinecap="round"
        strokeDasharray={`${progress} ${half - progress}`}
        className="transition-all duration-700"
      />
      {/* Score */}
      <text x={cx} y={cy - 2} textAnchor="middle" fill="white" fontSize="26" fontWeight="bold" fontFamily="monospace">
        {score.toFixed(0)}
      </text>
      <text x={cx} y={cy + 14} textAnchor="middle" fill="#94a3b8" fontSize="9" fontFamily="sans-serif">
        OUT OF 100
      </text>
    </svg>
  )
}

export default ThreatGauge
