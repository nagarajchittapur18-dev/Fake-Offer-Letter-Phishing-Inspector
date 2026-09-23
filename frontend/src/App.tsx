import { useState, useEffect, useCallback } from 'react'
import { Shield, History, FileText, Download, X, ChevronDown, ChevronUp, CheckSquare, Cpu } from 'lucide-react'
import type { ScanResponse, HealthResponse, ScanHistoryItem } from './api'
import {
  getHealth, scanText, scanFile, getScanHistory, deleteScan, reportUrl
} from './api'
import { getThreatBand, PRESETS } from './utils'
import ThreatGauge        from './components/ThreatGauge'
import RiskBreakdown      from './components/RiskBreakdown'
import EvidenceCard       from './components/EvidenceCard'
import StatusBar          from './components/StatusBar'
import DomainIntelligence from './components/DomainIntelligence'
import ScanHistory        from './components/ScanHistory'
import FileDropZone       from './components/FileDropZone'
import ScanningOverlay    from './components/ScanningOverlay'

// ── Detection engine registry ──────────────────────────────────────────────────
const ENGINES = [
  { key: 'rule_engine',    label: 'Rule Engine',              icon: '⚙️', always: true },
  { key: 'payment',        label: 'Payment Detection',        icon: '💰', always: true },
  { key: 'recruitment',    label: 'Recruitment Detection',    icon: '🎯', always: true },
  { key: 'urgency',        label: 'Urgency Detection',        icon: '⏰', always: true },
  { key: 'email',          label: 'Email Analysis',           icon: '📧', always: true },
  { key: 'domain_lookup',  label: 'Domain Intelligence',      icon: '🌐', always: false, healthKey: 'domain_lookup' },
  { key: 'url',            label: 'URL Analysis',             icon: '🔗', always: true },
  { key: 'ocr',            label: 'OCR (Scanned PDFs)',       icon: '📄', always: false, healthKey: 'ocr' },
  { key: 'gemini_ai',      label: 'Gemini Semantic Analysis', icon: '🤖', always: false, healthKey: 'gemini_ai' },
]

// ── Verification checklist items ───────────────────────────────────────────────
const CHECKLIST = [
  'Visit the company\'s official website directly (do not click links in the document).',
  'Search for the recruiter\'s name and profile on the company\'s official LinkedIn page.',
  'Confirm the job posting exists on the company\'s official careers portal.',
  'Verify the sender\'s email domain matches the company\'s domain exactly.',
  'Call the company\'s publicly listed phone number to confirm the offer.',
  'Never deposit unexpected cheques, cashier\'s cheques, or money orders.',
  'Never send money, gift cards, or cryptocurrency to a recruiter for any reason.',
  'Do not share banking credentials, SSN, or passport details before formal onboarding.',
  'Avoid clicking payment, login, or document-signing links in unsolicited emails.',
]

export default function App() {
  // ── Input ──────────────────────────────────────────────────────────────────
  const [text,        setText]        = useState('')
  const [senderEmail, setSenderEmail] = useState('')

  // ── App state ──────────────────────────────────────────────────────────────
  const [scanning,    setScanning]    = useState(false)
  const [result,      setResult]      = useState<ScanResponse | null>(null)
  const [error,       setError]       = useState<string | null>(null)

  // ── Health ─────────────────────────────────────────────────────────────────
  const [health,          setHealth]         = useState<HealthResponse | null>(null)
  const [healthLoading,   setHealthLoading]  = useState(true)

  // ── History ────────────────────────────────────────────────────────────────
  const [history,         setHistory]        = useState<ScanHistoryItem[]>([])
  const [historyLoading,  setHistoryLoading] = useState(false)
  const [showHistory,     setShowHistory]    = useState(false)

  // ── Collapsible sections ───────────────────────────────────────────────────
  const [showBreakdown,   setShowBreakdown]  = useState(true)
  const [showWhyScore,    setShowWhyScore]   = useState(false)
  const [showSignals,     setShowSignals]    = useState(true)
  const [showDomain,      setShowDomain]     = useState(true)
  const [showAI,          setShowAI]         = useState(true)
  const [showEngines,     setShowEngines]    = useState(false)
  const [showChecklist,   setShowChecklist]  = useState(false)
  const [showRecs,        setShowRecs]       = useState(true)

  // ── Boot ───────────────────────────────────────────────────────────────────
  useEffect(() => {
    getHealth()
      .then(h => { setHealth(h); setHealthLoading(false) })
      .catch(() => setHealthLoading(false))
  }, [])

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true)
    try { setHistory(await getScanHistory()) }
    finally { setHistoryLoading(false) }
  }, [])

  useEffect(() => { if (showHistory) loadHistory() }, [showHistory, loadHistory])

  // ── Scan handlers ──────────────────────────────────────────────────────────
  async function handleScanText() {
    if (!text.trim()) return
    setError(null); setScanning(true)
    try {
      const r = await scanText(text.trim(), senderEmail.trim() || undefined)
      setResult(r)
      setShowBreakdown(true); setShowSignals(true); setShowRecs(true); setShowAI(true)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Scan failed')
    } finally {
      setScanning(false)
    }
  }

  async function handleScanFile(file: File) {
    setError(null); setScanning(true)
    try {
      const r = await scanFile(file)
      setResult(r)
      setShowBreakdown(true); setShowSignals(true); setShowRecs(true); setShowAI(true)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'File scan failed')
    } finally {
      setScanning(false)
    }
  }

  async function handleDeleteHistory(id: string) {
    await deleteScan(id)
    setHistory(h => h.filter(i => i.scan_id !== id))
  }

  async function handleSelectHistory(id: string) {
    try {
      const resp = await fetch(`${reportUrl(id).replace('/report/', '/scans/')}`)
      if (resp.ok) setResult(await resp.json())
    } catch { /* ignore */ }
    setShowHistory(false)
  }

  // ── Helpers ────────────────────────────────────────────────────────────────
  const band = result ? getThreatBand(result.threat_index) : null

  /** Group risk signals by category for display */
  function groupSignals(signals: ScanResponse['risk_signals']) {
    const groups: Record<string, typeof signals> = {}
    for (const sig of signals) {
      if (!groups[sig.category]) groups[sig.category] = []
      groups[sig.category].push(sig)
    }
    return groups
  }

  function engineStatus(engineKey: string): 'ready' | 'unavailable' {
    if (!health) return 'unavailable'
    const comp = health.components[engineKey]
    if (!comp) return 'ready'  // rule-engine etc are always ready if backend is up
    return comp.status === 'online' ? 'ready' : 'unavailable'
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      {scanning && <ScanningOverlay />}

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center gap-3">
          <Shield size={20} className="text-blue-400" />
          <span className="font-bold text-base tracking-tight">
            Phishing <span className="text-blue-400">&</span> Fraud Inspector
          </span>
          <span className="text-xs text-slate-500 border border-slate-700 rounded px-1.5 py-0.5">V2</span>
          <div className="flex-1" />
          <div className="hidden md:flex">
            <StatusBar health={health} loading={healthLoading} />
          </div>
          <button
            onClick={() => setShowHistory(h => !h)}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 px-2 py-1.5 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <History size={14} /> History
          </button>
        </div>
      </header>

      {/* ── History panel ──────────────────────────────────────────────────── */}
      {showHistory && (
        <div className="border-b border-slate-800 bg-slate-900">
          <div className="max-w-7xl mx-auto px-4 py-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                <History size={14} /> Scan History
              </h2>
              <button onClick={() => setShowHistory(false)}>
                <X size={14} className="text-slate-500 hover:text-slate-300" />
              </button>
            </div>
            <ScanHistory
              items={history}
              onSelect={handleSelectHistory}
              onDelete={handleDeleteHistory}
              loading={historyLoading}
            />
          </div>
        </div>
      )}

      {/* ── Main ───────────────────────────────────────────────────────────── */}
      <main className="max-w-7xl mx-auto px-4 py-6 grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* ════════ LEFT — Input ════════════════════════════════════════════ */}
        <section className="flex flex-col gap-4">

          {/* Presets */}
          <div className="flex flex-wrap gap-2">
            {PRESETS.map(p => (
              <button key={p.label} onClick={() => setText(p.text)}
                className="flex items-center gap-1 text-xs bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-full px-3 py-1 transition-colors">
                <span>{p.icon}</span> {p.label}
              </button>
            ))}
          </div>

          {/* Text input card */}
          <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
            <div className="flex items-center justify-between px-3 py-2 border-b border-slate-800">
              <span className="text-xs text-slate-400 font-medium flex items-center gap-1.5">
                <FileText size={12} /> Offer Letter / Email / Document Text
              </span>
              {text && (
                <button onClick={() => { setText(''); setSenderEmail(''); setResult(null); setError(null) }}
                  className="text-xs text-slate-500 hover:text-slate-300">Clear</button>
              )}
            </div>
            <textarea
              value={text}
              onChange={e => setText(e.target.value)}
              placeholder="Paste the offer letter, email, or suspicious document text here…"
              rows={12}
              className="w-full bg-transparent text-sm text-slate-200 placeholder-slate-600 px-3 py-2.5 resize-none focus:outline-none"
            />
            <div className="border-t border-slate-800 px-3 py-2 flex items-center gap-3">
              <input
                value={senderEmail}
                onChange={e => setSenderEmail(e.target.value)}
                placeholder="Sender email (optional)"
                className="flex-1 bg-slate-800 text-xs text-slate-300 rounded-lg px-3 py-1.5 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
              <span className="text-xs text-slate-600">{text.length.toLocaleString()} chars</span>
            </div>
          </div>

          {/* Scan button */}
          <button onClick={handleScanText} disabled={!text.trim() || scanning}
            className={`w-full py-3 rounded-xl font-bold text-sm tracking-wide transition-all ${
              text.trim() && !scanning
                ? 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-900/50'
                : 'bg-slate-800 text-slate-600 cursor-not-allowed'
            }`}>
            {scanning ? '🔍 Analysing…' : '🛡️ Scan for Fraud'}
          </button>

          {/* File drop */}
          <div className="space-y-1">
            <p className="text-xs text-slate-500 text-center">— or upload a file —</p>
            <FileDropZone onFile={handleScanFile} disabled={scanning} />
          </div>

          {/* Error */}
          {error && (
            <div className="border border-red-800 bg-red-950/40 rounded-xl px-4 py-3 text-sm text-red-300">
              <strong>Error:</strong> {error}
            </div>
          )}

          {/* ── Detection Engines Panel ─────────────────────────────────── */}
          <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
            <button onClick={() => setShowEngines(e => !e)}
              className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/50 transition-colors">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Cpu size={12} /> Detection Engines
              </span>
              {showEngines ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
            </button>
            {showEngines && (
              <div className="px-4 pb-4 pt-1 grid grid-cols-1 gap-1.5">
                {ENGINES.map(eng => {
                  const status = eng.always ? 'ready' : engineStatus(eng.healthKey ?? eng.key)
                  return (
                    <div key={eng.key} className="flex items-center gap-2 text-xs">
                      <span className={`w-2 h-2 rounded-full shrink-0 ${status === 'ready' ? 'bg-green-500' : 'bg-slate-600'}`} />
                      <span className="mr-1">{eng.icon}</span>
                      <span className={status === 'ready' ? 'text-slate-300' : 'text-slate-600'}>{eng.label}</span>
                      <span className={`ml-auto font-medium ${status === 'ready' ? 'text-green-500' : 'text-slate-600'}`}>
                        {status === 'ready' ? 'Ready' : 'Unavailable'}
                      </span>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* ── Verification Checklist ──────────────────────────────────── */}
          <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
            <button onClick={() => setShowChecklist(c => !c)}
              className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/50 transition-colors">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <CheckSquare size={12} /> Independent Verification Checklist
              </span>
              {showChecklist ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
            </button>
            {showChecklist && (
              <div className="px-4 pb-4 pt-1 space-y-1.5">
                {CHECKLIST.map((item, i) => (
                  <label key={i} className="flex items-start gap-2 text-xs text-slate-300 leading-relaxed cursor-pointer group">
                    <input type="checkbox" className="mt-0.5 accent-blue-500 shrink-0" />
                    <span className="group-hover:text-slate-100 transition-colors">{item}</span>
                  </label>
                ))}
              </div>
            )}
          </div>

          {/* Mobile status */}
          <div className="md:hidden border border-slate-800 rounded-xl bg-slate-900 p-3">
            <StatusBar health={health} loading={healthLoading} />
          </div>
        </section>

        {/* ════════ RIGHT — Results ══════════════════════════════════════════ */}
        <section className="flex flex-col gap-4">
          {!result ? (
            <div className="flex-1 flex flex-col items-center justify-center text-center py-16 gap-4">
              <Shield size={48} className="text-slate-700" />
              <p className="text-slate-500 text-sm">Scan results will appear here</p>
              <p className="text-slate-600 text-xs max-w-xs">
                Paste text or upload a document to detect fake offer letters, phishing, and employment scams.
              </p>
            </div>
          ) : (
            <>
              {/* ── Verdict banner ─────────────────────────────────────── */}
              {band && (
                <div className={`rounded-xl border ${band.border} ${band.bg} p-4 flex items-start gap-4`}>
                  <ThreatGauge score={result.threat_index} />
                  <div className="flex-1 min-w-0 space-y-1.5">
                    {/* Single risk label — no duplicate */}
                    <p className={`font-bold text-base ${band.color}`}>{band.emoji} {band.label}</p>
                    <p className="text-xs text-slate-300 leading-relaxed">{result.verdict_summary}</p>
                    <div className="flex gap-2 flex-wrap pt-1">
                      <span className="text-xs text-slate-500">
                        {result.risk_signals.length} signal{result.risk_signals.length !== 1 ? 's' : ''} detected
                      </span>
                      {/* AI status badge — only shows online if health confirms it */}
                      {result.ai_analysis.available ? (
                        <span className="text-xs bg-blue-900/40 border border-blue-800 text-blue-300 rounded-full px-2 py-0.5">
                          🤖 AI: {result.ai_analysis.confidence_score}% confidence
                        </span>
                      ) : (
                        <span className="text-xs bg-slate-800 border border-slate-700 text-slate-500 rounded-full px-2 py-0.5">
                          🤖 AI offline — deterministic analysis active
                        </span>
                      )}
                      <a
                        href={reportUrl(result.scan_id)}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 bg-slate-800 border border-slate-700 rounded-full px-2 py-0.5"
                      >
                        <Download size={10} /> PDF Report
                      </a>
                    </div>
                  </div>
                </div>
              )}

              {/* ── Score Breakdown ────────────────────────────────────── */}
              <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
                <button onClick={() => setShowBreakdown(b => !b)}
                  className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/50 transition-colors">
                  <span className="text-xs font-semibold text-slate-300">📊 Score Breakdown</span>
                  {showBreakdown ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
                </button>
                {showBreakdown && (
                  <div className="px-4 pb-4 pt-1">
                    <RiskBreakdown breakdown={result.score_breakdown} />
                  </div>
                )}
              </div>

              {/* ── Why This Score? ────────────────────────────────────── */}
              {result.score_explanation && Object.keys(result.score_explanation.categories ?? {}).length > 0 && (
                <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
                  <button onClick={() => setShowWhyScore(w => !w)}
                    className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/50 transition-colors">
                    <span className="text-xs font-semibold text-slate-300">🔢 Why this score?</span>
                    {showWhyScore ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
                  </button>
                  {showWhyScore && (
                    <div className="px-4 pb-4 pt-2 font-mono text-xs space-y-3">
                      {Object.entries(result.score_explanation.categories as Record<string, {signals: Array<{label:string;points:number}>;subtotal:number;cap:number}>).map(([cat, data]) => (
                        <div key={cat}>
                          <div className="flex justify-between text-slate-300 font-semibold border-b border-slate-800 pb-1 mb-1">
                            <span>{cat}</span>
                            <span className="text-amber-400">+{data.subtotal}<span className="text-slate-600">/{data.cap}</span></span>
                          </div>
                          {data.signals.map((sig, i) => (
                            <div key={i} className="flex justify-between pl-3 text-slate-500">
                              <span>↳ {sig.label}</span>
                              <span className="text-slate-400">+{sig.points}</span>
                            </div>
                          ))}
                        </div>
                      ))}
                      {(result.score_explanation.compound_bonus as number) > 0 && (
                        <div>
                          <div className="flex justify-between text-orange-400 font-semibold border-b border-slate-800 pb-1 mb-1">
                            <span>Compound Risk Bonus</span>
                            <span>+{result.score_explanation.compound_bonus as number}</span>
                          </div>
                          <div className="pl-3 text-slate-500 text-xs">{result.score_explanation.compound_reason as string}</div>
                        </div>
                      )}
                      <div className="flex justify-between text-white font-bold pt-2 border-t border-slate-700">
                        <span>TOTAL</span>
                        <span>{(result.score_explanation.total as number).toFixed(0)}/100</span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── Risk Signals (grouped by category) ────────────────── */}
              {result.risk_signals.length > 0 && (
                <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
                  <button onClick={() => setShowSignals(s => !s)}
                    className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/50 transition-colors">
                    <span className="text-xs font-semibold text-slate-300">
                      🚩 Risk Signals ({result.risk_signals.length})
                    </span>
                    {showSignals ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
                  </button>
                  {showSignals && (
                    <div className="px-3 pb-3 pt-1 space-y-4 max-h-96 overflow-y-auto">
                      {Object.entries(groupSignals(result.risk_signals)).map(([cat, sigs]) => (
                        <div key={cat}>
                          <p className="text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wide">{cat}</p>
                          <div className="space-y-2">
                            {sigs.map((sig, i) => <EvidenceCard key={i} signal={sig} />)}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* ── AI Semantic Analysis ───────────────────────────────── */}
              <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
                <button onClick={() => setShowAI(a => !a)}
                  className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/50 transition-colors">
                  <span className="text-xs font-semibold text-slate-300">🤖 AI Semantic Analysis</span>
                  {showAI ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
                </button>
                {showAI && (
                  <div className="px-4 pb-4 pt-2">
                    {result.ai_analysis.available ? (
                      <div className="space-y-2">
                        <div className="grid grid-cols-2 gap-x-4 text-xs">
                          <span className="text-slate-400">Status</span>
                          <span className="text-green-400 font-semibold">✅ Online</span>
                          <span className="text-slate-400">Model</span>
                          <span className="text-slate-200 font-mono">{result.ai_analysis.model}</span>
                          <span className="text-slate-400">Confidence</span>
                          <span className="text-slate-200">{result.ai_analysis.confidence_score}%</span>
                          <span className="text-slate-400">Score Contribution</span>
                          <span className="text-slate-200">+{result.ai_analysis.score_contribution} pts (max 5)</span>
                        </div>
                        {result.ai_analysis.semantic_flags.length > 0 && (
                          <div className="space-y-1 pt-1">
                            <p className="text-xs text-slate-500">Detected semantic patterns:</p>
                            {result.ai_analysis.semantic_flags.map((f, i) => (
                              <p key={i} className="text-xs text-slate-300">• {f}</p>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : (
                      /* AI Unavailable state — explicit, not empty */
                      <div className="flex items-start gap-3 p-3 rounded-lg bg-slate-800/60 border border-slate-700">
                        <span className="text-2xl mt-0.5">🤖</span>
                        <div className="space-y-1">
                          <p className="text-xs font-semibold text-slate-400">AI Semantic Analysis Unavailable</p>
                          <p className="text-xs text-slate-500 leading-relaxed">
                            The Gemini AI engine is not configured or could not be reached.
                            All deterministic detectors (payment, urgency, recruitment, email,
                            domain, and URL analysis) are fully active and contributed to this score.
                          </p>
                          <p className="text-xs text-slate-600 mt-1">
                            To enable AI analysis, set the <code className="bg-slate-700 px-1 rounded">GEMINI_API_KEY</code> environment variable.
                          </p>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* ── Domain Intelligence ────────────────────────────────── */}
              {result.domain_intelligence && (
                <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
                  <button onClick={() => setShowDomain(d => !d)}
                    className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/50 transition-colors">
                    <span className="text-xs font-semibold text-slate-300">🌐 Domain Intelligence</span>
                    {showDomain ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
                  </button>
                  {showDomain && (
                    <div className="px-4 pb-4 pt-1">
                      <DomainIntelligence intel={result.domain_intelligence} />
                    </div>
                  )}
                </div>
              )}

              {/* ── Suspicious URLs ────────────────────────────────────── */}
              {result.url_analyses.filter(u => u.is_suspicious).length > 0 && (
                <div className="rounded-xl border border-orange-900/50 bg-orange-950/20 p-4">
                  <p className="text-xs font-semibold text-orange-400 mb-2">🔗 Suspicious URLs Detected</p>
                  <div className="space-y-2">
                    {result.url_analyses.filter(u => u.is_suspicious).map((ua, i) => (
                      <div key={i} className="text-xs space-y-0.5">
                        <p className="text-slate-300 font-mono break-all">
                          {ua.url.length > 80 ? ua.url.substring(0, 80) + '…' : ua.url}
                        </p>
                        <p className="text-slate-500">{ua.evidence}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Recommendations ────────────────────────────────────── */}
              {result.recommendations.length > 0 && (
                <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
                  <button onClick={() => setShowRecs(r => !r)}
                    className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/50 transition-colors">
                    <span className="text-xs font-semibold text-slate-300">
                      💡 Safety Recommendations ({result.recommendations.length})
                    </span>
                    {showRecs ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
                  </button>
                  {showRecs && (
                    <div className="px-4 pb-4 pt-1 space-y-2">
                      {result.recommendations.map((rec, i) => (
                        <div key={i} className="flex gap-2.5 text-xs text-slate-300 leading-relaxed">
                          <span className="text-blue-400 font-bold shrink-0">{i + 1}.</span>
                          <span>{rec}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* ── New Scan ───────────────────────────────────────────── */}
              <button
                onClick={() => { setResult(null); setError(null); setText(''); setSenderEmail('') }}
                className="w-full py-2 rounded-xl border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 text-sm transition-colors">
                ✕ Clear & New Scan
              </button>
            </>
          )}
        </section>
      </main>

      <footer className="border-t border-slate-800 py-4 text-center text-xs text-slate-600 mt-8">
        Fake Offer Letter & Phishing Inspector V2 — For educational and investigative use only.
      </footer>
    </div>
  )
}
