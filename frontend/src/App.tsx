import { useState, useEffect, useCallback } from 'react'
import { Shield, History, FileText, Download, X, ChevronDown, ChevronUp } from 'lucide-react'
import type { ScanResponse, HealthResponse, ScanHistoryItem } from './api'
import {
  getHealth, scanText, scanFile, getScanHistory, deleteScan, reportUrl
} from './api'
import { getThreatBand, PRESETS } from './utils'
import ThreatGauge         from './components/ThreatGauge'
import RiskBreakdown       from './components/RiskBreakdown'
import EvidenceCard        from './components/EvidenceCard'
import StatusBar           from './components/StatusBar'
import DomainIntelligence  from './components/DomainIntelligence'
import ScanHistory         from './components/ScanHistory'
import FileDropZone        from './components/FileDropZone'
import ScanningOverlay     from './components/ScanningOverlay'

export default function App() {
  // ── Input state ─────────────────────────────────────────────────────────────
  const [text,        setText]        = useState('')
  const [senderEmail, setSenderEmail] = useState('')

  // ── App state ───────────────────────────────────────────────────────────────
  const [scanning,    setScanning]    = useState(false)
  const [result,      setResult]      = useState<ScanResponse | null>(null)
  const [error,       setError]       = useState<string | null>(null)

  // ── System status ────────────────────────────────────────────────────────────
  const [health,       setHealth]      = useState<HealthResponse | null>(null)
  const [healthLoading, setHealthLoading] = useState(true)

  // ── History ──────────────────────────────────────────────────────────────────
  const [history,      setHistory]     = useState<ScanHistoryItem[]>([])
  const [historyLoading, setHistoryLoading] = useState(false)
  const [showHistory,  setShowHistory] = useState(false)

  // ── UI sections ──────────────────────────────────────────────────────────────
  const [showBreakdown,  setShowBreakdown]  = useState(true)
  const [showSignals,    setShowSignals]    = useState(true)
  const [showDomain,     setShowDomain]     = useState(true)
  const [showAI,         setShowAI]         = useState(false)
  const [showRecs,       setShowRecs]       = useState(true)

  // ── Fetch health on mount ────────────────────────────────────────────────────
  useEffect(() => {
    getHealth()
      .then(h => { setHealth(h); setHealthLoading(false) })
      .catch(() => setHealthLoading(false))
  }, [])

  // ── Load history when panel opens ────────────────────────────────────────────
  const loadHistory = useCallback(async () => {
    setHistoryLoading(true)
    try {
      setHistory(await getScanHistory())
    } finally {
      setHistoryLoading(false)
    }
  }, [])

  useEffect(() => {
    if (showHistory) loadHistory()
  }, [showHistory, loadHistory])

  // ── Handlers ─────────────────────────────────────────────────────────────────

  async function handleScanText() {
    if (!text.trim()) return
    setError(null); setScanning(true)
    try {
      const r = await scanText(text.trim(), senderEmail.trim() || undefined)
      setResult(r)
      setShowBreakdown(true); setShowSignals(true); setShowRecs(true)
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
      setShowBreakdown(true); setShowSignals(true); setShowRecs(true)
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
    // Fetch full result and display it
    try {
      const resp = await fetch(
        `${window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
          ? '/api' : 'https://fake-offer-letter-phishing-inspector.onrender.com/api'}/scans/${id}`
      )
      if (resp.ok) setResult(await resp.json())
    } catch { /* ignore */ }
    setShowHistory(false)
  }

  const band = result ? getThreatBand(result.threat_index) : null

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      {scanning && <ScanningOverlay />}

      {/* ── Top nav ───────────────────────────────────────────────────────── */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center gap-3">
          <Shield size={20} className="text-blue-400" />
          <span className="font-bold text-base tracking-tight">
            Phishing <span className="text-blue-400">&</span> Fraud Inspector
          </span>
          <span className="text-xs text-slate-500 border border-slate-700 rounded px-1.5 py-0.5">V2</span>

          <div className="flex-1" />

          {/* Status bar */}
          <div className="hidden md:flex items-center">
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

      {/* ── History panel ─────────────────────────────────────────────────── */}
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

      {/* ── Main layout ───────────────────────────────────────────────────── */}
      <main className="max-w-7xl mx-auto px-4 py-6 grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* ════════════════════════════════════════════════════════════════════
            LEFT COLUMN — Input
        ════════════════════════════════════════════════════════════════════ */}
        <section className="flex flex-col gap-4">

          {/* Preset chips */}
          <div className="flex flex-wrap gap-2">
            {PRESETS.map(p => (
              <button
                key={p.label}
                onClick={() => setText(p.text)}
                className="flex items-center gap-1 text-xs bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-full px-3 py-1 transition-colors"
              >
                <span>{p.icon}</span> {p.label}
              </button>
            ))}
          </div>

          {/* Text input */}
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
          <button
            onClick={handleScanText}
            disabled={!text.trim() || scanning}
            className={`
              w-full py-3 rounded-xl font-bold text-sm tracking-wide transition-all
              ${text.trim() && !scanning
                ? 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-900/50 hover:shadow-blue-800/60'
                : 'bg-slate-800 text-slate-600 cursor-not-allowed'
              }
            `}
          >
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

          {/* Mobile status */}
          <div className="md:hidden border border-slate-800 rounded-xl bg-slate-900 p-3">
            <StatusBar health={health} loading={healthLoading} />
          </div>
        </section>

        {/* ════════════════════════════════════════════════════════════════════
            RIGHT COLUMN — Results
        ════════════════════════════════════════════════════════════════════ */}
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
              {/* ── Verdict banner ─────────────────────────────────────────── */}
              {band && (
                <div className={`rounded-xl border ${band.border} ${band.bg} p-4 flex items-start gap-4`}>
                  <ThreatGauge score={result.threat_index} />
                  <div className="flex-1 min-w-0 space-y-1.5">
                    <p className={`font-bold text-base ${band.color}`}>{band.emoji} {band.label}</p>
                    <p className="text-xs text-slate-300 leading-relaxed">{result.verdict_summary}</p>
                    <div className="flex gap-2 flex-wrap pt-1">
                      <span className="text-xs text-slate-500">
                        {result.risk_signals.length} signal{result.risk_signals.length !== 1 ? 's' : ''} detected
                      </span>
                      {result.ai_analysis.available ? (
                        <span className="text-xs bg-blue-900/40 border border-blue-800 text-blue-300 rounded-full px-2 py-0.5">
                          🤖 AI: {result.ai_analysis.confidence_score}% confidence
                        </span>
                      ) : (
                        <span className="text-xs bg-slate-800 border border-slate-700 text-slate-400 rounded-full px-2 py-0.5">
                          🤖 AI unavailable — heuristics only
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

              {/* ── Score Breakdown ────────────────────────────────────────── */}
              <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
                <button
                  onClick={() => setShowBreakdown(b => !b)}
                  className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/50 transition-colors"
                >
                  <span className="text-xs font-semibold text-slate-300">📊 Score Breakdown</span>
                  {showBreakdown ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
                </button>
                {showBreakdown && (
                  <div className="px-4 pb-4 pt-1">
                    <RiskBreakdown breakdown={result.score_breakdown} />
                  </div>
                )}
              </div>

              {/* ── Risk Signals ───────────────────────────────────────────── */}
              {result.risk_signals.length > 0 && (
                <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
                  <button
                    onClick={() => setShowSignals(s => !s)}
                    className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/50 transition-colors"
                  >
                    <span className="text-xs font-semibold text-slate-300">
                      🚩 Risk Signals ({result.risk_signals.length})
                    </span>
                    {showSignals ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
                  </button>
                  {showSignals && (
                    <div className="px-3 pb-3 pt-1 space-y-2 max-h-72 overflow-y-auto">
                      {result.risk_signals.map((sig, i) => (
                        <EvidenceCard key={i} signal={sig} />
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* ── Domain Intelligence ────────────────────────────────────── */}
              {result.domain_intelligence && (
                <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
                  <button
                    onClick={() => setShowDomain(d => !d)}
                    className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/50 transition-colors"
                  >
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

              {/* ── AI Analysis ────────────────────────────────────────────── */}
              <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
                <button
                  onClick={() => setShowAI(a => !a)}
                  className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/50 transition-colors"
                >
                  <span className="text-xs font-semibold text-slate-300">🤖 AI Semantic Analysis</span>
                  {showAI ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
                </button>
                {showAI && (
                  <div className="px-4 pb-4 pt-1 space-y-2">
                    <div className="grid grid-cols-2 gap-x-4 text-xs">
                      <span className="text-slate-400">Status</span>
                      <span className={result.ai_analysis.available ? 'text-green-400' : 'text-slate-500'}>
                        {result.ai_analysis.available ? '✅ Online' : '❌ Offline'}
                      </span>
                      {result.ai_analysis.model && <>
                        <span className="text-slate-400">Model</span>
                        <span className="text-slate-200 font-mono">{result.ai_analysis.model}</span>
                      </>}
                      <span className="text-slate-400">Confidence</span>
                      <span className="text-slate-200">{result.ai_analysis.confidence_score}%</span>
                      <span className="text-slate-400">Score Contribution</span>
                      <span className="text-slate-200">+{result.ai_analysis.score_contribution} pts</span>
                    </div>
                    {result.ai_analysis.semantic_flags.length > 0 && (
                      <div className="space-y-1 pt-1">
                        <p className="text-xs text-slate-500">Semantic flags:</p>
                        {result.ai_analysis.semantic_flags.map((f, i) => (
                          <p key={i} className="text-xs text-slate-300">• {f}</p>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* ── URL Analyses ───────────────────────────────────────────── */}
              {result.url_analyses.filter(u => u.is_suspicious).length > 0 && (
                <div className="rounded-xl border border-orange-900/50 bg-orange-950/20 p-4">
                  <p className="text-xs font-semibold text-orange-400 mb-2">🔗 Suspicious URLs</p>
                  <div className="space-y-2">
                    {result.url_analyses.filter(u => u.is_suspicious).map((ua, i) => (
                      <div key={i} className="text-xs space-y-0.5">
                        <p className="text-slate-300 font-mono break-all">{ua.url.substring(0, 80)}…</p>
                        <p className="text-slate-500">{ua.evidence}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Recommendations ────────────────────────────────────────── */}
              {result.recommendations.length > 0 && (
                <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
                  <button
                    onClick={() => setShowRecs(r => !r)}
                    className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/50 transition-colors"
                  >
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

              {/* ── Clear / New Scan ───────────────────────────────────────── */}
              <button
                onClick={() => { setResult(null); setError(null); setText(''); setSenderEmail('') }}
                className="w-full py-2 rounded-xl border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 text-sm transition-colors"
              >
                ✕ Clear & New Scan
              </button>
            </>
          )}
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-4 text-center text-xs text-slate-600 mt-8">
        Fake Offer Letter & Phishing Inspector V2 — For educational and investigative use only.
      </footer>
    </div>
  )
}
