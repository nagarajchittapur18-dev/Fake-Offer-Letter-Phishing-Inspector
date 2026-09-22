import React, { useState } from 'react'
import {
  Shield, Search, FileText, AlertTriangle,
  Lightbulb, ChevronDown, ChevronUp, Upload, PenLine,
  Globe, ExternalLink, CheckCircle2, XCircle, Clock,
  Cpu, FileSearch, CheckCircle, RotateCcw
} from 'lucide-react'
import { scanPayload } from './api'
import type { ScanResponse } from './api'
import { ThreatGauge }       from './components/ThreatGauge'
import { FlagCard }           from './components/FlagCard'
import { DomainDetailsPanel } from './components/DomainDetails'
import { FileDropZone }       from './components/FileDropZone'
import { ScanningOverlay }    from './components/ScanningOverlay'

// ── Demo templates ────────────────────────────────────────────────────────────
const DEMOS = [
  {
    icon: '🚨',
    label: 'Equipment Scam',
    url: 'careers.apple-jobs.top',
    text: `Congratulations! You have been selected for an immediate hire for the Remote Data Entry Specialist position at Apple Inc. No interview is required.

Your starting pay is $45/hour (100% remote). To begin onboarding, contact our HR director on Telegram (@apple_hr_recruiter).

We will send you a cashier's check for $2,850 to purchase your equipment. You must buy the required MacBook Pro and licensed software from our certified vendor and wire the remainder back to our procurement account via Zelle or wire transfer within 24 hours. Failure to act immediately will forfeit your position.`,
  },
  {
    icon: '🏠',
    label: 'Rental Trap',
    url: 'gmail.com',
    text: `Hello,

Thank you for your interest in renting my 2-bedroom apartment at 412 Elmwood Drive. Unfortunately I am currently out of the country on a missionary program in Ghana, so I am unable to show the property in person.

The rent is $800/month. To secure the unit and receive the keys by mail, you must send a $1,200 refundable security deposit via CashApp ($johnsmith_landlord) or Western Union before I release the keys. Once the funds are confirmed I will overnight the keys and lease to you.

Please respond urgently as I have several other interested parties.`,
  },
  {
    icon: '✅',
    label: 'Legitimate Offer',
    url: 'stripe.com',
    text: `Dear Alex,

We are delighted to extend this formal offer of employment for the role of Senior Software Engineer at Stripe, Inc., effective October 1st, 2026.

Your annual base salary will be $175,000, paid semi-monthly via direct deposit. You will also be eligible for the company's standard equity and benefits package as outlined in the enclosed Total Compensation Statement.

Please review and sign the Employment Agreement through our secure HR portal (Workday) within five (5) business days. Your company-issued MacBook Pro and access credentials will be shipped by our IT department directly to your home address prior to your start date. No equipment purchase or upfront payment of any kind is required.

Should you have questions, please contact your recruiter at recruiting@stripe.com or call our HR line directly.

We look forward to welcoming you to the team.

Sincerely,
Sarah Chen
Senior Talent Partner, Stripe, Inc.`,
  },
]

// ── Sub-components ────────────────────────────────────────────────────────────

const SectionHeader: React.FC<{ icon: React.ReactNode; title: string; count?: number }> = ({ icon, title, count }) => (
  <div className="flex items-center gap-2 mb-3">
    <span className="text-indigo-400">{icon}</span>
    <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider">{title}</h2>
    {count !== undefined && (
      <span className="ml-auto text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">{count}</span>
    )}
  </div>
)

const BoolVector: React.FC<{ active: boolean; label: string; desc: string }> = ({ active, label, desc }) => (
  <div className={`flex items-start gap-2.5 rounded-xl border p-3 transition
    ${active ? 'bg-red-950/40 border-red-800/70' : 'bg-slate-900/40 border-slate-800/80'}`}>
    {active
      ? <XCircle     className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
      : <CheckCircle2 className="w-4 h-4 text-emerald-500 flex-shrink-0 mt-0.5" />}
    <div>
      <p className={`text-xs font-bold ${active ? 'text-red-300' : 'text-slate-400'}`}>{label}</p>
      <p className="text-[11px] text-slate-500 mt-0.5 leading-snug">{desc}</p>
    </div>
  </div>
)

// ── Main App ──────────────────────────────────────────────────────────────────
type Tab = 'file' | 'text'

export default function App() {
  const [tab,     setTab]     = useState<Tab>('text')
  const [text,    setText]    = useState('')
  const [url,     setUrl]     = useState('')
  const [file,    setFile]    = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [result,  setResult]  = useState<ScanResponse | null>(null)
  const [error,   setError]   = useState<string | null>(null)
  const [showRaw, setShowRaw] = useState(false)

  const loadDemo = (d: typeof DEMOS[0]) => {
    setTab('text')
    setUrl(d.url)
    setText(d.text)
    setFile(null)
    setResult(null)
    setError(null)
  }

  const handleScan = async () => {
    const hasText = text.trim().length > 0
    const hasFile = !!file
    if (!hasText && !hasFile) {
      setError('Please upload a document or paste offer text before scanning.')
      return
    }
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await scanPayload({ text: text.trim() || undefined, url: url.trim() || undefined, file })
      setResult(res)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'An unexpected error occurred.')
    } finally {
      setLoading(false)
    }
  }

  const handleReset = () => {
    setText('')
    setUrl('')
    setFile(null)
    setResult(null)
    setError(null)
    setShowRaw(false)
  }

  const isAiUnavailable = result?.ai_analysis?.ai_audit_available === false || (result?.ai_analysis?.ai_confidence_score === 0 && result?.threat_index > 0)

  return (
    <div className="min-h-screen w-full bg-[#0b0f19] text-slate-100 flex flex-col antialiased">

      {/* ── Fixed/Sticky Top Navigation ── */}
      <header className="sticky top-0 z-30 border-b border-slate-800 bg-[#0b0f19]/95 backdrop-blur-md flex-shrink-0">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
          
          {/* Brand */}
          <div className="flex items-center gap-3 flex-shrink-0">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-600 to-violet-700 flex items-center justify-center shadow-lg shadow-indigo-900/50">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-sm sm:text-base font-bold text-white tracking-tight leading-tight">
                Fake Offer Letter &amp; Phishing Inspector
              </h1>
              <p className="text-[11px] text-slate-500 hidden sm:block">Forensic Scam &amp; Contract Fraud Detection</p>
            </div>
          </div>

          {/* Quick Demos In Header */}
          <div className="flex items-center gap-2 overflow-x-auto no-scrollbar py-1">
            <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-widest hidden md:inline-block mr-1">
              Presets:
            </span>
            {DEMOS.map(d => (
              <button
                key={d.label}
                onClick={() => loadDemo(d)}
                className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-full
                  bg-slate-900 border border-slate-700 hover:border-indigo-500 hover:bg-slate-800
                  text-slate-300 hover:text-white transition whitespace-nowrap flex-shrink-0"
              >
                <span>{d.icon}</span>
                <span>{d.label}</span>
              </button>
            ))}
          </div>

          {/* Engine Status */}
          <div className="flex items-center gap-2 text-[11px] font-medium bg-emerald-950/60 border border-emerald-800/60 text-emerald-400 px-3 py-1.5 rounded-full flex-shrink-0">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span>Gemini 3.6 Flash Engine Online</span>
          </div>
        </div>
      </header>

      {/* ── Main Dashboard: Full-Width 12-Column Grid ── */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">

          {/* ════════════════ LEFT COLUMN: Offer Ingestion Panel (6 cols) ════════════════ */}
          <div className="lg:col-span-6 space-y-5">

            {/* Ingestion Box */}
            <div className="rounded-2xl border border-slate-800 bg-[#0f172a] shadow-xl overflow-hidden">
              
              {/* Header Label */}
              <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between bg-slate-900/40">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-indigo-400" />
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">Offer Ingestion Center</span>
                </div>
                <span className="text-[11px] text-slate-500">Document or Text Analysis</span>
              </div>

              {/* Mode Tabs */}
              <div className="flex border-b border-slate-800 bg-slate-950/40">
                <button
                  onClick={() => setTab('text')}
                  className={`flex-1 flex items-center justify-center gap-2 py-3 text-xs font-semibold transition
                    ${tab === 'text'
                      ? 'bg-slate-800/80 text-white border-b-2 border-indigo-500'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'}`}
                >
                  <PenLine className="w-3.5 h-3.5" /> ✍️ Paste Raw Text
                </button>
                <button
                  onClick={() => setTab('file')}
                  className={`flex-1 flex items-center justify-center gap-2 py-3 text-xs font-semibold transition
                    ${tab === 'file'
                      ? 'bg-slate-800/80 text-white border-b-2 border-indigo-500'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'}`}
                >
                  <Upload className="w-3.5 h-3.5" /> 📄 Upload Document
                </button>
              </div>

              <div className="p-5 space-y-4">

                {/* Tab: Text Ingestion */}
                {tab === 'text' && (
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span className="font-bold uppercase tracking-wider text-slate-500">Offer / Contract Content</span>
                      <span className="text-slate-500">{text.length.toLocaleString()} characters</span>
                    </div>
                    <textarea
                      rows={9}
                      placeholder="Paste the full job offer letter, freelance contract, recruitment email, or rental agreement here…"
                      value={text}
                      onChange={e => setText(e.target.value)}
                      className="w-full max-h-64 rounded-xl bg-slate-950 border border-slate-800 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 px-4 py-3 text-sm text-slate-200 placeholder-slate-700 outline-none resize-none font-mono leading-relaxed overflow-y-auto"
                    />
                    {text && (
                      <div className="flex justify-end">
                        <button
                          onClick={() => setText('')}
                          className="text-[11px] text-slate-500 hover:text-slate-300 transition"
                        >
                          Clear Text
                        </button>
                      </div>
                    )}
                  </div>
                )}

                {/* Tab: File Upload Ingestion */}
                {tab === 'file' && (
                  <div className="space-y-2">
                    <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Document Upload</span>
                    <FileDropZone file={file} onFile={setFile} />
                  </div>
                )}

                {/* Target URL / Recruiter Domain Input */}
                <div className="space-y-1.5">
                  <label className="flex items-center gap-2 text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                    <Globe className="w-3.5 h-3.5 text-indigo-400" /> Target URL or Recruiter Email
                    <span className="text-slate-600 normal-case font-normal">(Optional for WHOIS check)</span>
                  </label>
                  <input
                    type="text"
                    placeholder="e.g.  careers.company.com  ·  recruiter@company.com"
                    value={url}
                    onChange={e => setUrl(e.target.value)}
                    className="w-full rounded-xl bg-slate-950 border border-slate-800 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 px-4 py-2.5 text-sm text-slate-200 placeholder-slate-700 outline-none transition"
                  />
                </div>

                {/* Error Banner */}
                {error && (
                  <div className="flex items-start gap-2.5 rounded-xl bg-red-950/50 border border-red-800 px-4 py-3 text-xs text-red-300">
                    <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0 text-red-400" />
                    <span>{error}</span>
                  </div>
                )}

                {/* Loading Radar Overlay */}
                {loading && <ScanningOverlay />}

                {/* Action Buttons */}
                {!loading && (
                  <div className="flex gap-3 pt-2">
                    <button
                      onClick={handleScan}
                      disabled={loading}
                      className="flex-1 flex items-center justify-center gap-2.5 rounded-xl
                        bg-gradient-to-r from-indigo-600 to-violet-700
                        hover:from-indigo-500 hover:to-violet-600
                        active:from-indigo-700 active:to-violet-800
                        text-white font-bold py-3.5 text-sm tracking-wide
                        shadow-lg shadow-indigo-900/40 transition disabled:opacity-50"
                    >
                      <Search className="w-4 h-4" />
                      <span>Run Forensic Security Scan</span>
                    </button>
                    {result && (
                      <button
                        onClick={handleReset}
                        className="px-4 rounded-xl border border-slate-700 hover:border-slate-500 text-slate-400 hover:text-slate-200 text-xs font-semibold transition flex items-center gap-1.5"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        <span>Reset</span>
                      </button>
                    )}
                  </div>
                )}

              </div>
            </div>

            {/* How It Works Card */}
            <div className="rounded-2xl border border-slate-800 bg-[#0f172a] p-4 text-slate-400">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="w-4 h-4 text-indigo-400" />
                <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Forensic Audit Methodology</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800">
                  <FileSearch className="w-4 h-4 text-indigo-400 mx-auto mb-1" />
                  <p className="text-[11px] font-semibold text-slate-300">File &amp; Text</p>
                  <p className="text-[10px] text-slate-600">PDF/DOCX OCR</p>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800">
                  <Globe className="w-4 h-4 text-indigo-400 mx-auto mb-1" />
                  <p className="text-[11px] font-semibold text-slate-300">WHOIS / RDAP</p>
                  <p className="text-[10px] text-slate-600">Domain Age Check</p>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800">
                  <Cpu className="w-4 h-4 text-indigo-400 mx-auto mb-1" />
                  <p className="text-[11px] font-semibold text-slate-300">Gemini 3.6</p>
                  <p className="text-[10px] text-slate-600">Semantic Audit</p>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800">
                  <CheckCircle className="w-4 h-4 text-indigo-400 mx-auto mb-1" />
                  <p className="text-[11px] font-semibold text-slate-300">Dynamic Score</p>
                  <p className="text-[10px] text-slate-600">0–100% Threat Index</p>
                </div>
              </div>
            </div>

          </div>


          {/* ════════════════ RIGHT COLUMN: Threat Intelligence Dashboard (6 cols) ════════════════ */}
          <div className="lg:col-span-6 space-y-5">

            {/* ── Idle Placeholder State ── */}
            {!result && !loading && (
              <div className="rounded-2xl border border-dashed border-slate-800 bg-[#0f172a] p-10 flex flex-col items-center justify-center text-center min-h-[460px]">
                <div className="relative mb-5">
                  <div className="w-20 h-20 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto shadow-inner">
                    <Shield className="w-10 h-10 text-slate-600" />
                  </div>
                  <div className="absolute -top-1 -right-1 w-6 h-6 rounded-full bg-slate-800 border-2 border-[#0f172a] flex items-center justify-center">
                    <Clock className="w-3 h-3 text-indigo-400" />
                  </div>
                </div>
                <h3 className="text-base font-bold text-slate-300 mb-1">Awaiting Offer Document or URL</h3>
                <p className="text-xs text-slate-500 max-w-sm leading-relaxed mb-6">
                  Paste the text or upload your offer letter in the left console. Click <strong className="text-slate-400">"Run Forensic Security Scan"</strong> to inspect for wire traps, fake letterheads, and suspicious domain telemetry.
                </p>
                <div className="flex flex-wrap justify-center gap-1.5 max-w-md">
                  <span className="text-[10px] bg-slate-950 border border-slate-800 text-slate-500 px-2.5 py-1 rounded-full">
                    Pay-for-Equipment Checks
                  </span>
                  <span className="text-[10px] bg-slate-950 border border-slate-800 text-slate-500 px-2.5 py-1 rounded-full">
                    Domain Age WHOIS
                  </span>
                  <span className="text-[10px] bg-slate-950 border border-slate-800 text-slate-500 px-2.5 py-1 rounded-full">
                    Advance-Fee Rental Traps
                  </span>
                  <span className="text-[10px] bg-slate-950 border border-slate-800 text-slate-500 px-2.5 py-1 rounded-full">
                    Free Recruiter Email Detection
                  </span>
                  <span className="text-[10px] bg-slate-950 border border-slate-800 text-slate-500 px-2.5 py-1 rounded-full">
                    Interview Bypass Flags
                  </span>
                </div>
              </div>
            )}

            {/* ── Active Scan Results (No Duplicate Top Banner) ── */}
            {result && !loading && (
              <div className="space-y-5 animate-in fade-in duration-300">

                {/* Single Prominent Score Gauge Meter */}
                <ThreatGauge score={result.threat_index} breakdown={result.score_breakdown} />

                {/* AI Audit Fallback Badge if AI was unavailable */}
                {isAiUnavailable && (
                  <div className="flex items-center gap-2.5 rounded-xl bg-amber-950/40 border border-amber-800/80 px-4 py-3 text-xs font-medium text-amber-300">
                    <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
                    <div>
                      <span className="font-bold">AI Audit Unavailable — Heuristics Applied:</span>
                      <span className="ml-1 text-amber-200/80">Regex pattern matching and domain age verification have established the Threat Index.</span>
                    </div>
                  </div>
                )}

                {/* Domain Telemetry Card */}
                {result.domain_details?.domain && (
                  <DomainDetailsPanel details={result.domain_details} />
                )}

                {/* AI Auditor Assessment Card */}
                <div className="rounded-2xl border border-slate-800 bg-[#0f172a] p-5 shadow-lg">
                  <SectionHeader icon={<Cpu className="w-4 h-4" />} title="AI Forensic Auditor Verdict" />
                  <p className="text-sm text-slate-300 leading-relaxed font-sans">{result.verdict_summary}</p>
                  
                  {/* Threat Vector Checks Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-4">
                    <BoolVector
                      active={result.ai_analysis.payment_demand_detected}
                      label="Wire / Equipment Demand"
                      desc="Demands for checks, Zelle, crypto, or equipment reimbursement"
                    />
                    <BoolVector
                      active={result.ai_analysis.urgency_detected}
                      label="Coercive Urgency Tactics"
                      desc="Threats of offer expiration to force hasty decision-making"
                    />
                    <BoolVector
                      active={result.ai_analysis.interview_bypass_detected}
                      label="Interview Bypass Signal"
                      desc="Immediate job offer without live technical or behavioral interview"
                    />
                    <BoolVector
                      active={result.ai_analysis.free_email_domain_used}
                      label="Free Recruiter Email"
                      desc="Recruiter using public Gmail/Hotmail instead of corporate domain"
                    />
                  </div>

                  {/* Confidence bar */}
                  <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center gap-3">
                    <span className="text-xs text-slate-500 flex-shrink-0">AI Confidence Index</span>
                    <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-indigo-500 transition-all duration-700"
                        style={{ width: `${result.ai_analysis.ai_confidence_score}%` }}
                      />
                    </div>
                    <span className="text-xs font-bold text-indigo-400 tabular-nums">
                      {result.ai_analysis.ai_confidence_score}%
                    </span>
                  </div>
                </div>

                {/* Identified Risk Indicators / Evidence Feed */}
                {result.flags.length > 0 && (
                  <div className="rounded-2xl border border-slate-800 bg-[#0f172a] p-5 shadow-lg">
                    <SectionHeader
                      icon={<AlertTriangle className="w-4 h-4 text-red-400" />}
                      title="Identified Risk Indicators"
                      count={result.flags.length}
                    />
                    <div className="space-y-3 max-h-80 overflow-y-auto pr-1">
                      {result.flags.map((f, i) => <FlagCard key={i} flag={f} />)}
                    </div>
                  </div>
                )}

                {/* Recommended Countermeasures & Reporting Links */}
                {result.safety_recommendations.length > 0 && (
                  <div className="rounded-2xl border border-slate-800 bg-[#0f172a] p-5 shadow-lg">
                    <SectionHeader icon={<Lightbulb className="w-4 h-4 text-amber-400" />} title="Recommended Countermeasures" />
                    <ul className="space-y-2.5">
                      {result.safety_recommendations.map((rec, i) => (
                        <li key={i} className="flex gap-2.5 text-xs sm:text-sm text-slate-300 leading-relaxed">
                          <span className="flex-shrink-0 w-5 h-5 rounded-full bg-indigo-950 border border-indigo-700 text-indigo-400 text-[10px] flex items-center justify-center font-bold mt-0.5">
                            {i + 1}
                          </span>
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>

                    {/* Official reporting links */}
                    <div className="mt-4 pt-3 border-t border-slate-800">
                      <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-2">Escalate / Report Scam</p>
                      <div className="flex flex-wrap gap-2">
                        <a
                          href="https://reportfraud.ftc.gov"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 text-xs text-indigo-400 hover:text-indigo-300 border border-indigo-800/60 hover:border-indigo-600 rounded-lg px-2.5 py-1.5 transition bg-indigo-950/20"
                        >
                          <ExternalLink className="w-3 h-3" /> FTC Fraud Report
                        </a>
                        <a
                          href="https://ic3.gov"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 text-xs text-indigo-400 hover:text-indigo-300 border border-indigo-800/60 hover:border-indigo-600 rounded-lg px-2.5 py-1.5 transition bg-indigo-950/20"
                        >
                          <ExternalLink className="w-3 h-3" /> FBI IC3 Center
                        </a>
                        <a
                          href="https://actionfraud.police.uk"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 text-xs text-indigo-400 hover:text-indigo-300 border border-indigo-800/60 hover:border-indigo-600 rounded-lg px-2.5 py-1.5 transition bg-indigo-950/20"
                        >
                          <ExternalLink className="w-3 h-3" /> Action Fraud (UK)
                        </a>
                      </div>
                    </div>
                  </div>
                )}

                {/* Raw API Output Collapsible */}
                <div className="rounded-2xl border border-slate-800 bg-slate-950/60 overflow-hidden">
                  <button
                    onClick={() => setShowRaw(v => !v)}
                    className="w-full flex items-center justify-between px-5 py-3 text-xs text-slate-500 hover:text-slate-300 transition font-mono"
                  >
                    <span>Raw JSON Telemetry</span>
                    {showRaw ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>
                  {showRaw && (
                    <pre className="px-5 pb-5 text-[11px] text-slate-400 font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed border-t border-slate-800 pt-3">
                      {JSON.stringify(result, null, 2)}
                    </pre>
                  )}
                </div>

              </div>
            )}

          </div>

        </div>
      </main>

      {/* ── Footer ── */}
      <footer className="border-t border-slate-900 mt-12 py-5 text-center text-xs text-slate-600 flex-shrink-0">
        Fake Offer Letter &amp; Phishing Inspector · Powered by Gemini 3.6 Flash · For Cybersecurity Research &amp; Consumer Protection
      </footer>
    </div>
  )
}
