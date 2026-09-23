/**
 * V2 API types matching the backend schemas.py
 */

export type Severity = "Critical" | "High" | "Medium" | "Low";
export type RiskLevel = "LOW" | "SUSPICIOUS" | "HIGH" | "CRITICAL";
export type RiskCategory =
  | "Financial/Payment"
  | "Urgency/Coercion"
  | "Recruitment Anomaly"
  | "Email Provider"
  | "Organization Mismatch"
  | "Domain Intelligence"
  | "URL Risk"
  | "AI Semantic";

export type InputType = "text" | "file" | "url";

export interface RiskSignal {
  category: RiskCategory;
  severity: Severity;
  score_contribution: number;
  evidence: string;
  explanation: string;
}

export interface ScoreBreakdown {
  financial_payment: number;    // max 25
  urgency_coercion: number;     // max 10
  recruitment_anomaly: number;  // max 10
  email_provider: number;       // max 10
  org_mismatch: number;         // max 15
  domain_intelligence: number;  // max 15
  url_risk: number;             // max 10
  ai_semantic: number;          // max 5
  total: number;
}

export interface DomainIntelligence {
  domain: string | null;
  age_days: number | null;
  created: string | null;
  provider_type: string;
  registrar: string | null;
  score_contribution: number;
  notes: string[];
}

export interface URLAnalysis {
  url: string;
  is_reachable: boolean;
  is_suspicious: boolean;
  is_ssrf_blocked: boolean;
  final_url: string | null;
  status_code: number | null;
  redirect_count: number;
  score_contribution: number;
  evidence: string;
}

export interface AIAnalysis {
  available: boolean;
  model: string | null;
  confidence_score: number;
  score_contribution: number;
  verdict_summary: string;
  semantic_flags: string[];
}

export interface ScanResponse {
  scan_id: string;
  threat_index: number;
  risk_level: RiskLevel;
  verdict_summary: string;
  risk_signals: RiskSignal[];
  score_breakdown: ScoreBreakdown;
  domain_intelligence: DomainIntelligence | null;
  url_analyses: URLAnalysis[];
  ai_analysis: AIAnalysis;
  recommendations: string[];
  score_explanation: {
    categories: Record<string, {
      signals: Array<{ label: string; points: number }>;
      subtotal: number;
      cap: number;
    }>;
    compound_bonus: number;
    compound_reason: string | null;
    total: number;
  };
  metadata: Record<string, unknown>;
  input_type: InputType;
  scanned_at: string;
}

export interface HealthComponentStatus {
  status: "online" | "degraded" | "offline";
  message: string;
}

export interface HealthResponse {
  status: "healthy" | "degraded" | "unhealthy";
  version: string;
  components: Record<string, HealthComponentStatus>;
  timestamp: string;
}

export interface ScanHistoryItem {
  scan_id: string;
  created_at: string;
  input_type: string;
  source_name: string | null;
  domain: string | null;
  threat_index: number;
  risk_level: RiskLevel;
  signal_count: number;
}

// ── API client ─────────────────────────────────────────────────────────────────

/**
 * BASE is determined in priority order:
 * 1. VITE_API_BASE_URL (set via .env.production or Render env)  ← never localhost in prod
 * 2. /api proxy — only when running on localhost dev server
 * 3. Production Render URL — final fallback
 */
const BASE: string =
  (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") ||
  (typeof window !== "undefined" &&
   (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")
    ? "/api"
    : "https://fake-offer-letter-phishing-inspector.onrender.com/api");

export async function getHealth(): Promise<HealthResponse> {
  const r = await fetch(`${BASE}/health`);
  if (!r.ok) throw new Error("Health check failed");
  return r.json();
}

export async function scanText(
  text: string,
  senderEmail?: string
): Promise<ScanResponse> {
  const r = await fetch(`${BASE}/scan/text`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, sender_email: senderEmail || null }),
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: "Scan failed" }));
    throw new Error(err.detail || "Scan failed");
  }
  return r.json();
}

export async function scanFile(file: File): Promise<ScanResponse> {
  const fd = new FormData();
  fd.append("file", file);
  const r = await fetch(`${BASE}/scan/file`, { method: "POST", body: fd });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: "File scan failed" }));
    throw new Error(err.detail || "File scan failed");
  }
  return r.json();
}

export async function getScanHistory(): Promise<ScanHistoryItem[]> {
  const r = await fetch(`${BASE}/scans`);
  if (!r.ok) throw new Error("Failed to load history");
  return r.json();
}

export async function deleteScan(scanId: string): Promise<void> {
  await fetch(`${BASE}/scans/${scanId}`, { method: "DELETE" });
}

export function reportUrl(scanId: string): string {
  return `${BASE}/report/${scanId}`;
}
