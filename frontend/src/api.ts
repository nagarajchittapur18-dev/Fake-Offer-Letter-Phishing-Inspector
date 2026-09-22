// ── Types mirroring the FastAPI Pydantic schemas ────────────────────────────

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

export interface Flag {
  category: string
  severity: Severity
  evidence: string
}

export interface DomainDetails {
  domain:        string | null
  creation_date: string | null
  age_in_days:   number | null
  penalty:       number
}

export interface GeminiAnalysis {
  payment_demand_detected:   boolean
  urgency_detected:          boolean
  interview_bypass_detected: boolean
  free_email_domain_used:    boolean
  ai_confidence_score:       number
  flags:                     Flag[]
  verdict_summary:           string
  ai_audit_available?:       boolean
}

export interface ScoreBreakdown {
  ai_component:           number
  payment_penalty:        number
  domain_penalty:         number
  process_bypass_penalty: number
  raw_sum:                number
  threat_index:           number
}

export interface ScanResponse {
  threat_index:           number
  verdict_summary:        string
  flags:                  Flag[]
  domain_details:         DomainDetails | null
  ai_analysis:            GeminiAnalysis
  safety_recommendations: string[]
  score_breakdown:        ScoreBreakdown
}

// ── Scan payload: now uses FormData for multipart file upload ─────────────────

export interface ScanPayload {
  text?: string
  url?:  string
  file?: File | null
}

const BASE_URL = '/api'

export async function scanPayload(payload: ScanPayload): Promise<ScanResponse> {
  const form = new FormData()
  if (payload.text) form.append('text', payload.text)
  if (payload.url)  form.append('url',  payload.url)
  if (payload.file) form.append('file', payload.file)

  const res = await fetch(`${BASE_URL}/scan`, { method: 'POST', body: form })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail ?? 'Scan request failed')
  }
  return res.json() as Promise<ScanResponse>
}

export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${BASE_URL}/health`)
    return res.ok
  } catch {
    return false
  }
}
