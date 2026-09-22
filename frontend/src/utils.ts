import type { RiskLevel, Severity } from './api'

export const SEVERITY_STYLES: Record<Severity, { badge: string; dot: string }> = {
  Critical: { badge: 'bg-red-900/60 text-red-300 border border-red-700',     dot: 'bg-red-500'    },
  High:     { badge: 'bg-orange-900/60 text-orange-300 border border-orange-700', dot: 'bg-orange-400' },
  Medium:   { badge: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700', dot: 'bg-yellow-400' },
  Low:      { badge: 'bg-blue-900/60 text-blue-300 border border-blue-700',   dot: 'bg-blue-400'   },
}

export interface ThreatBand {
  label:    string
  color:    string
  bg:       string
  barColor: string
  emoji:    string
  border:   string
  ring:     string
}

export function getThreatBand(score: number): ThreatBand {
  if (score >= 75) return {
    label: 'CRITICAL RISK',  color: 'text-red-400',
    bg: 'bg-red-950/40',     barColor: 'bg-red-500',
    emoji: '🚨',             border: 'border-red-600',  ring: 'ring-red-500',
  }
  if (score >= 50) return {
    label: 'HIGH RISK',      color: 'text-orange-400',
    bg: 'bg-orange-950/30',  barColor: 'bg-orange-500',
    emoji: '⚠️',             border: 'border-orange-500', ring: 'ring-orange-500',
  }
  if (score >= 25) return {
    label: 'SUSPICIOUS',     color: 'text-amber-400',
    bg: 'bg-amber-950/30',   barColor: 'bg-amber-400',
    emoji: '🔍',             border: 'border-amber-500',  ring: 'ring-amber-500',
  }
  return {
    label: 'LOW RISK',       color: 'text-green-400',
    bg: 'bg-green-950/30',   barColor: 'bg-green-500',
    emoji: '✅',             border: 'border-green-600',  ring: 'ring-green-500',
  }
}

export const RISK_LEVEL_LABEL: Record<RiskLevel, string> = {
  LOW:        'Low Risk',
  SUSPICIOUS: 'Suspicious',
  HIGH:       'High Risk',
  CRITICAL:   'Critical Risk',
}

export const CATEGORY_LABELS: Record<string, { icon: string; max: number }> = {
  'Financial/Payment':      { icon: '💰', max: 25 },
  'Urgency/Coercion':       { icon: '⏰', max: 10 },
  'Recruitment Anomaly':    { icon: '🎯', max: 10 },
  'Email Provider':         { icon: '📧', max: 10 },
  'Organization Mismatch':  { icon: '🏢', max: 15 },
  'Domain Intelligence':    { icon: '🌐', max: 15 },
  'URL Risk':               { icon: '🔗', max: 10 },
  'AI Semantic':            { icon: '🤖', max:  5 },
}

export function formatDate(iso: string | null): string {
  if (!iso) return 'Unknown'
  return new Date(iso).toLocaleDateString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
  })
}

export function formatRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins  = Math.floor(diff / 60_000)
  if (mins < 1)  return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24)  return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

export const PRESETS: Array<{ label: string; text: string; icon: string }> = [
  {
    icon: '🖥️',
    label: 'Equipment Scam',
    text: `Dear Applicant,

Congratulations! You have been selected for the position of Remote Data Entry Specialist at Global Staffing Solutions LLC. You will start immediately without an interview.

As part of your onboarding, we will send you a check for $3,500 to purchase your home office equipment. Please deposit the check and wire transfer $2,800 to our equipment supplier. You will keep the remaining $700 as your signing bonus.

Please confirm acceptance within 24 hours or the offer will be given to another candidate. Contact our HR coordinator on Telegram @globalstaffhr to proceed.

Do not discuss this offer with others until the equipment is purchased.

Best regards,
HR Department`,
  },
  {
    icon: '💸',
    label: 'Fake Check',
    text: `OFFER LETTER

We are pleased to offer you the role of Payment Processing Agent. Your primary duty will be to receive and forward client payments on behalf of our company.

You will receive cheques made out to you from our clients. You should deposit these into your personal bank account and then wire transfer 90% of the amount to our overseas accounts, keeping 10% as your commission.

This position does not require an interview. No experience necessary. Earn up to $500 per day from home!

Contact us via WhatsApp: +1-555-SCAM to get started today!`,
  },
  {
    icon: '🏠',
    label: 'Rental Deposit Scam',
    text: `Beautiful 2BR apartment available for $1,200/month. I am currently working overseas as a missionary and cannot show the property in person.

To secure the apartment, please send a security deposit of $2,400 via Western Union or Zelle before viewing. I will mail you the keys once payment is confirmed.

This is a limited time offer — another applicant is interested. Please respond within 24 hours.

Send payment to: missionarylandlord88@gmail.com`,
  },
  {
    icon: '🏦',
    label: 'Corporate Impersonation',
    text: `On behalf of Amazon Web Services, we are delighted to offer you the position of Cloud Solutions Architect.

Salary: $120,000/year
Start Date: Immediate

To complete your onboarding, you must pay a one-time background check fee of $150 and a training materials cost of $75 using CashApp ($AWSOnboarding).

Please provide your Social Security Number and bank routing number for payroll setup. Reply to hr-aws@gmail.com within 24 hours.`,
  },
  {
    icon: '✅',
    label: 'Legitimate Offer',
    text: `Dear Sarah,

We are delighted to offer you the position of Senior Software Engineer at Acme Corporation, effective October 1, 2025.

Compensation: $110,000 annually
Benefits: Full health, dental, and vision insurance; 401(k) with 4% match
Location: Austin, TX (hybrid, 3 days on-site)

Please review the attached employment agreement and return the signed copy to hr@acmecorp.com by September 27, 2025. If you have any questions, contact your recruiter at 512-555-0100.

We look forward to welcoming you to the team.

Best regards,
Emma Wilson
Director of Talent Acquisition
Acme Corporation`,
  },
]
