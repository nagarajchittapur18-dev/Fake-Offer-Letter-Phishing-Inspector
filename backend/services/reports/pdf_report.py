"""
PDF forensic report generator using ReportLab.
"""
from __future__ import annotations

import io
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


_RISK_COLORS = {
    "CRITICAL":   colors.HexColor("#ef4444"),
    "HIGH":       colors.HexColor("#f97316"),
    "SUSPICIOUS": colors.HexColor("#f59e0b"),
    "LOW":        colors.HexColor("#22c55e"),
}

_SEV_COLORS = {
    "Critical": colors.HexColor("#ef4444"),
    "High":     colors.HexColor("#f97316"),
    "Medium":   colors.HexColor("#f59e0b"),
    "Low":      colors.HexColor("#3b82f6"),
}


def generate_pdf_report(result: dict) -> bytes:
    """
    Accept a ScanResponse dict and return PDF bytes.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm,
        leftMargin=2 * cm, rightMargin=2 * cm,
    )

    styles   = getSampleStyleSheet()
    elements = []

    # ── Header ─────────────────────────────────────────────────────────────────
    header_style = ParagraphStyle(
        "Header",
        parent=styles["Title"],
        fontSize=20,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=6,
        alignment=TA_CENTER,
    )
    sub_style = ParagraphStyle(
        "Sub",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.grey,
        alignment=TA_CENTER,
    )

    elements.append(Paragraph("🔍 Phishing & Fraud Inspection Report", header_style))
    elements.append(Paragraph("Fake Offer Letter & Phishing Inspector — V2", sub_style))
    elements.append(Spacer(1, 0.4 * cm))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    elements.append(Spacer(1, 0.4 * cm))

    # ── Threat Index summary ───────────────────────────────────────────────────
    threat_index = result.get("threat_index", 0)
    risk_level   = result.get("risk_level", "LOW")
    risk_color   = _RISK_COLORS.get(risk_level, colors.grey)

    summary_data = [
        ["Scan ID",       result.get("scan_id", "—")],
        ["Scanned At",    result.get("scanned_at", "—")],
        ["Input Type",    result.get("input_type", "—").upper()],
        ["Threat Index",  f"{threat_index:.1f} / 100"],
        ["Risk Level",    risk_level],
        ["Verdict",       result.get("verdict_summary", "—")],
    ]

    tbl = Table(summary_data, colWidths=[4 * cm, 13 * cm])
    tbl.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (-1, -1), "Helvetica"),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING",     (0, 0), (-1, -1), 5),
        ("TEXTCOLOR",   (1, 3), (1, 3), risk_color),
        ("FONTNAME",    (1, 3), (1, 3), "Helvetica-Bold"),
        ("FONTSIZE",    (1, 3), (1, 3), 12),
        ("TEXTCOLOR",   (1, 4), (1, 4), risk_color),
        ("FONTNAME",    (1, 4), (1, 4), "Helvetica-Bold"),
    ]))
    elements.append(tbl)
    elements.append(Spacer(1, 0.6 * cm))

    # ── Score breakdown ────────────────────────────────────────────────────────
    elements.append(Paragraph("<b>Score Breakdown</b>", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * cm))

    breakdown = result.get("score_breakdown", {})
    cat_rows  = [
        ["Category",                    "Score", "Max"],
        ["Financial / Payment Risk",    str(breakdown.get("financial_payment",   0)), "25"],
        ["Urgency / Coercion",          str(breakdown.get("urgency_coercion",    0)), "10"],
        ["Recruitment Anomaly",         str(breakdown.get("recruitment_anomaly", 0)), "10"],
        ["Email Provider Risk",         str(breakdown.get("email_provider",      0)), "10"],
        ["Organisation Mismatch",       str(breakdown.get("org_mismatch",        0)), "15"],
        ["Domain Intelligence",         str(breakdown.get("domain_intelligence", 0)), "15"],
        ["URL Risk",                    str(breakdown.get("url_risk",            0)), "10"],
        ["AI Semantic Confirmation",    str(breakdown.get("ai_semantic",         0)),  "5"],
        ["TOTAL",                       f"{threat_index:.0f}",                       "100"],
    ]

    bt = Table(cat_rows, colWidths=[10 * cm, 2.5 * cm, 2.5 * cm])
    bt.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTNAME",  (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f1f5f9")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID",      (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ALIGN",     (1, 0), (-1, -1), "CENTER"),
        ("FONTSIZE",  (0, 0), (-1, -1), 9),
        ("PADDING",   (0, 0), (-1, -1), 5),
    ]))
    elements.append(bt)
    elements.append(Spacer(1, 0.6 * cm))

    # ── Risk signals ───────────────────────────────────────────────────────────
    signals = result.get("risk_signals", [])
    if signals:
        elements.append(Paragraph("<b>Detected Risk Signals</b>", styles["Heading2"]))
        elements.append(Spacer(1, 0.2 * cm))

        sig_data = [["Category", "Severity", "Score", "Evidence"]]
        for sig in signals:
            sev_color = _SEV_COLORS.get(sig.get("severity", "Low"), colors.grey)
            sig_data.append([
                sig.get("category", ""),
                sig.get("severity", ""),
                str(sig.get("score_contribution", 0)),
                sig.get("evidence", "")[:80],
            ])

        st = Table(sig_data, colWidths=[4 * cm, 2 * cm, 1.5 * cm, 9.5 * cm])
        st.setStyle(TableStyle([
            ("FONTNAME",  (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("GRID",      (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("FONTSIZE",  (0, 0), (-1, -1), 8),
            ("PADDING",   (0, 0), (-1, -1), 4),
            ("VALIGN",    (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(st)
        elements.append(Spacer(1, 0.6 * cm))

    # ── Recommendations ────────────────────────────────────────────────────────
    recs = result.get("recommendations", [])
    if recs:
        elements.append(Paragraph("<b>Safety Recommendations</b>", styles["Heading2"]))
        elements.append(Spacer(1, 0.2 * cm))
        for i, rec in enumerate(recs, 1):
            elements.append(Paragraph(
                f"<b>{i}.</b> {rec}",
                ParagraphStyle("rec", parent=styles["Normal"], fontSize=9, spaceAfter=6),
            ))
        elements.append(Spacer(1, 0.4 * cm))

    # ── Footer ─────────────────────────────────────────────────────────────────
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
    elements.append(Spacer(1, 0.2 * cm))
    elements.append(Paragraph(
        "This report was generated automatically by the Fake Offer Letter & Phishing Inspector. "
        "It is provided for informational purposes only and does not constitute legal advice. "
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        ParagraphStyle("footer", parent=styles["Normal"], fontSize=7, textColor=colors.grey, alignment=TA_CENTER),
    ))

    doc.build(elements)
    return buf.getvalue()
