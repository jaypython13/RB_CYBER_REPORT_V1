# report_builder.py
from __future__ import annotations

import io
import json
from dataclasses import dataclass
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)
from reportlab.pdfgen import canvas


# -----------------------------
# JSON parsing helpers
# -----------------------------
def _strip_to_json(text: str) -> str:
    i = text.find("{")
    if i == -1:
        raise ValueError("No JSON object found.")
    return text[i:]


def _normalize_extended_json(obj: Any) -> Any:
    if isinstance(obj, dict):
        if "$date" in obj and len(obj) == 1:
            return obj["$date"]
        if "$numberLong" in obj and len(obj) == 1:
            try:
                return int(obj["$numberLong"])
            except Exception:
                return obj["$numberLong"]
        return {k: _normalize_extended_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_extended_json(x) for x in obj]
    return obj


def load_json_from_text(text: str) -> Dict[str, Any]:
    return _normalize_extended_json(json.loads(_strip_to_json(text)))


# -----------------------------
# Data model
# -----------------------------
@dataclass
class Finding:
    number: int
    title: str
    status: str
    headline: str
    summary: str
    details: List[Tuple[str, str]]


def _status_color(status: str) -> colors.Color:
    return {
        "PASS": colors.HexColor("#2E7D32"),
        "RISK": colors.HexColor("#C62828"),
    }.get(status, colors.HexColor("#616161"))


# -----------------------------
# Findings builder
# -----------------------------
def build_findings(hibp: Dict[str, Any], ssl: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []

    # 1. Account compromise
    hibp_summary = hibp.get("summary", {})
    is_pwned = bool(hibp_summary.get("is_pwned", False))

    findings.append(
        Finding(
            1,
            "Account compromise",
            "RISK" if is_pwned else "PASS",
            "Bad News!" if is_pwned else "Great News!",
            "Our dark web research indicates your email address "
            f"{'has' if is_pwned else 'has not'} been recorded as part of known data breaches.",
            [
                ("Email", hibp.get("email", "N/A")),
                ("Breaches found", str(hibp_summary.get("breaches_found", 0))),
                ("Pastes found", str(hibp_summary.get("pastes_found", 0))),
                ("Scan date", str(hibp.get("scanned_at", "N/A"))),
            ],
        )
    )

    # 2. Website encryption (SSL Labs)
    grade = ssl.get("grade", "N/A")
    good = grade in ("A", "A+")

    findings.append(
        Finding(
            2,
            "Website encryption",
            "PASS" if good else "RISK",
            "Great News!" if good else "Bad News!",
            "Our research indicates your website "
            f"{'has' if good else 'does not have'} strong encryption controls in place.",
            [
                ("Domain", ssl.get("domain", "N/A")),
                ("IP address", ssl.get("ip_address", "N/A")),
                ("Overall grade", grade),
                ("Scan date", ssl.get("scanned_at", "N/A")),
            ],
        )
    )

    return findings


# -----------------------------
# Header / Footer
# -----------------------------
def _draw_header_footer(c, doc, title, classification, reviewed, logo):
    width, height = A4

    if logo:
        try:
            c.drawImage(
                ImageReader(logo),
                20 * mm,
                height - 22 * mm,
                width=28 * mm,
                height=14 * mm,
                preserveAspectRatio=True,
                mask="auto",
            )
        except Exception:
            pass

    c.setFont("Helvetica", 10)
    c.drawRightString(width - 20 * mm, height - 15 * mm, title)
    c.setFont("Helvetica", 9)
    c.drawRightString(width - 20 * mm, height - 22 * mm, f"Version: 1.0  Classification: {classification}")

    c.drawString(20 * mm, 12 * mm, f"Last Reviewed: {reviewed}")
    c.drawString(20 * mm, 6 * mm, "Document Owner: RB Consultancy Ltd")
    c.drawRightString(width - 20 * mm, 12 * mm, f"Page {doc.page}")


# -----------------------------
# PDF generator
# -----------------------------
def generate_pdf_bytes(
    business_name: str,
    email: str,
    website: str,
    hibp: Dict[str, Any],
    ssl: Dict[str, Any],
    classification: str = "Confidential",
    last_reviewed: Optional[str] = None,
    logo_path: Optional[str] = None,
) -> bytes:

    last_reviewed = last_reviewed or date.today().strftime("%d/%m/%Y")
    title = f"Cyber Health Check Report {business_name}"
    findings = build_findings(hibp, ssl)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=28 * mm,
        bottomMargin=18 * mm,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("H1", fontSize=26, spaceAfter=16))
    styles.add(ParagraphStyle("H2", fontSize=14, spaceAfter=10))
    styles.add(ParagraphStyle("Body", fontSize=10, leading=14))

    story: List[Any] = []

    # Cover
    story += [
        Spacer(1, 30 * mm),
        Paragraph("Cyber Health Check Report", styles["H1"]),
        Paragraph(business_name, styles["H1"]),
        PageBreak(),
    ]

    # Summary
    story += [
        Paragraph("Summary", styles["H2"]),
        Paragraph(
            f"RB Consultancy Ltd have been requested to carry out a cyber security health check for "
            f"{business_name}. The report is based on the following information provided:<br/><br/>"
            f"<b>Business name:</b> {business_name}<br/>"
            f"<b>Email:</b> {email}<br/>"
            f"<b>Website:</b> {website}<br/>",
            styles["Body"],
        ),
        PageBreak(),
    ]

    # -------------------------------------------------
    # NCSC EARLY WARNING SECTION (NEW)
    # -------------------------------------------------
    story.append(Paragraph("Information to Support NCSC Early Warning", styles["H2"]))
    story.append(
        Paragraph(
            "The National Cyber Security Centre (NCSC) is the UK’s technical authority on cyber security "
            "and provides services to help organisations protect themselves from cyber threats. One of "
            "their key services is the Early Warning service, which provides notification of potential "
            "cyber security related threats such as malicious activity.<br/><br/>"
            "The Early Warning service is free to use and is available to organisations of any size "
            "based in the UK, including private companies, charities, public sector bodies and educational "
            "institutions.<br/><br/>"
            "<b>Key benefits include:</b><br/>"
            "• Timely alerts about detected cyber threats<br/>"
            "• Reduced risk through early identification of vulnerabilities<br/>"
            "• Easy setup and effective communication to the right contacts<br/>"
            "• Additional monitoring to support existing security controls<br/>"
            "• Support for compliance with UK data protection regulations<br/><br/>"
            "<b>To set up the service:</b><br/>"
            "1. Create a MyNCSC account<br/>"
            "2. Register your organisation for the Early Warning service<br/>"
            "3. Add and manage your assets (domains and IP addresses)<br/>"
            "4. Review alerts and take action where required",
            styles["Body"],
        )
    )
    story.append(PageBreak())

    # High-Level Findings
    story.append(Paragraph("High-Level Report Findings", styles["H2"]))

    hl_rows = [[
        Paragraph("<b>#</b>", styles["Body"]),
        Paragraph("<b>Test</b>", styles["Body"]),
        Paragraph("<b>Result</b>", styles["Body"]),
        Paragraph("<b>Headline</b>", styles["Body"]),
        Paragraph("<b>Summary</b>", styles["Body"]),
    ]]

    for f in findings:
        hl_rows.append([
            Paragraph(str(f.number), styles["Body"]),
            Paragraph(f.title, styles["Body"]),
            Paragraph(
                f"<font color='{_status_color(f.status).hexval()}'><b>{f.status}</b></font>",
                styles["Body"],
            ),
            Paragraph(f.headline, styles["Body"]),
            Paragraph(f.summary, styles["Body"]),
        ])

    hl = Table(hl_rows, colWidths=[10 * mm, 45 * mm, 18 * mm, 30 * mm, 57 * mm], repeatRows=1)
    hl.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E0E0E0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("ALIGN", (2, 1), (2, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(hl)

    def on_page(c, d):
        _draw_header_footer(c, d, title, classification, last_reviewed, logo_path)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
