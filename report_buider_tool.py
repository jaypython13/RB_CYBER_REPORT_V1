# report_builder.py
from __future__ import annotations

import io, json
from dataclasses import dataclass
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, PageBreak, KeepTogether
)
from reportlab.pdfgen import canvas


# -------------------------------
# JSON loader
# -------------------------------
def load_json_from_text(text: str) -> Dict[str, Any]:
    return json.loads(text[text.find("{"):])


# -------------------------------
# Models
# -------------------------------
@dataclass
class Finding:
    number: int
    title: str
    status: str
    headline: str
    summary: str
    details: List[Tuple[str, str]]


def _status_color(status: str):
    return {
        "PASS": colors.HexColor("#2E7D32"),
        "RISK": colors.HexColor("#C62828"),
    }.get(status, colors.grey)


# -------------------------------
# Findings logic
# -------------------------------
def build_findings(hibp: Dict[str, Any], ssl: Dict[str, Any]) -> List[Finding]:
    findings = []

    # 1. Account compromise
    is_pwned = hibp.get("summary", {}).get("is_pwned", False)
    findings.append(Finding(
        1, "Account compromise",
        "RISK" if is_pwned else "PASS",
        "Bad News!" if is_pwned else "Great News!",
        "Checks whether the provided email address has appeared in known data breaches.",
        [("Email", hibp.get("email", "N/A")),
         ("Breaches found", str(hibp.get("summary", {}).get("breaches_found", 0)))]
    ))

    # 2. Credential exposure risk
    findings.append(Finding(
        2, "Credential exposure risk",
        "RISK" if is_pwned else "PASS",
        "Bad News!" if is_pwned else "Great News!",
        "Evaluates the likelihood of credential reuse and exposure based on breach data.",
        [("Credential exposure", "Detected" if is_pwned else "Not detected")]
    ))

    # 3. Website encryption
    grade = ssl.get("grade", "N/A")
    strong = grade in ("A", "A+")
    findings.append(Finding(
        3, "Website encryption",
        "PASS" if strong else "RISK",
        "Great News!" if strong else "Bad News!",
        "Reviews the overall TLS grade of the website using SSL Labs data.",
        [("Domain", ssl.get("domain", "N/A")),
         ("Overall grade", grade)]
    ))

    # 4. TLS configuration strength
    findings.append(Finding(
        4, "TLS configuration strength",
        "PASS" if strong else "RISK",
        "Great News!" if strong else "Bad News!",
        "Assesses the strength of TLS configuration and certificate handling.",
        [("Configuration strength", "Strong" if strong else "Weak")]
    ))

    return findings


# -------------------------------
# Header / Footer
# -------------------------------
def _draw_header_footer(c, doc, title, classification, reviewed, logo):
    w, h = A4
    if logo:
        try:
            c.drawImage(ImageReader(logo), 20*mm, h-22*mm, 28*mm, 14*mm)
        except Exception:
            pass

    c.setFont("Helvetica", 9)
    c.drawRightString(w-20*mm, h-15*mm, title)
    c.drawRightString(w-20*mm, h-22*mm, f"Classification: {classification}")
    c.drawString(20*mm, 10*mm, f"Last Reviewed: {reviewed}")
    c.drawRightString(w-20*mm, 10*mm, f"Page {doc.page}")


# -------------------------------
# PDF generator
# -------------------------------
def generate_pdf_bytes(
    business_name: str,
    email: str,
    website: str,
    hibp: Dict[str, Any],
    ssl: Dict[str, Any],
    classification="Confidential",
    last_reviewed=None,
    logo_path=None
) -> bytes:

    last_reviewed = last_reviewed or date.today().strftime("%d/%m/%Y")
    title = f"Cyber Health Check Report – {business_name}"
    findings = build_findings(hibp, ssl)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=28*mm, bottomMargin=18*mm
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("H1", fontSize=26))
    styles.add(ParagraphStyle("H2", fontSize=14))
    styles.add(ParagraphStyle("Body", fontSize=10, leading=14))

    story = []

    # Cover
    story += [
        Spacer(1, 40*mm),
        Paragraph("Cyber Health Check Report", styles["H1"]),
        Paragraph(business_name, styles["H1"]),
        PageBreak()
    ]

    # Document control
    story.append(Paragraph("Document Control", styles["H2"]))
    dc = Table([
        ["Version", "Date", "Description", "Author", "Approved By"],
        ["1.0", last_reviewed, "Initial release", "RB Consultancy", "Client"]
    ], colWidths=[20*mm, 30*mm, 50*mm, 30*mm, 30*mm])
    dc.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#E0E0E0"))
    ]))
    story += [dc, PageBreak()]

    # Contents
    story.append(Paragraph("Document Contents", styles["H2"]))
    contents = Table([
        ["Section", "Page"],
        ["Summary", "3"],
        ["Legal Disclaimer", "4"],
        ["NCSC Early Warning", "5"],
        ["High-Level Findings", "6"],
        ["Aim and Importance", "7"],
        ["Detailed Findings", "8+"],
        ["Considerations", "End"]
    ], colWidths=[120*mm, 30*mm])
    contents.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#E0E0E0"))
    ]))
    story += [contents, PageBreak()]

    # Summary
    story.append(Paragraph("Summary", styles["H2"]))
    story.append(Paragraph(
        f"This cyber health check is based on client-provided data.<br/><br/>"
        f"<b>Email:</b> {email}<br/><b>Website:</b> {website}",
        styles["Body"]
    ))
    story.append(PageBreak())

    # Legal Disclaimer
    story.append(Paragraph("Legal Disclaimer", styles["H2"]))
    story.append(Paragraph(
        "This report is provided for informational purposes only and does not constitute legal, "
        "technical, or professional advice. RB Consultancy Ltd accepts no liability for decisions "
        "made based on this report.",
        styles["Body"]
    ))
    story.append(PageBreak())

    # NCSC section (already validated exact text omitted here for brevity)
    story.append(Paragraph("Information to Support NCSC Early Warning", styles["H2"]))
    story.append(Paragraph(
        "The National Cyber Security Centre (NCSC) is the UK's technical authority on cyber security...",
        styles["Body"]
    ))
    story.append(PageBreak())

    # High-level findings
    story.append(Paragraph("High-Level Report Findings", styles["H2"]))
    hl = [["#", "Test", "Result", "Summary"]]
    for f in findings:
        hl.append([str(f.number), f.title, f.status, f.summary])

    t = Table(hl, colWidths=[10*mm, 50*mm, 20*mm, 80*mm])
    t.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#E0E0E0"))
    ]))
    story += [t, PageBreak()]

    # Aim & importance
    story.append(Paragraph("Aim and Importance", styles["H2"]))
    story.append(Paragraph(
        "The aim of this assessment is to raise awareness of cyber security risks "
        "and support informed decision-making.",
        styles["Body"]
    ))
    story.append(PageBreak())

    # Detailed findings
    for f in findings:
        story.append(Paragraph(f"{f.number}. {f.title}", styles["H2"]))
        story.append(Paragraph(f.summary, styles["Body"]))
        story.append(Spacer(1, 5*mm))
        dt = Table([["Metric", "Value"]] + f.details, colWidths=[60*mm, 90*mm])
        dt.setStyle(TableStyle([("GRID", (0,0), (-1,-1), 0.5, colors.grey)]))
        story += [dt, PageBreak()]

    # Considerations
    story.append(Paragraph("Considerations", styles["H2"]))
    story.append(Paragraph(
        "This report reflects a point-in-time review and should be supplemented "
        "with ongoing security monitoring and additional assessments.",
        styles["Body"]
    ))

    doc.build(
        story,
        onFirstPage=lambda c, d: _draw_header_footer(c, d, title, classification, last_reviewed, logo_path),
        onLaterPages=lambda c, d: _draw_header_footer(c, d, title, classification, last_reviewed, logo_path),
    )

    return buf.getvalue()
