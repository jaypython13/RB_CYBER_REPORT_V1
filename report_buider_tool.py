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


# ------------------------------------------------
# JSON helpers
# ------------------------------------------------
def load_json_from_text(text: str) -> Dict[str, Any]:
    return json.loads(text[text.find("{"):])


# ------------------------------------------------
# Data model
# ------------------------------------------------
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


# ------------------------------------------------
# Findings logic
# ------------------------------------------------
def build_findings(hibp: Dict[str, Any], ssl: Dict[str, Any]) -> List[Finding]:
    findings = []

    is_pwned = hibp.get("summary", {}).get("is_pwned", False)

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
                ("Breaches found", str(hibp.get("summary", {}).get("breaches_found", 0))),
                ("Scan date", hibp.get("scanned_at", "N/A")),
            ],
        )
    )

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


# ------------------------------------------------
# Header / Footer
# ------------------------------------------------
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


# ------------------------------------------------
# PDF generator
# ------------------------------------------------
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
            f"A cyber security health check has been carried out using information provided by the client.<br/><br/>"
            f"<b>Business name:</b> {business_name}<br/>"
            f"<b>Email:</b> {email}<br/>"
            f"<b>Website:</b> {website}<br/>",
            styles["Body"],
        ),
        PageBreak(),
    ]

    # ------------------------------------------------
    # NCSC EARLY WARNING (EXACT TEXT)
    # ------------------------------------------------
    story.append(Paragraph("Information to Support NCSC Early Warning", styles["H2"]))
    story.append(Paragraph(
        """The National Cyber Security Centre (NCSC) is the UK's technical authority on cyber security, dedicated to making the UK the safest place to live and work online. The NCSC provides a range of services to help organisations protect themselves and react to cyber threats. One of their key offerings is called ‘Early Warning’ and is aimed to provide notification about potential cyber security related threats such as malicious activity.<br/><br/>
        The NCSC have a mission to make the UK the safest place to work online, and as such they have made the Early Warning Service available to any sized organisation based in the UK. This includes public sector bodies, private companies of all sizes, charities and not for profits, educational institutes, healthcare providers and local authorities. There are thousands of organisations already signed up, but many thousands more that can sign-up.<br/><br/>
        <b>How it Works:</b><br/>
        • Timely Alerts: Provides notifications about potential cyber threats as soon as they’re detected by the NCSC. This (early warning) can give more opportunity to fix, before the situation gets worse<br/>
        • Reduced Risk: By receiving alerts about vulnerabilities and malicious activities, organisations can strengthen security controls and reduce the risk of a data breach<br/>
        • Free and Easy to Use: It’s a free service, that just requires sign-up. It’s also very easy to setup and use<br/>
        • Effective Communication: Having a point of contact aligned with the services, means the (early warning) alerts will be sent to the correct person, who can take action<br/>
        • Adds to Existing Security Controls: The Early Warning service can enhance and supplement the effectiveness of cyber security, by providing an additional layer of monitoring and alerting<br/>
        • Compliance Support: By helping organisations identify and address vulnerabilities, the service supports compliance with UK data protection regulations and other legal requirements<br/><br/>
        <b>To setup NCSC Early Warning for your organisation:</b><br/>
        1. Create a MyNCSC Account<br/>
        2. Register for the Service<br/>
        3. Reference Assets<br/>
        4. Review and Act on Alerts
        """,
        styles["Body"]
    ))
    story.append(PageBreak())

    # ------------------------------------------------
    # High-Level Findings
    # ------------------------------------------------
    story.append(Paragraph("High-Level Report Findings", styles["H2"]))

    table_data = [[
        Paragraph("<b>#</b>", styles["Body"]),
        Paragraph("<b>Test</b>", styles["Body"]),
        Paragraph("<b>Result</b>", styles["Body"]),
        Paragraph("<b>Headline</b>", styles["Body"]),
        Paragraph("<b>Summary</b>", styles["Body"]),
    ]]

    for f in findings:
        table_data.append([
            Paragraph(str(f.number), styles["Body"]),
            Paragraph(f.title, styles["Body"]),
            Paragraph(f"<font color='{_status_color(f.status).hexval()}'><b>{f.status}</b></font>", styles["Body"]),
            Paragraph(f.headline, styles["Body"]),
            Paragraph(f.summary, styles["Body"]),
        ])

    t = Table(table_data, colWidths=[10*mm, 45*mm, 18*mm, 30*mm, 57*mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E0E0E0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)
    story.append(PageBreak())

    # Aim and Importance
    story.append(Paragraph("Aim and Importance", styles["H2"]))
    story.append(Paragraph(
        "The aim of this health check is to raise awareness of cyber security risks and help determine "
        "whether further action is required to improve the organisation’s cyber security posture.",
        styles["Body"]
    ))
    story.append(PageBreak())

    # Detailed Findings
    for f in findings:
        story.append(Paragraph(f"{f.number}. {f.title}", styles["H2"]))
        story.append(Paragraph(f.summary, styles["Body"]))
        story.append(Spacer(1, 6*mm))

        dt = Table([["Metric", "Value"]] + f.details, colWidths=[60*mm, 100*mm])
        dt.setStyle(TableStyle([
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#EEEEEE")),
        ]))
        story.append(dt)
        story.append(PageBreak())

    # Considerations
    story.append(Paragraph("Considerations", styles["H2"]))
    story.append(Paragraph(
        "This report is generated using client-provided data extracts and should be considered a point-in-time assessment. "
        "RB Consultancy Ltd recommend regular reviews and additional security assessments for ongoing risk management.",
        styles["Body"]
    ))

    def on_page(c, d):
        _draw_header_footer(c, d, title, classification, last_reviewed, logo_path)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
