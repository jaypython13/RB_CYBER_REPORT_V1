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
# Robust JSON loading
# -----------------------------
def _strip_to_json(text: str) -> str:
    """
    Some exports include comment headers. We parse from first '{'.
    """
    i = text.find("{")
    if i == -1:
        raise ValueError("No JSON object found in input text.")
    return text[i:]


def _normalize_extended_json(obj: Any) -> Any:
    """
    Handles extended JSON formats like:
      {"$date": "..."} or {"$numberLong": "..."}
    """
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
    raw = _strip_to_json(text)
    data = json.loads(raw)
    return _normalize_extended_json(data)


# -----------------------------
# Findings model
# -----------------------------
@dataclass
class Finding:
    number: int
    title: str
    status: str  # PASS / RISK / N/A
    headline: str
    summary: str
    details: List[Tuple[str, str]]


def _status_color(status: str) -> colors.Color:
    if status == "PASS":
        return colors.HexColor("#2E7D32")
    if status == "RISK":
        return colors.HexColor("#C62828")
    return colors.HexColor("#616161")


# -----------------------------
# Build findings from your files
# -----------------------------
def build_findings(hibp: Dict[str, Any], ssl: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []

    # 1) Account compromise (HIBP)
    hibp_summary = hibp.get("summary", {})
    breaches_found = int(hibp_summary.get("breaches_found", 0) or 0)
    pastes_found = int(hibp_summary.get("pastes_found", 0) or 0)
    is_pwned = bool(hibp_summary.get("is_pwned", False))

    breaches = [
        b.get("Name")
        for b in (hibp.get("raw", {}).get("breaches") or [])
        if isinstance(b, dict)
    ]
    breaches = [x for x in breaches if x]

    status = "RISK" if is_pwned else "PASS"
    headline = "Bad News!" if is_pwned else "Great News!"
    summary = (
        "Our dark web research indicates your email address "
        f"{'has' if is_pwned else 'has not'} been recorded as part of "
        f"{'one or more' if is_pwned else 'any'} data breaches."
    )

    findings.append(
        Finding(
            number=1,
            title="Account compromise",
            status=status,
            headline=headline,
            summary=summary,
            details=[
                ("Email", str(hibp.get("email", "N/A"))),
                ("Breaches found", str(breaches_found)),
                ("Pastes found", str(pastes_found)),
                ("Breaches", ", ".join(breaches) if breaches else "None"),
                ("Scan date", str(hibp.get("scanned_at", "N/A"))),
            ],
        )
    )

    # 2) Website encryption (SSL Labs)
    grade = ssl.get("grade") or "N/A"
    domain = ssl.get("domain") or ssl.get("raw", {}).get("host") or "N/A"
    ip_addr = ssl.get("ip_address") or "N/A"
    scanned_at = ssl.get("scanned_at") or "N/A"

    if grade in ("A+", "A"):
        status = "PASS"
        headline = "Great News!"
        summary = "Our research indicates your website has a strong TLS configuration."
    elif grade == "N/A":
        status = "N/A"
        headline = "N/A"
        summary = "No SSL Labs grade was available in the provided data."
    else:
        status = "RISK"
        headline = "Bad News!"
        summary = "Our research indicates your website TLS grade is below A, which may increase exposure to attack."

    endpoints = (ssl.get("raw", {}) or {}).get("endpoints") or []
    ep0 = endpoints[0] if endpoints else {}
    details_obj = (ep0.get("details") or {}) if isinstance(ep0, dict) else {}

    protocols = details_obj.get("protocols") or []
    protocol_names: List[str] = []
    for p in protocols:
        if isinstance(p, dict):
            protocol_names.append(f"{p.get('name', 'TLS')} {p.get('version', '')}".strip())
    protocol_list = ", ".join(protocol_names) if protocol_names else "N/A"

    findings.append(
        Finding(
            number=2,
            title="Website encryption",
            status=status,
            headline=headline,
            summary=summary,
            details=[
                ("Domain", domain),
                ("IP address", ip_addr),
                ("Overall grade", str(grade)),
                ("Supported protocols", protocol_list),
                ("BEAST vulnerability flag", str(details_obj.get("vulnBeast")) if details_obj.get("vulnBeast") is not None else "N/A"),
                ("OCSP stapling", str(details_obj.get("ocspStapling")) if details_obj.get("ocspStapling") is not None else "N/A"),
                ("RC4 supported", str(details_obj.get("supportsRc4")) if details_obj.get("supportsRc4") is not None else "N/A"),
                ("Scan date", str(scanned_at)),
            ],
        )
    )

    # 3) Legacy TLS (1.0/1.1)
    has_tls10 = any("1.0" in x for x in protocol_names)
    has_tls11 = any("1.1" in x for x in protocol_names)
    legacy = has_tls10 or has_tls11

    if not protocol_names:
        status = "N/A"
        headline = "N/A"
        summary = "No protocol information was available in the provided data."
    else:
        status = "RISK" if legacy else "PASS"
        headline = "Bad News!" if legacy else "Great News!"
        summary = (
            "Our research indicates your website supports legacy TLS versions (1.0/1.1), which can reduce transport security."
            if legacy
            else "Our research indicates your website does not advertise legacy TLS 1.0/1.1 support."
        )

    findings.append(
        Finding(
            number=3,
            title="Website encryption downgrade (legacy TLS)",
            status=status,
            headline=headline,
            summary=summary,
            details=[
                ("TLS 1.0 supported", str(has_tls10) if protocol_names else "N/A"),
                ("TLS 1.1 supported", str(has_tls11) if protocol_names else "N/A"),
                ("Supported protocols", protocol_list),
            ],
        )
    )

    return findings


# -----------------------------
# Header/footer with RB logo (top-left)
# -----------------------------
def _draw_header_footer(
    c: canvas.Canvas,
    doc,
    report_title: str,
    classification: str,
    last_reviewed: str,
    logo_path: Optional[str],
):
    width, height = A4

    # Logo on top-left of every page
    if logo_path:
        try:
            logo = ImageReader(logo_path)
            c.drawImage(
                logo,
                20 * mm,
                height - 22 * mm,
                width=28 * mm,
                height=14 * mm,
                preserveAspectRatio=True,
                mask="auto",
            )
        except Exception:
            pass

    # Header text (right)
    c.setFont("Helvetica", 10)
    c.drawRightString(width - 20 * mm, height - 15 * mm, report_title)
    c.setFont("Helvetica", 9)
    c.drawRightString(width - 20 * mm, height - 22 * mm, f"Version: 1.0  Classification: {classification}")

    # Footer
    c.setFont("Helvetica", 9)
    c.drawString(20 * mm, 12 * mm, f"Last Reviewed: {last_reviewed}")
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
    report_title = f"Cyber Health Check Report {business_name}"
    findings = build_findings(hibp, ssl)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=28 * mm,
        bottomMargin=18 * mm,
        title=report_title,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="H1", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=26, spaceAfter=14))
    styles.add(ParagraphStyle(name="H2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=14, spaceAfter=10))
    styles.add(ParagraphStyle(name="Body", parent=styles["BodyText"], fontName="Helvetica", fontSize=10, leading=14))

    story: List[Any] = []

    # Cover
    story.append(Spacer(1, 25 * mm))
    story.append(Paragraph("Cyber Health Check Report", styles["H1"]))
    story.append(Paragraph(business_name, styles["H1"]))
    story.append(PageBreak())

    # Contents
    story.append(Paragraph("Document Contents Page", styles["H2"]))
    contents_data = [
        ["Summary", "3"],
        ["Information to Support NCSC Early Warning", "4"],
        ["High-Level Report Findings", "5"],
        ["Aim and Importance", "9"],
        ["Considerations", "16"],
    ]
    t = Table(contents_data, colWidths=[120 * mm, 30 * mm])
    t.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (-1, -1), "Helvetica", 10),
                ("LINEBELOW", (0, 0), (-1, 0), 1, colors.black),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(t)
    story.append(PageBreak())

    # Summary
    story.append(Paragraph("Summary", styles["H2"]))
    story.append(
        Paragraph(
            "A cyber security health check has been carried out and this report shows the associated findings.<br/><br/>"
            f"<b>Business name:</b> {business_name}<br/>"
            f"<b>Email:</b> {email}<br/>"
            f"<b>Website:</b> {website}<br/><br/>"
            "Tests included in this generated report (based on the provided data files):<br/><br/>"
            "1. Email compromise (HaveIBeenPwned extract)<br/>"
            "2. Website TLS posture (SSL Labs extract)<br/>",
            styles["Body"],
        )
    )
    story.append(PageBreak())

    # -------------------------------------------------------
    # Information to Support NCSC Early Warning 
    # -------------------------------------------------------
    story.append(Paragraph("Information to Support NCSC Early Warning", styles["H2"]))
    story.append(
        Paragraph(
            "The National Cyber Security Centre (NCSC) is the UK's technical authority on cyber security, "
            "dedicated to making the UK the safest place to live and work online. The NCSC provides a range "
            "of services to help organisations protect themselves and react to cyber threats. One of their "
            "key offerings is called ‘Early Warning’ and is aimed to provide notification about potential "
            "cyber security related threats such as malicious activity.<br/><br/>"

            "The NCSC have a mission to make the UK the safest place to work online, and as such they have "
            "made the Early Warning Service available to any sized organisation based in the UK. This "
            "includes public sector bodies, private companies of all sizes, charities and not for profits, "
            "educational institutes, healthcare providers and local authorities. There are thousands of "
            "organisations already signed up, but many thousands more that can sign-up.<br/><br/>"

            "<b>How it Works:</b><br/><br/>"
            "• Timely Alerts: Provides notifications about potential cyber threats as soon as they’re "
            "detected by the NCSC. This (early warning) can give more opportunity to fix, before the "
            "situation gets worse<br/><br/>"
            "• Reduced Risk: By receiving alerts about vulnerabilities and malicious activities, "
            "organisations can strengthen security controls and reduce the risk of a data breach<br/><br/>"
            "• Free and Easy to Use: It’s a free service, that just requires sign-up. It’s also very easy "
            "to setup and use<br/><br/>"
            "• Effective Communication: Having a point of contact aligned with the services, means the "
            "(early warning) alerts will be sent to the correct person, who can take action.<br/><br/>"
            "• Adds to Existing Security Controls: The Early Warning service can enhance and supplement "
            "the effectiveness of cyber security, by providing an additional layer of monitoring and "
            "alerting<br/><br/>"
            "• Compliance Support: By helping organisations identify and address vulnerabilities, the "
            "service supports compliance with UK data protection regulations and other legal requirements<br/><br/>"

            "<b>To setup NCSC Early Warning for your organisation:</b><br/><br/>"
            "1. Create a MyNCSC Account: Organisations need to first create a MyNCSC account (unless "
            "already holding one). This can be done by visiting the NCSC website and following the "
            "registration instructions<br/><br/>"
            "2. Register for the Service: For the registration process, organisations provide their name "
            "and/or company number. This is then reviewed and approved by the NCSC.<br/><br/>"
            "3. Reference Assets: Once registered, organisations can setup their assets (domain names and "
            "IP addresses) within the MyNCSC Early Warning system. Asset can also be detected automatically, "
            "based on the information provided. Members and points of contact can also be setup<br/><br/>"
            "4. Review and Act on Alerts: After setting up the service, organisations will start receiving "
            "alerts about potential threats – this can be received via email and through the MyNCSC portal. "
            "It’s important to review these alerts promptly and take appropriate actions to mitigate any "
            "identified risks.",
            styles["Body"],
        )
    )
    story.append(PageBreak())

    # -------------------------------------------------------
    # High-Level Findings (FIXED: wrapped text + alignment)
    # -------------------------------------------------------
    story.append(Paragraph("High-Level Report Findings", styles["H2"]))

    hl_rows = [
        [
            Paragraph("<b>#</b>", styles["Body"]),
            Paragraph("<b>Test</b>", styles["Body"]),
            Paragraph("<b>Result</b>", styles["Body"]),
            Paragraph("<b>Headline</b>", styles["Body"]),
            Paragraph("<b>Summary</b>", styles["Body"]),
        ]
    ]

    for f in findings:
        hl_rows.append(
            [
                Paragraph(str(f.number), styles["Body"]),
                Paragraph(f.title, styles["Body"]),
                Paragraph(
                    f"<font color='{_status_color(f.status).hexval()}'><b>{f.status}</b></font>",
                    styles["Body"],
                ),
                Paragraph(f.headline, styles["Body"]),
                Paragraph(f.summary, styles["Body"]),
            ]
        )

    hl = Table(
        hl_rows,
        colWidths=[
            10 * mm,  # #
            40 * mm,  # Test
            18 * mm,  # Result
            28 * mm,  # Headline
            64 * mm,  # Summary
        ],
        repeatRows=1,
    )

    hl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E0E0E0")),
                ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 10),

                ("FONT", (0, 1), (-1, -1), "Helvetica", 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),

                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (0, 0), (0, -1), "CENTER"),  # #
                ("ALIGN", (2, 1), (2, -1), "CENTER"),  # Result

                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),

                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAFAFA")]),
            ]
        )
    )

    story.append(hl)
    story.append(PageBreak())



    # Detailed Findings
    for f in findings:
        story.append(Paragraph(f"{f.number}. {f.title}", styles["H2"]))
        story.append(
            Paragraph(
                f"<b>Result:</b> <font color='{_status_color(f.status).hexval()}'>{f.status}</font> &nbsp;&nbsp;"
                f"<b>{f.headline}</b>",
                styles["Body"],
            )
        )
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(f.summary, styles["Body"]))
        story.append(Spacer(1, 6 * mm))

        detail_table = Table(
            [["Metric", "Value"]] + [[k, v] for (k, v) in f.details],
            colWidths=[55 * mm, 105 * mm],
        )
        detail_table.setStyle(
            TableStyle(
                [
                    ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 10),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEEEEE")),
                    ("FONT", (0, 1), (-1, -1), "Helvetica", 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(KeepTogether(detail_table))
        story.append(PageBreak())
    # -------------------------------------------------------
    # Aim and Importance
    # -------------------------------------------------------
    story.append(Paragraph("Aim and Importance", styles["H2"]))
    story.append(
        Paragraph(
            "The aim of the health check is to raise awareness of the cyber security related risks and to "
            "help consider whether action should be taken.<br/><br/>"

            "For each test the following criteria has been expanded on to support understanding, importance "
            "and decision making:<br/><br/>"
            
            "• Impact – what a potential failed test might lead to.<br/><br/>"
            "• Example – more specific cyberattack technique that could be faced and/or example of financial impact.<br/><br/>"
            "• Data privacy and protection – reference to United Kingdom and European Union General Data Protection Regulations "
            "(UK and EU GDPR) and California Consumer Privacy Act (CCPA).<br/><br/>"
            "• Potential Resolution – action that may be considered to reduce the risk.<br/><br/>"
            "• Resolution risk – impact that may need to be considered as a result of implementing action to reduce the risk.<br/><br/>"
            "• To pass our test – criteria that we have set to pass the test.<br/><br/>"
            "• Key metric / perspective – insight on how wide-spread the risk may be.<br/><br/>"

            "<b>1. Account compromise</b><br/><br/>"
            
            "• Impact - your account password may be known and/or your email / data may be accessible to others.<br/><br/>"
            "• Example – ‘credential stuffing’ is a technique used by bad actors, where password / username combinations are tried "
            "on multiple websites, data breaches often involve this type of attack.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – change password (wherever it is used), use unique / strong passwords, enable "
            "multi-factor authentication (MFA), change answers to any security questions.<br/><br/>"
            "• Resolution risk – new password may be forgotten and/or MFA may not be strong enough (consider using a password "
            "manager and Google / Microsoft authenticator).<br/><br/>"
            "• To pass our test - your email address must not show in a list of known compromised accounts from a dark web search.<br/><br/>"
            "• Key metric / perspective – Over 14 billion email accounts appear in this test based on our (external) 2024 data source.<br/><br/>"

            "<b>2. Email anti-spoofing protection</b><br/><br/>"
            
            "• Impact – other people may be sending email that appears to be from you.<br/><br/>"
            "• Example – ‘spoofing’ is a technique used by bad actors, where emails are sent that impersonate company employees, "
            "financial implications can often be experienced from this type of attack.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – review and update configuration settings on your DNS and email platforms.<br/><br/>"
            "• Resolution risk – failed email delivery due to strict policy enforcement changes.<br/><br/>"
            "• To pass our test – your email platform must have a strong Domain Based Message Authentication Reporting and "
            "Conformance (DMARC) policy in place (set to quarantine or reject) and no errors in Sender Policy Framework (SPF) settings.<br/><br/>"
            "• Key metric / perspective – Approximately 45% of domains should pass this test based on our (external) 2024 data source.<br/><br/>"

            "<b>3. Email encryption (privacy)</b><br/><br/>"
            
            "• Potential Impact – other people may be reading the emails that you send and receive.<br/><br/>"
            "• Example – ‘man-in the-middle’ attack is a technique used by bad actors, where they read and potentially alter communications.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – review and update configuration settings on your email platform.<br/><br/>"
            "• Resolution risk – failed email delivery due to compatibility and/or configuration.<br/><br/>"
            "• To pass our test – an up-to-date version of Transport Layer Security (TLS) must be detected on your email platform.<br/><br/>"
            "• Key metric / perspective – Approximately 85% of email domains should pass this test based on our (external) 2024 data source.<br/><br/>"

            "<b>4. Email encryption downgrade (privacy)</b><br/><br/>"
            
            "• Potential Impact – other people may be reading the emails that you send and receive.<br/><br/>"
            "• Example – ‘man-in-the-middle’ attack is a technique used by bad actors, where they read and potentially alter communications.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – review and update configuration settings on your email hosting platform.<br/><br/>"
            "• Resolution risk – failed email delivery due to compatibility and/or configuration.<br/><br/>"
            "• To pass our test – Your email platform must have Mail Transfer Agent-Strict Transport Security (MTA-SPS) settings "
            "applied to enforce mode and no errors.<br/><br/>"
            "• Key metric / perspective – Approximately 1% of domains should pass this test based on our (external) 2024 data source.<br/><br/>"

            "<b>5. Public IP address vulnerability</b><br/><br/>"
            "• Potential Impact – systems weaknesses could be exploited, leading to data compromise.<br/><br/>"
            "• Example – ‘exploitation’ attack is a technique used by bad actors, to scan and detect known vulnerabilities, then exploit weakness<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – review, remove and/or block access to known weaknesses that are associated with your public IP address.<br/><br/>"
            "• Resolution risk – service disruption, misconfiguration and compatibility issues on hosts that have been changed.<br/><br/>"
            "• To pass our test – no vulnerabilities must be detected on your public IP address.<br/><br/>"
            "• Key metric / perspective – Approximately 80% of public IP addresses should pass this test based on our (external) 2023 data source.<br/><br/>"

            "<b>6. Website malicious software</b><br/><br/>"
            "• Potential Impact – your website may be infected with malicious software.<br/><br/>"
            "• Example – ‘drive by downloads’ are a type of attack used by bad actors, whereby user devices are infected simply by visiting the site.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – isolate, clean, recover and secure your web server.<br/><br/>"
            "• Resolution risk – service disruption, misconfiguration and compatibility issues on website due to change<br/><br/>"
            "• To pass our test – your website must not have malware detected by scanners.<br/><br/>"
            "• Key metric / perspective – Approximately 93% of websites should pass this test based on our (external) 2024 data source.<br/><br/>"

            "<b>7. Website blacklisting</b><br/><br/>"
            "• Potential Impact – your website may be infected with malicious software.<br/><br/>"
            "• Example – ‘website blacklisting’ can lead to websites being blocked by search engines and security tools.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – isolate, clean, recover and secure your web server and request removal from blacklist.<br/><br/>"
            "• Resolution risk – service disruption, misconfiguration and compatibility issues on website due to change.<br/><br/>"
            "• To pass our test – your website must not appear on a blacklist site lists.<br/><br/>"
            "• Key metric / perspective – Approximately 99% of websites should pass this test based on our (external) 2024 data source.<br/><br/>"

            "<b>8. Website encryption</b><br/><br/>"
            "• Potential Impact – communication to / from your website may be read by others.<br/><br/>"
            "• Example – ‘man-in-the-middle’ attacks can take place on websites without strong encryption.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – ensure your website has strong encryption in place.<br/><br/>"
            "• Resolution risk – service disruption, misconfiguration and compatibility issues on website due to change.<br/><br/>"
            "• To pass our test – your website must be identified to use TLS 1.2 or above and must not support weak encryption.<br/><br/>"
            "• Key metric / perspective – Approximately 97% of websites should pass this test based on our (external) 2024 data source.<br/><br/>"

            "<b>9. Website privacy notice</b><br/><br/>"
            "• Potential Impact – you may not be informing website visitors that their personal data is being collected.<br/><br/>"
            "• Example – Google (2019) and Facebook (2018) have both experienced heavy fines.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – ensure your website has an appropriate privacy policy.<br/><br/>"
            "• Resolution risk – legal considerations for content of notice.<br/><br/>"
            "• To pass our test – your website must have a clear option to enable viewing of a privacy notice.<br/><br/>"
            "• Key metric / perspective – Approximately 36% of websites should pass this test based on our (external) 2024 data source.<br/><br/>"

            "<b>10. Website cookies notice</b><br/><br/>"
            "• Potential Impact – you may be collecting data from website visitors without their consent.<br/><br/>"
            "• Example – Sephora (2022) were fined around $1.2m in relation to cookies.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – ensure your website has an appropriate cookies policy.<br/><br/>"
            "• Resolution risk – challenges with technical review of cookies and legal considerations for content of notice.<br/><br/>"
            "• To pass our test – your website must have a clear option to enable viewing of a dedicated cookies notice.<br/><br/>"
            "• Key metric / perspective – Approximately 36% of websites should pass this test based on our (external) 2024 data source.<br/><br/>"

            "<b>11. Website cookies rejection (before usage)</b><br/><br/>"
            "• Potential Impact – you may be collecting data from website visitors without their consent.<br/><br/>"
            "• Example – Google (2021) were fined around $150m for not providing a straight forward way to reject cookies.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – ensure your website has an appropriate banner or button to reject non-essential cookies<br/><br/>"
            "• Resolution risk – challenges with implementation, reduced analytics and change in user experience.<br/><br/>"
            "• To pass our test – when first visiting your website, there must be a clear banner or button to reject non-essential cookies.<br/><br/>"
            "• Key metric / perspective – Approximately 50% of websites should pass this test based on our (external) 2024 data source.<br/><br/>"

            "<b>12. Website cookies rejection (after initial consent)</b><br/><br/>"
            "• Potential Impact – you may be collecting data from website visitors without their consent.<br/><br/>"
            "• Example – TikTok (2023) were fined around $5m for making it difficult for users to refuse cookies.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – ensure your website has an appropriate banner or button to reject non-essential cookies.<br/><br/>"
            "• Resolution risk – challenges with implementation, reduced analytics and change in user experience.<br/><br/>"
            "• To pass our test – when returning to your website, there must be a clear banner or button to reject non-essential cookies.<br/><br/>"
            "• Key metric / perspective – Approximately 60% of websites should pass this test based on our (external) 2024 data source.<br/><br/>"

            "<b>13. Website web application firewall</b><br/><br/>"
            "• Potential Impact – your website may be susceptible to attack and/or compromise.<br/><br/>"
            "• Example – SQL injection and remote code execution attacks.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – ensure your website is protected by a web application firewall.<br/><br/>"
            "• Resolution risk – impact to website performance, configuration complexity and cost.<br/><br/>"
            "• To pass our test – your website must indicate a web application firewall is in place during testing.<br/><br/>"
            "• Key metric / perspective – Approximately 70% of websites should pass this test based on our (external) 2024 data source.<br/><br/>"

            "<b>14. Website security headers</b><br/><br/>"
            "• Potential Impact – your website may be susceptible to attack and/or compromise.<br/><br/>"
            "• Example – credit card skimming attacks.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – ensure your website has protections to prevent exploitation.<br/><br/>"
            "• Resolution risk – configuration complexity and cost.<br/><br/>"
            "• To pass our test – your website must be rated as having ‘grade C’ level hardening or above.<br/><br/>"
            "• Key metric / perspective – Approximately 14% of websites should pass this test based on our (external) 2024 data source.<br/><br/>"

            "<b>15. Information Commissioners Office (ICO) register of data protection fee payers</b><br/><br/>"
            "• Potential Impact – your organisation may not be exempt from fees and could be subject to financial charges<br/><br/>"
            "• Example – nonpayment can result in fines of up to £4,000.<br/><br/>"
            "• Data privacy and protection – potential for unauthorised access to personal data and therefore non-compliance "
            "with UK GDPR, EU GDPR and CCPA.<br/><br/>"
            "• Potential resolution – check and pay the ICO annual fee.<br/><br/>"
            "• Resolution risk – cost to implement.<br/><br/>"
            "• To pass our test – your business name must be visible via the register of data protection fee payers.<br/><br/>"
            "• Key metric / perspective – Approximately 80% of business should pass this test based on our (external) 2024 data source.<br/>",
            styles["Body"],
        )
    )
    story.append(PageBreak())
    
    # Considerations
    story.append(Paragraph("Considerations", styles["H2"]))
    story.append(
        Paragraph(
            " <b>If any of the above test have failed – you may need to:</b><br/><br/>"
                "• Check whether it’s a false positive (incorrect report of a failure)<br/>"
                "• Carry out further research and testing<br/>"
                "• Check your legal and regulatory obligations<br/>"
                "• Seek professional advice and support<br/>"
                "• Carry out a risk assessment and manage the risk<br/>"
                "• Manage and report a security incident<br/>",
            styles["Body"],
        )
    )

    # Page callbacks
    def on_page(c: canvas.Canvas, d):
        _draw_header_footer(
            c=c,
            doc=d,
            report_title=report_title,
            classification=classification,
            last_reviewed=last_reviewed,
            logo_path=logo_path,
        )

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
