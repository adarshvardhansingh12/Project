from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER

SEVERITY_COLORS_PDF = {
    "critical": colors.HexColor("#c0392b"),
    "high":     colors.HexColor("#e74c3c"),
    "medium":   colors.HexColor("#e67e22"),
    "low":      colors.HexColor("#2980b9"),
    "info":     colors.HexColor("#7f8c8d"),
}


class PDFReporter:
    def __init__(self, domain: str, subdomains: list[dict], findings: list[dict], output_path: str):
        self.domain = domain
        self.subdomains = subdomains
        self.findings = findings
        self.output_path = output_path

    def generate(self):
        doc = SimpleDocTemplate(self.output_path, pagesize=A4,
                                rightMargin=2*cm, leftMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("t", parent=styles["Title"], fontSize=20, spaceAfter=6)
        sub_style   = ParagraphStyle("s", parent=styles["Normal"], fontSize=10,
                                     textColor=colors.HexColor("#555"), spaceAfter=14)
        h2_style    = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13,
                                     spaceBefore=14, spaceAfter=6)
        footer_style = ParagraphStyle("f", parent=styles["Normal"], fontSize=8,
                                      textColor=colors.gray, alignment=TA_CENTER)

        story = []
        story.append(Paragraph("Subdomain Takeover Scanner Report", title_style))
        story.append(Paragraph(
            f"Target: {self.domain} &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M')} &nbsp;|&nbsp; "
            f"Subdomains: {len(self.subdomains)} &nbsp;|&nbsp; Vulnerable: {len(self.findings)}",
            sub_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a1a2e")))
        story.append(Spacer(1, 0.4*cm))

        # Summary table
        story.append(Paragraph("Executive Summary", h2_style))
        counts = {}
        for f in self.findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1

        sum_data = [["Metric", "Count"],
                    ["Total subdomains discovered", str(len(self.subdomains))],
                    ["Vulnerable subdomains", str(len(self.findings))]]
        for sev in ["critical", "high", "medium", "low"]:
            if sev in counts:
                sum_data.append([f"{sev.capitalize()} severity", str(counts[sev])])

        sum_table = Table(sum_data, colWidths=[9*cm, 4*cm])
        sum_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 10),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f9f9f9"), colors.white]),
            ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
            ("ALIGN",      (1,0), (1,-1), "CENTER"),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ]))
        story.append(sum_table)
        story.append(Spacer(1, 0.5*cm))

        # Vulnerable findings
        story.append(Paragraph("Vulnerable Subdomains", h2_style))
        if not self.findings:
            story.append(Paragraph("No vulnerable subdomains detected.", styles["Normal"]))
        else:
            for i, f in enumerate(self.findings, 1):
                sev = f.get("severity", "info")
                sev_color = SEVERITY_COLORS_PDF.get(sev, colors.gray)
                data = [
                    ["#",            str(i)],
                    ["Subdomain",    f.get("subdomain", "")],
                    ["Severity",     sev.upper()],
                    ["Service",      f.get("service", "")],
                    ["CNAME",        f.get("cname") or "N/A"],
                    ["HTTP Status",  str(f.get("status_code", ""))],
                    ["Confidence",   f.get("confidence", "").upper()],
                    ["Description",  f.get("description", "")],
                    ["Remediation",  f.get("remediation", "")],
                    ["References",   f.get("references", "")],
                ]
                t = Table(data, colWidths=[3.5*cm, 13*cm])
                t.setStyle(TableStyle([
                    ("FONTNAME",  (0,0), (0,-1), "Helvetica-Bold"),
                    ("FONTSIZE",  (0,0), (-1,-1), 9),
                    ("BACKGROUND",(0,2),(1,2), sev_color),
                    ("TEXTCOLOR", (0,2),(1,2), colors.white),
                    ("FONTNAME",  (0,2),(1,2), "Helvetica-Bold"),
                    ("VALIGN",    (0,0),(-1,-1), "TOP"),
                    ("GRID",      (0,0),(-1,-1), 0.4, colors.HexColor("#dddddd")),
                    ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.HexColor("#f4f4f4"), colors.white]),
                    ("TOPPADDING",(0,0),(-1,-1), 5),
                    ("BOTTOMPADDING",(0,0),(-1,-1), 5),
                    ("LEFTPADDING",(0,0),(-1,-1), 7),
                ]))
                story.append(t)
                story.append(Spacer(1, 0.3*cm))

        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.gray))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph("Generated by Subdomain Takeover Scanner — For authorized use only.", footer_style))
        doc.build(story)
