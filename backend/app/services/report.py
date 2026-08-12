from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib import colors
from app.db import REPORT_DIR


def generate_report(case, evidence, artifacts, findings, analysis: dict) -> Path:
    path = REPORT_DIR / f"case_{case.id}_report.pdf"
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=A4)
    story = [
        Paragraph("DFIS Investigation Report", styles["Title"]),
        Paragraph("AI-assisted findings are investigative aids, not evidence.", styles["Italic"]),
        Spacer(1, 12),
        Paragraph(f"<b>Case</b> {case.case_number}: {case.title}", styles["Heading2"]),
        Paragraph(case.description or "", styles["BodyText"]),
        Paragraph(f"Investigator: {case.investigator} &nbsp; Status: {case.status}", styles["BodyText"]),
        Spacer(1, 8),
        Paragraph("Evidence integrity (SHA-256)", styles["Heading2"]),
    ]
    rows = [["ID", "File", "SHA-256", "OK"]]
    for e in evidence:
        rows.append([str(e.id), e.filename[:40], e.sha256[:20] + "…", "yes" if e.integrity_ok else "NO"])
    story.append(_table(rows))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Incident summary", styles["Heading2"]))
    story.append(
        Paragraph(
            f"Classification: <b>{analysis.get('category')}</b> &nbsp; Risk: {analysis.get('risk_score')}",
            styles["BodyText"],
        )
    )
    for f in findings:
        story.append(Paragraph(f"<b>{f.title}</b> (conf {f.confidence:.2f})", styles["Heading3"]))
        story.append(Paragraph(f.body.replace("\n", "<br/>"), styles["BodyText"]))
        story.append(Paragraph(f"MITRE: {f.mitre_ids} &nbsp; Artifacts: {f.artifact_ids}", styles["BodyText"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Timeline (first 40 events)", styles["Heading2"]))
    trows = [["When", "Source", "Event"]]
    for a in artifacts[:40]:
        trows.append(
            [
                str(a.timestamp or "—")[:19],
                a.source_type,
                (a.description or "")[:80],
            ]
        )
    story.append(_table(trows))
    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            "Original artifacts remain authoritative. Hashes were computed at ingest. "
            "Do not treat model output as a substitute for examiner judgment.",
            styles["Italic"],
        )
    )
    doc.build(story)
    return path


def _table(rows):
    t = Table(rows, repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f2744")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f4f7fb")),
            ]
        )
    )
    return t
