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
        Paragraph("DFIS Evidence-Linked Investigation Report", styles["Title"]),
        Paragraph(
            "The LLM does not treat general forensic knowledge as evidence. "
            "It retrieves case-specific events and uses general knowledge only to interpret them. "
            "Every important conclusion is linked to original evidence IDs. "
            "ATT&amp;CK mappings are hypothesized unless marked observed. "
            "Risk is investigation priority, not probability of crime.",
            styles["Italic"],
        ),
        Spacer(1, 12),
        Paragraph(f"<b>Case</b> {case.case_number}: {case.title}", styles["Heading2"]),
        Paragraph(case.description or "", styles["BodyText"]),
        Paragraph(f"Investigator: {case.investigator} &nbsp; Status: {case.status}", styles["BodyText"]),
        Spacer(1, 8),
        Paragraph("1. Evidence integrity (SHA-256)", styles["Heading2"]),
    ]
    rows = [["ID", "File", "SHA-256", "OK"]]
    for e in evidence:
        rows.append([str(e.id), e.filename[:40], e.sha256[:20] + "…", "yes" if e.integrity_ok else "NO"])
    story.append(_table(rows))

    story.append(Spacer(1, 10))
    story.append(Paragraph("2. Incident classification & Evidentiary States", styles["Heading2"]))
    
    from app.services.investigation import format_classification_label
    formatted_label = format_classification_label(analysis.get("category"), analysis.get("secondary"))

    story.append(
        Paragraph(
            f"Working Classification: <b>{formatted_label}</b> "
            f"&nbsp; Investigation Priority: {analysis.get('risk_score')}/100 — "
            f"{(analysis.get('risk') or {}).get('priority') or analysis.get('priority') or 'PRIORITY'} "
            f"(prioritization aid, not legal culpability)",
            styles["BodyText"],
        )
    )
    story.append(
        Paragraph(
            "Malicious intent and unauthorized access cannot be established from logs alone.",
            styles["Italic"],
        )
    )

    # 4-Tier Evidentiary States Table
    ev_states = analysis.get("evidentiary_states") or []
    if ev_states:
        story.append(Spacer(1, 6))
        story.append(Paragraph("<b>Forensic Evidentiary State Breakdown</b>", styles["Heading3"]))
        srows = [["Investigation Finding", "Evidentiary State", "Forensic Detail"]]
        for s in ev_states:
            srows.append([s.get("finding", ""), s.get("state", ""), s.get("detail", "")[:75]])
        story.append(_table(srows))

    risk = analysis.get("risk") or {}
    if risk.get("indicators"):
        story.append(Spacer(1, 8))
        story.append(Paragraph("3. Transparent risk indicators (prototype weights)", styles["Heading2"]))
        story.append(Paragraph(risk.get("disclaimer") or "", styles["Italic"]))
        rrows = [["Fired", "Points", "Indicator"]]
        for i in risk.get("indicators") or []:
            rrows.append(["yes", str(i["points"]), i["label"]])
        for i in risk.get("unused") or []:
            rrows.append(["no", str(i["points"]), i["label"]])
        story.append(_table(rrows))

    story.append(Spacer(1, 8))
    story.append(Paragraph("4. Reconstructed Attack Chain Hypothesis (ATT&amp;CK not factual)", styles["Heading2"]))
    crows = [["Time", "Activity", "Technique", "Status", "Conf.", "Evidence IDs"]]
    for s in analysis.get("attack_chain") or []:
        crows.append(
            [
                str(s.get("time") or "")[:19],
                (s.get("title") or "")[:35],
                s.get("mitre") or "—",
                s.get("status") or "hypothesized",
                s.get("confidence") or "",
                ",".join(str(i) for i in (s.get("evidence_event_ids") or [])),
            ]
        )
    if len(crows) > 1:
        story.append(_table(crows))

    story.append(Spacer(1, 8))
    story.append(Paragraph("5. Correlated activities → supporting event IDs", styles["Heading2"]))
    story.append(Paragraph("Correlation links are analytical relationships, not evidence artifacts.", styles["Italic"]))
    grows = [["Time", "Type", "Entity", "Link", "Evidence IDs"]]
    for g in analysis.get("correlations") or []:
        grows.append(
            [
                str(g.get("timestamp") or "")[:19],
                g.get("family") or "",
                (g.get("entity") or "")[:28],
                g.get("correlation_id") or "",
                ",".join(str(i) for i in (g.get("source_event_ids") or [])),
            ]
        )
    if len(grows) > 1:
        story.append(_table(grows))

    # 5c. Evidence Acquisition / Observations
    obs = analysis.get("observations") or []
    if obs:
        story.append(Spacer(1, 8))
        story.append(Paragraph("5c. Evidence Acquisition / Observations", styles["Heading2"]))
        orows = [["Time", "Observation", "Type", "Status", "Evidence IDs", "Forensic Note"]]
        for o in obs:
            orows.append(
                [
                    str(o.get("time") or "")[:19],
                    o.get("title", ""),
                    o.get("type", "Acquisition"),
                    o.get("status", "OBSERVED"),
                    ",".join(str(i) for i in (o.get("evidence_event_ids") or [])),
                    o.get("note", "")[:60],
                ]
            )
        story.append(_table(orows))

    from app.services.investigation import _usb_transfer_answer

    story.append(Spacer(1, 8))
    story.append(Paragraph("5b. Grounded examiner Q&amp;A (USB / transfer)", styles["Heading2"]))
    qa = _usb_transfer_answer(analysis, [])
    if qa:
        story.append(Paragraph(qa.replace("\n", "<br/>"), styles["BodyText"]))
    else:
        story.append(
            Paragraph(
                "No file-copy correlation is available to answer whether confidential data was copied to USB. "
                "USB-based confidential data transfer is NOT established by the evidence.",
                styles["BodyText"],
            )
        )

    for f in findings:
        story.append(Paragraph(f"<b>{f.title}</b> (conf {f.confidence:.2f})", styles["Heading3"]))
        story.append(Paragraph((f.body or "").replace("\n", "<br/>")[:4000], styles["BodyText"]))

    story.append(Spacer(1, 8))
    story.append(Paragraph("6. Recommended next investigation actions", styles["Heading2"]))
    story.append(
        Paragraph(
            "Examiner verification tasks derived from evidentiary gaps (NOT ESTABLISHED / INSUFFICIENT EVIDENCE). These are examiner tasks, not findings of fact.",
            styles["Italic"],
        )
    )
    arows = [["#", "Investigation Question", "Action / Task", "Why Investigate", "Evidence IDs", "Status"]]
    for a in analysis.get("next_actions") or []:
        arows.append(
            [
                str(a.get("priority")),
                (a.get("question") or a.get("action") or "")[:28],
                (a.get("action") or "")[:28],
                (a.get("reason") or "")[:45],
                ",".join(str(i) for i in (a.get("evidence_ids") or [])),
                (a.get("status") or "pending_examiner_verification").replace("_", " "),
            ]
        )
    if len(arows) > 1:
        story.append(_table(arows))

    story.append(Spacer(1, 10))
    story.append(Paragraph("7. Timeline extract", styles["Heading2"]))
    trows = [["When", "Kind", "Source", "Event"]]
    for a in artifacts[:45]:
        trows.append(
            [
                str(a.timestamp or "—")[:19],
                getattr(a, "time_kind", None) or "event",
                a.source_type,
                (a.description or "")[:70],
            ]
        )
    story.append(_table(trows))
    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            "Original artifacts remain authoritative. Hashes were computed at ingest. "
            "Do not treat model output as a substitute for examiner judgment. "
            "GENERAL forensic knowledge must not be confused with CASE evidence.",
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
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f4f7fb")),
            ]
        )
    )
    return t
