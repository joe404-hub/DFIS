import os
import pptx
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

def create_presentation():
    prs = Presentation()
    # 16:9 widescreen layout
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    # Color definitions matching DFIS Black & Emerald Palette
    BG_COLOR = RGBColor(2, 8, 7)          # #020807
    CARD_BG = RGBColor(8, 20, 15)         # #08140f
    CARD_BORDER = RGBColor(61, 255, 174)  # #3dffae (semi-transparent border logic)
    ACCENT_GREEN = RGBColor(61, 255, 174) # #3dffae
    MINT_GREEN = RGBColor(109, 255, 199)  # #6dffc7
    TEXT_PRIMARY = RGBColor(238, 250, 244)# #eefaf4
    TEXT_MUTED = RGBColor(143, 168, 157)  # #8fa89d
    AMBER = RGBColor(246, 184, 74)        # #f6b84a
    RED = RGBColor(255, 101, 101)         # #ff6565
    CYAN = RGBColor(56, 189, 248)         # #38bdf8

    blank_layout = prs.slide_layouts[6]

    def add_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_COLOR
        bg.line.fill.background()
        return bg

    def add_header(slide, title_text, category="DFIS INVESTIGATION PLATFORM"):
        header_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.9))
        tf = header_box.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

        p1 = tf.paragraphs[0]
        p1.text = category.upper()
        p1.font.size = Pt(10)
        p1.font.bold = True
        p1.font.color.rgb = ACCENT_GREEN
        p1.font.name = "Inter"

        p2 = tf.add_paragraph()
        p2.text = title_text
        p2.font.size = Pt(22)
        p2.font.bold = True
        p2.font.color.rgb = TEXT_PRIMARY
        p2.font.name = "Inter"
        p2.space_before = Pt(3)

    def add_card(slide, left, top, width, height, title="", title_color=ACCENT_GREEN, bg_color=CARD_BG, border_color=ACCENT_GREEN):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        card.fill.solid()
        card.fill.fore_color.rgb = bg_color
        if border_color:
            card.line.color.rgb = border_color
            card.line.width = Pt(1.2)
        else:
            card.line.fill.background()

        if title:
            tb = slide.shapes.add_textbox(left + Inches(0.2), top + Inches(0.15), width - Inches(0.4), Inches(0.4))
            tf = tb.text_frame
            tf.word_wrap = True
            tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
            p = tf.paragraphs[0]
            p.text = title
            p.font.size = Pt(13)
            p.font.bold = True
            p.font.color.rgb = title_color
            p.font.name = "Inter"

        return card

    # ==========================================
    # SLIDE 1: TITLE SLIDE
    # ==========================================
    slide1 = prs.slides.add_slide(blank_layout)
    add_background(slide1)

    # Accent decorative box
    add_card(slide1, Inches(0.8), Inches(1.2), Inches(11.733), Inches(5.2), "", bg_color=CARD_BG, border_color=ACCENT_GREEN)

    tb = slide1.shapes.add_textbox(Inches(1.2), Inches(1.6), Inches(11.0), Inches(4.4))
    tf = tb.text_frame
    tf.word_wrap = True

    p = tf.paragraphs[0]
    p.text = "● SECURE FORENSIC WORKSTATION • AIR-GAPPED"
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = ACCENT_GREEN
    p.font.name = "Courier New"

    p2 = tf.add_paragraph()
    p2.text = "DFIS: Digital Forensics\nIntelligence System"
    p2.font.size = Pt(38)
    p2.font.bold = True
    p2.font.color.rgb = TEXT_PRIMARY
    p2.font.name = "Inter"
    p2.space_before = Pt(10)

    p3 = tf.add_paragraph()
    p3.text = "AI-Assisted Multi-Source Forensic Ingestion, Deterministic Correlation Engine, & Air-Gapped Local LLM (llama3.2:3b) Copilot"
    p3.font.size = Pt(15)
    p3.font.color.rgb = TEXT_MUTED
    p3.font.name = "Inter"
    p3.space_before = Pt(12)

    p4 = tf.add_paragraph()
    p4.text = "✓ 100% Private Local Inference  •  ✓ Strict Evidentiary State Separation  •  ✓ FRE 901/902 Defensible Custody"
    p4.font.size = Pt(12)
    p4.font.bold = True
    p4.font.color.rgb = MINT_GREEN
    p4.font.name = "Inter"
    p4.space_before = Pt(24)

    # ==========================================
    # SLIDE 2: PROBLEM STATEMENT
    # ==========================================
    slide2 = prs.slides.add_slide(blank_layout)
    add_background(slide2)
    add_header(slide2, "The Critical Problem in Digital Forensics & AI Ingestion", "PROBLEM STATEMENT")

    probs = [
        ("1. Multi-Source Artifact Deluge", "Examiners face millions of fragmented records across EVTX, SYSTEM registry, PCAP flows, $MFT filesystem, browser SQLite, and memory snapshots with zero unified timeline.", RED),
        ("2. Cloud AI Data Leakage", "Submitting sensitive case artifacts or trade secrets to commercial cloud LLMs (OpenAI, Claude) violates corporate confidentiality, GDPR, and chain-of-custody rules.", AMBER),
        ("3. AI Hallucination & Inadmissibility", "Generic LLMs fabricate log event IDs and conflate hypothesis with proven fact, making unconstrained AI outputs legally inadmissible in court.", RED),
        ("4. Evidence Gap Blind Spots", "Existing tools display raw logs but fail to detect missing correlation links (e.g. asserting USB exfiltration without drive-to-device mapping).", CYAN)
    ]

    for i, (title, desc, color) in enumerate(probs):
        col = i % 2
        row = i // 2
        left = Inches(0.8 + col * 5.95)
        top = Inches(1.5 + row * 2.7)
        add_card(slide2, left, top, Inches(5.75), Inches(2.4), title, title_color=color, border_color=color)

        tb = slide2.shapes.add_textbox(left + Inches(0.2), top + Inches(0.65), Inches(5.35), Inches(1.6))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = desc
        p.font.size = Pt(12.5)
        p.font.color.rgb = TEXT_MUTED
        p.font.name = "Inter"

    # ==========================================
    # SLIDE 3: OBJECTIVES OF DFIS
    # ==========================================
    slide3 = prs.slides.add_slide(blank_layout)
    add_background(slide3)
    add_header(slide3, "Core Technical Objectives & Design Principles", "PROJECT OBJECTIVES")

    objs = [
        ("Deterministic Normalization", "Ingest and verify heterogeneous artifacts (EVTX, Registry, PCAP, Browser, FS) with SHA-256 digests into a single synchronized chronological timeline.", ACCENT_GREEN),
        ("Air-Gapped LLM Grounding", "Execute 100% local neural inference using Ollama (`llama3.2:3b`) on the examiner's workstation with zero data leakage.", MINT_GREEN),
        ("Canonical Evidentiary States", "Strictly enforce 4 discrete truth levels: [✓ OBSERVED], [○ NOT ESTABLISHED], [◐ HYPOTHESIS], and [⚠ EVIDENCE GAP].", AMBER),
        ("3-Way Synchronized Workspace", "Bidirectional live synchronization between Visual Timeline (38vh), Chronological Event Table, and Local AI Copilot.", CYAN),
        ("Forensic Role-Based Access", "Enforce strict case isolation across ADMIN, EXAMINER, ANALYST, and VIEWER roles with immutable audit logging.", TEXT_PRIMARY)
    ]

    for i, (title, desc, color) in enumerate(objs):
        top = Inches(1.4 + i * 1.1)
        add_card(slide3, Inches(0.8), top, Inches(11.733), Inches(0.95), "", border_color=color)

        tb = slide3.shapes.add_textbox(Inches(1.0), top + Inches(0.12), Inches(11.3), Inches(0.7))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = f"{i+1}. {title}: "
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = color
        p.font.name = "Inter"

        run = p.add_run()
        run.text = desc
        run.font.size = Pt(12)
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED
        run.font.name = "Inter"

    # ==========================================
    # SLIDE 4: NOVELTY & TECHNICAL CONTRIBUTIONS
    # ==========================================
    slide4 = prs.slides.add_slide(blank_layout)
    add_background(slide4)
    add_header(slide4, "Novelty & Key Architectural Differentiators", "NOVELTY OF WORK")

    novelties = [
        ("Canonical State Machine", "Traditional tools only show raw logs; DFIS uses a mathematical truth engine that prevents AI from promoting unverified assumptions to facts."),
        ("Air-Gapped Browser-Ollama Bridge", "Direct browser-to-local loopback connection (`localhost:11434`) allows cloud preview hosting while keeping neural inference strictly on the client."),
        ("Clickable Evidence Citations", "Every token in AI responses (`[#50]`, `[4624]`) is interactive—clicking focuses the timeline, selects the table row, and loads the inspector."),
        ("Automated Evidence Gap Detection", "System actively surfaces what is missing in the case (e.g. unverified cloud uploads, temporal gaps) rather than only summarizing found items."),
        ("Cryptographic Session Custody", "Immutable real-time audit ledger tracking every case open, evidence view, AI synthesis, and PDF report export.")
    ]

    for i, (title, desc) in enumerate(novelties):
        col = i % 2 if i < 4 else 0
        row = i // 2 if i < 4 else 2
        width = Inches(5.75) if i < 4 else Inches(11.733)
        left = Inches(0.8 + col * 5.95)
        top = Inches(1.5 + row * 1.8)

        add_card(slide4, left, top, width, Inches(1.6), title, title_color=ACCENT_GREEN, border_color=ACCENT_GREEN)
        tb = slide4.shapes.add_textbox(left + Inches(0.2), top + Inches(0.55), width - Inches(0.4), Inches(0.95))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = desc
        p.font.size = Pt(11.5)
        p.font.color.rgb = TEXT_MUTED
        p.font.name = "Inter"

    # ==========================================
    # SLIDE 5: STAKEHOLDER MATRIX
    # ==========================================
    slide5 = prs.slides.add_slide(blank_layout)
    add_background(slide5)
    add_header(slide5, "Target Stakeholders & Beneficiaries", "STAKEHOLDER ANALYSIS")

    stakeholders = [
        ("Lead Forensic Examiners", "PRIMARY USER", "• Instant correlation across multi-source evidence packages\n• 100% court-admissible, evidence-linked PDF reports\n• Elimination of repetitive manual artifact cross-referencing", ACCENT_GREEN),
        ("SOC Incident Responders", "PRIMARY USER", "• Rapid incident triage in minutes instead of hours\n• Interactive entity relationship graph & ATT&CK mapping\n• Natural language forensic queries without complex SQL", CYAN),
        ("Corporate Legal & Compliance", "BENEFICIARY", "• Read-only compliance review (`VIEWER` role)\n• Zero data sovereignty or cloud privacy leak risks\n• Clear demarcation between verified facts and hypotheses", AMBER),
        ("CISOs & Enterprise Leaders", "BENEFICIARY", "• Air-gapped AI capability without cloud subscription costs\n• Tamper-evident immutable custody logs for internal audits\n• Scalable incident response across endpoint breaches", MINT_GREEN)
    ]

    for i, (title, role, desc, color) in enumerate(stakeholders):
        col = i % 2
        row = i // 2
        left = Inches(0.8 + col * 5.95)
        top = Inches(1.5 + row * 2.7)
        add_card(slide5, left, top, Inches(5.75), Inches(2.45), f"{title} ({role})", title_color=color, border_color=color)

        tb = slide5.shapes.add_textbox(left + Inches(0.2), top + Inches(0.6), Inches(5.35), Inches(1.7))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = desc
        p.font.size = Pt(12)
        p.font.color.rgb = TEXT_PRIMARY
        p.font.name = "Inter"

    # ==========================================
    # SLIDE 6: EXISTING SYSTEMS COMPARISON
    # ==========================================
    slide6 = prs.slides.add_slide(blank_layout)
    add_background(slide6)
    add_header(slide6, "Comparative Analysis: DFIS vs Existing Solutions", "EXISTING SYSTEMS")

    add_card(slide6, Inches(0.8), Inches(1.4), Inches(11.733), Inches(5.4), "", border_color=ACCENT_GREEN)

    table_shape = slide6.shapes.add_table(6, 5, Inches(1.0), Inches(1.6), Inches(11.333), Inches(4.9))
    table = table_shape.table

    headers = ["Feature / Capability", "Autopsy / FTK / EnCase", "Commercial SIEMs", "Cloud GenAI (ChatGPT)", "DFIS Platform"]
    for j, h in enumerate(headers):
        cell = table.cell(0, j)
        cell.text = h
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(12, 32, 24)
        for p in cell.text_frame.paragraphs:
            p.font.size = Pt(11)
            p.font.bold = True
            p.font.color.rgb = ACCENT_GREEN
            p.font.name = "Inter"

    rows_data = [
        ("Natural Language Q&A", "❌ No (Regex / SQL only)", "⚠️ Limited assistant", "⚠️ Yes (High Hallucination)", "✅ Grounded in Manifest"),
        ("Air-Gap / Zero Cloud Leak", "✅ Yes (Offline client)", "❌ Cloud / Central server", "❌ Exfiltrates case data", "✅ 100% Local (llama3.2:3b)"),
        ("Evidentiary State Separation", "❌ Raw tables only", "❌ Alert feeds only", "❌ Mixes fact with fiction", "✅ 4-Tier Truth Machine"),
        ("Interactive 3-Way Sync", "❌ Sub-window clutter", "❌ Separate dashboards", "❌ Static text output", "✅ Timeline ↔ Table ↔ AI"),
        ("Evidence Gap Detection", "❌ Manual analyst work", "❌ Not supported", "❌ Ignored by LLM", "✅ Automated Missing Proofs")
    ]

    for i, row in enumerate(rows_data):
        for j, val in enumerate(row):
            cell = table.cell(i+1, j)
            cell.text = val
            cell.fill.solid()
            cell.fill.fore_color.rgb = CARD_BG
            for p in cell.text_frame.paragraphs:
                p.font.size = Pt(10.5)
                p.font.name = "Inter"
                if j == 4:
                    p.font.bold = True
                    p.font.color.rgb = ACCENT_GREEN
                elif j == 0:
                    p.font.bold = True
                    p.font.color.rgb = TEXT_PRIMARY
                else:
                    p.font.color.rgb = TEXT_MUTED

    # ==========================================
    # SLIDE 7: REASONABLE QUESTIONS & ANSWERS (Q&A)
    # ==========================================
    slide7 = prs.slides.add_slide(blank_layout)
    add_background(slide7)
    add_header(slide7, "Technical Defense: Addressing Key Inquiries", "REASONABLE QUESTIONS & DEFENSE")

    qas = [
        ("Q1: How is LLM hallucination strictly prevented?", "DFIS constructs a deterministic context manifest containing only ingested, verified artifacts. The Canonical State Engine tags any assertion without supporting evidence ID as [NOT ESTABLISHED]."),
        ("Q2: Why use a 3B model (llama3.2:3b) over GPT-4?", "Forensic workstations require strict air-gapping and data privacy. Because DFIS pre-correlates artifacts, a lightweight 3B model achieves near-zero latency on commodity hardware with zero data leakage."),
        ("Q3: Is DFIS legally defensible under FRE 901/902?", "Yes. AI analysis is explicitly labeled as 'Interpretive Assessment — Not Case Evidence', while every supporting event links to raw logs with SHA-256 digests and cryptographic audit trails."),
        ("Q4: How does DFIS isolate investigations between users?", "DFIS implements Case-Level Role-Based Access Control (RBAC). Personnel (Examiner, Analyst, Viewer) can only access authorized case IDs (`user.assignedCases`), governed by Admin policy.")
    ]

    for i, (q, a) in enumerate(qas):
        top = Inches(1.4 + i * 1.35)
        add_card(slide7, Inches(0.8), top, Inches(11.733), Inches(1.2), "", border_color=ACCENT_GREEN if i % 2 == 0 else CYAN)

        tb = slide7.shapes.add_textbox(Inches(1.0), top + Inches(0.12), Inches(11.3), Inches(0.95))
        tf = tb.text_frame
        tf.word_wrap = True
        p1 = tf.paragraphs[0]
        p1.text = q
        p1.font.size = Pt(12.5)
        p1.font.bold = True
        p1.font.color.rgb = ACCENT_GREEN if i % 2 == 0 else CYAN
        p1.font.name = "Inter"

        p2 = tf.add_paragraph()
        p2.text = a
        p2.font.size = Pt(11.5)
        p2.font.color.rgb = TEXT_PRIMARY
        p2.font.name = "Inter"
        p2.space_before = Pt(3)

    # ==========================================
    # SLIDE 8: FUTURE WORK & IMPROVEMENTS NEEDED
    # ==========================================
    slide8 = prs.slides.add_slide(blank_layout)
    add_background(slide8)
    add_header(slide8, "Roadmap: Future Enhancements & System Scalability", "FUTURE WORK & IMPROVEMENTS")

    future_items = [
        ("1. Volatility3 Automated Memory Extraction", "Directly orchestrate Volatility3 memory plugins to parse injected DLLs, unlinked VADs, mutant handles, and hidden rootkit processes into the unified timeline.", ACCENT_GREEN),
        ("2. Multi-Agent Collaborative Reasoning", "Deploy specialized parallel agents (Network Flow Agent, Registry Persistence Agent, Filesystem Staging Agent) that debate and converge on root-cause breach conclusions.", CYAN),
        ("3. Automated Detection Engineering (SIGMA/YARA)", "Automatically convert verified breach sequences into actionable SIGMA detection rules, YARA byte patterns, and Snort PCAP signatures for immediate enterprise shielding.", MINT_GREEN),
        ("4. Distributed Ingestion with DuckDB / Arrow", "Scale ingestion throughput to terabyte-scale disk images (E01/DD/AFF4) using vectorized columnar processing and out-of-core memory indexing.", AMBER),
        ("5. Hardware-Accelerated Local Inference", "Integrate TensorRT-LLM and llama.cpp GPU offloading to support local 8B and 14B quantized models (Qwen2.5/Llama-3) on mid-tier forensic laptops.", TEXT_PRIMARY)
    ]

    for i, (title, desc, color) in enumerate(future_items):
        top = Inches(1.4 + i * 1.1)
        add_card(slide8, Inches(0.8), top, Inches(11.733), Inches(0.95), "", border_color=color)

        tb = slide8.shapes.add_textbox(Inches(1.0), top + Inches(0.12), Inches(11.3), Inches(0.7))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = f"{title}: "
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = color
        p.font.name = "Inter"

        run = p.add_run()
        run.text = desc
        run.font.size = Pt(12)
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED
        run.font.name = "Inter"

    # ==========================================
    # SLIDE 9: SUMMARY & CONCLUSION
    # ==========================================
    slide9 = prs.slides.add_slide(blank_layout)
    add_background(slide9)
    add_header(slide9, "Executive Conclusion & Operational Readiness", "SUMMARY & CONCLUSION")

    add_card(slide9, Inches(0.8), Inches(1.5), Inches(11.733), Inches(5.2), "", bg_color=CARD_BG, border_color=ACCENT_GREEN)

    tb = slide9.shapes.add_textbox(Inches(1.2), Inches(1.8), Inches(11.0), Inches(4.5))
    tf = tb.text_frame
    tf.word_wrap = True

    p = tf.paragraphs[0]
    p.text = "DFIS: Redefining Digital Forensics for the AI Era"
    p.font.size = Pt(24)
    p.font.bold = True
    p.font.color.rgb = ACCENT_GREEN
    p.font.name = "Inter"

    conclusions = [
        ("Deterministic Reliability", "Forensic investigations demand mathematical proof. DFIS ensures AI assists the analyst without ever inventing evidence or corrupting custody."),
        ("100% Privacy & Sovereignty", "All telemetry, evidence hashes, and reasoning models execute air-gapped on the investigator's local workstation."),
        ("Operational Acceleration", "Replaces hours of disconnected log parsing with an interactive, 3-way synchronized investigation console that answers complex temporal questions in seconds."),
        ("Complete Enterprise Governance", "Role-based access control, case isolation, and immutable audit logs deliver end-to-end defensibility from endpoint acquisition to courtroom presentation.")
    ]

    for title, desc in conclusions:
        p_c = tf.add_paragraph()
        p_c.text = f"• {title}: "
        p_c.font.size = Pt(14)
        p_c.font.bold = True
        p_c.font.color.rgb = MINT_GREEN
        p_c.font.name = "Inter"
        p_c.space_before = Pt(14)

        run = p_c.add_run()
        run.text = desc
        run.font.size = Pt(13)
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED
        run.font.name = "Inter"

    pptx_path = "DFIS_Executive_Presentation.pptx"
    prs.save(pptx_path)
    print(f"Presentation saved successfully as {pptx_path}")

create_presentation()
