import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def create_doc():
    doc = Document()

    # Set page margins
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.8)
        section.right_margin = Inches(0.8)

    # Document Title
    title = doc.add_paragraph()
    r_title = title.add_run("DFIS: Digital Forensics Intelligence System")
    r_title.font.size = Pt(26)
    r_title.font.bold = True
    r_title.font.color.rgb = RGBColor(12, 111, 84) # Forest Green
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    sub = doc.add_paragraph()
    r_sub = sub.add_run("Executive Project Documentation & Technical Defense")
    r_sub.font.size = Pt(14)
    r_sub.font.italic = True
    r_sub.font.color.rgb = RGBColor(100, 110, 115)
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_paragraph("─" * 60).alignment = WD_ALIGN_PARAGRAPH.CENTER

    def add_sec_heading(text):
        h = doc.add_paragraph()
        r = h.add_run(text)
        r.font.size = Pt(16)
        r.font.bold = True
        r.font.color.rgb = RGBColor(16, 120, 90)
        h.space_before = Pt(16)
        h.space_after = Pt(6)
        return h

    def add_sub_heading(text):
        h = doc.add_paragraph()
        r = h.add_run(text)
        r.font.size = Pt(13)
        r.font.bold = True
        r.font.color.rgb = RGBColor(30, 41, 59)
        h.space_before = Pt(10)
        h.space_after = Pt(4)
        return h

    # Section 1: Problem Statement
    add_sec_heading("1. Problem Statement")
    doc.add_paragraph(
        "Digital Forensics and Incident Response (DFIR) investigations are increasingly paralyzed by three fundamental challenges:"
    )
    p = doc.add_paragraph()
    p.add_run("1. Multi-Source Artifact Deluge: ").bold = True
    p.add_run("Modern enterprise endpoints generate millions of disparate event records across Windows Event Logs (EVTX 4624/4688), SYSTEM and NTUSER.DAT registry hives, PCAP network flows, $MFT filesystem activity, browser SQLite databases, prefetch files, and memory snapshots. Correlating these fragmented sources manually is labor-intensive, error-prone, and slow.")

    p2 = doc.add_paragraph()
    p2.add_run("2. Cloud AI Data Sovereignty & Privacy Violations: ").bold = True
    p2.add_run("While commercial Large Language Models (LLMs) offer natural language summarization, transmitting sensitive corporate case evidence, proprietary source code, or unredacted forensic images to external cloud APIs (e.g. OpenAI, Anthropic, Google) violates corporate confidentiality agreements, GDPR, and legal chain-of-custody requirements.")

    p3 = doc.add_paragraph()
    p3.add_run("3. AI Hallucination & Legal Inadmissibility: ").bold = True
    p3.add_run("Unconstrained generative AI models frequently fabricate timestamps, invent non-existent event IDs, and conflate speculative hypotheses with verified facts. In a court of law or regulatory hearing, ungrounded AI claims compromise the integrity of the entire forensic investigation.")

    # Section 2: Objectives
    add_sec_heading("2. Technical Objectives")
    doc.add_paragraph("The primary objectives of the DFIS project are:")
    doc.add_paragraph("• Deterministic Ingestion & Normalization: Automatically ingest, parse, and verify multi-source forensic evidence using SHA-256 cryptographic digests into a unified chronological investigation timeline.", style='List Bullet')
    doc.add_paragraph("• 100% Air-Gapped Local Neural Copilot: Execute grounded local inference using Ollama (llama3.2:3b) on the examiner's workstation with zero data leakage.", style='List Bullet')
    doc.add_paragraph("• Canonical Evidentiary Truth Enforcement: Enforce strict separation between verified facts ([✓ OBSERVED]), unproven assumptions ([○ NOT ESTABLISHED]), speculative ATT&CK mappings ([◐ HYPOTHESIS]), and correlation blind spots ([⚠ EVIDENCE GAP]).", style='List Bullet')
    doc.add_paragraph("• 3-Way Synchronized Interactive Workspace: Enable seamless bidirectional live synchronization between the Visual Timeline, Chronological Event Table, Artifact Inspector Drawer, and Local AI Copilot.", style='List Bullet')
    doc.add_paragraph("• Role-Based Access Control & Immutable Custody: Implement robust case isolation and permission boundaries across Admin, Examiner, Analyst, and Viewer roles with real-time audit trail logging.", style='List Bullet')

    # Section 3: Novelty of Work
    add_sec_heading("3. Novelty & Technical Contributions")
    doc.add_paragraph("DFIS introduces key architectural innovations that differentiate it from existing commercial and open-source forensic tools:")
    doc.add_paragraph("1. Canonical State Machine: Unlike conventional tools that present raw tables or black-box AI outputs, DFIS uses a mathematical truth engine that prevents generative AI from promoting unverified hypotheses to observed facts.")
    doc.add_paragraph("2. Browser-to-Ollama Local Bridge: A unique hybrid architecture allowing cloud/container-hosted UI previews to interface securely with local workstation Ollama instances (http://localhost:11434) without routing evidence through cloud servers.")
    doc.add_paragraph("3. Clickable Bidirectional Evidence Tracing: Every evidence token in AI responses (e.g. [#39], [4624]) is interactive, instantly synchronizing the visual timeline map, scrolling the table log, and loading deep artifact metadata.")
    doc.add_paragraph("4. Automated Evidence Gap Detection: The system actively identifies missing forensic correlations (e.g., detecting that file access occurred but Drive-to-Device mapping is missing before concluding USB transfer).")

    # Section 4: Stakeholders
    add_sec_heading("4. Stakeholder Analysis")
    table = doc.add_table(rows=5, cols=3)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["Stakeholder Group", "Role in System", "Key Value & Impact"]
    for j, h in enumerate(headers):
        cell = table.cell(0, j)
        cell.text = h
        cell.paragraphs[0].runs[0].font.bold = True

    data = [
        ("Lead Forensic Examiners", "Primary User", "Rapid artifact correlation, cryptographic verification, court-admissible PDF reports with zero manual cross-referencing overhead."),
        ("SOC Incident Responders", "Primary User", "Accelerated root-cause breach triage in minutes instead of hours using natural language queries and interactive relationship graphs."),
        ("Corporate Legal & Compliance", "Beneficiary", "Read-only access to defensible investigation findings with complete air-gapped data sovereignty and zero cloud leakage."),
        ("CISOs & Enterprise Leaders", "Beneficiary", "Scalable, air-gapped forensic readiness without cloud API subscriptions, backed by tamper-evident audit logs.")
    ]
    for i, row in enumerate(data):
        for j, val in enumerate(row):
            table.cell(i+1, j).text = val

    # Section 5: Comparative Matrix
    add_sec_heading("5. Existing Systems vs. DFIS")
    doc.add_paragraph(
        "Compared to traditional tools (Autopsy, FTK, EnCase), commercial SIEMs (Splunk, ELK), and generic Cloud AI (ChatGPT, Copilot), DFIS provides a unified, defensible investigation workstation:"
    )
    c_table = doc.add_table(rows=6, cols=4)
    c_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    c_headers = ["Feature", "Traditional DFIR Tools", "Commercial SIEMs", "DFIS Platform"]
    for j, h in enumerate(c_headers):
        cell = c_table.cell(0, j)
        cell.text = h
        cell.paragraphs[0].runs[0].font.bold = True

    c_data = [
        ("Natural Language Q&A", "No (Regex/SQL only)", "Limited query assistants", "Grounded Manifest Reasoning"),
        ("Air-Gap / Privacy", "Yes (Offline client)", "No (Central server/cloud)", "100% Local (llama3.2:3b)"),
        ("Evidentiary Truth Model", "Raw tables only", "Alert feeds only", "4-Tier Truth Machine"),
        ("Interactive 3-Way Sync", "No (Cluttered subwindows)", "No (Disconnected tabs)", "Live Timeline ↔ Table ↔ AI"),
        ("Evidence Gap Detection", "Manual deduction", "Not supported", "Automated Correlation Gaps")
    ]
    for i, row in enumerate(c_data):
        for j, val in enumerate(row):
            c_table.cell(i+1, j).text = val

    # Section 6: Q&A Defense
    add_sec_heading("6. Technical Defense: Questions & Answers (Q&A)")
    qas = [
        ("Q1: How does DFIS ensure AI outputs are not hallucinated?",
         "DFIS enforces a strict Manifest-Grounded Architecture. The backend constructs a structured manifest containing only SHA-256 verified artifacts. The system prompt instructs the model that it is an investigative assistant, and the Canonical State Engine programmatically categorizes unverified claims as [NOT ESTABLISHED]."),
        ("Q2: Why is llama3.2:3b preferred over massive cloud models?",
         "Forensic investigation mandates complete privacy and data confidentiality. By pre-correlating artifacts and structuring context manifests, a lightweight 3B model achieves near-instantaneous inference on standard investigator hardware without requiring multi-GPU cloud servers."),
        ("Q3: How does DFIS maintain chain-of-custody compliance under FRE 901/902?",
         "Every ingested file generates an immutable SHA-256 hash. The system records all actions, evidence views, and queries in an append-only audit vault. Forensic reports clearly distinguish between raw evidence records and interpretive AI assessments."),
        ("Q4: How does DFIS enforce case-level isolation between users?",
         "DFIS utilizes Role-Based Access Control (RBAC) with case scoping. Users with roles such as Examiner, Analyst, or Viewer can only access investigations explicitly assigned to them (user.assignedCases), while Administrators maintain full governance.")
    ]
    for q, a in qas:
        p_q = doc.add_paragraph()
        p_q.add_run(q).bold = True
        doc.add_paragraph(a)

    # Section 7: Future Work & Improvements Needed
    add_sec_heading("7. Future Work & Improvements Needed")
    doc.add_paragraph("To advance DFIS from a workstation-grade prototype into a global enterprise standard, the following improvements and extensions are planned:")

    add_sub_heading("7.1 Automated Memory Forensics (Volatility3 Plugin Pipeline)")
    doc.add_paragraph(
        "Integrate automated memory dump acquisition and Volatility3 plugin execution directly into the ingestion pipeline. The system will extract injected code (malfind), unlinked VAD structures, mutant handles, hidden kernel modules, and credential artifacts, automatically correlating volatile memory events into the unified timeline."
    )

    add_sub_heading("7.2 Multi-Agent Collaborative Reasoning Architecture")
    doc.add_paragraph(
        "Transition from a single copilot model to a multi-agent debate architecture where specialized local agents (Network Flow Agent, Filesystem Staging Agent, Registry Persistence Agent) analyze independent evidence streams and debate cross-source correlations to synthesize consensus attack chains."
    )

    add_sub_heading("7.3 Automated Detection Engineering (SIGMA / YARA Compilation)")
    doc.add_paragraph(
        "Implement automated rule compilation that translates verified breach timelines directly into standardized SIGMA behavioral rules, YARA memory signatures, and Snort PCAP filters, enabling immediate enterprise-wide remediation."
    )

    add_sub_heading("7.4 Cloud, SaaS & Container Forensic Expansion")
    doc.add_paragraph(
        "Expand artifact extraction to native cloud management and container logs (AWS CloudTrail, Azure Activity Logs, Google Cloud Audit, Kubernetes apiserver audit logs, Docker container overlay FS), allowing multi-cloud incident correlation."
    )

    add_sub_heading("7.5 Distributed Ingestion Engine for Terabyte-Scale Images")
    doc.add_paragraph(
        "Integrate out-of-core columnar processing engines (Apache Arrow, DuckDB) and distributed worker nodes to ingest full raw forensic disk images (E01, DD, AFF4) across terabyte-scale enterprise environments with high-throughput indexing."
    )

    add_sub_heading("7.6 Hardware-Accelerated Local Inference Optimization")
    doc.add_paragraph(
        "Implement TensorRT-LLM and optimized GGUF quantization pipelines to enable forensic laptops equipped with mid-tier GPUs to run 8B and 14B models (e.g., Llama-3.1 8B, Qwen2.5 14B) with sub-second token latency."
    )

    # Conclusion
    add_sec_heading("8. Conclusion")
    doc.add_paragraph(
        "DFIS represents a transformative step in digital forensics and incident response. By combining deterministic multi-source correlation, strict canonical truth enforcement, and air-gapped local AI copilot assistance, DFIS empowers investigators to solve complex insider threat and cyber breach investigations in minutes with 100% legal defensibility."
    )

    doc_path = "DFIS_Project_Documentation.docx"
    doc.save(doc_path)
    print(f"Documentation saved successfully as {doc_path}")

create_doc()
