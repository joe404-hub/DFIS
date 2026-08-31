"""Local LLM Forensic Assistant Service (llama3.2:3b).

Provides 100% local, air-gapped, privacy-preserving AI forensic reasoning
integrated with Ollama / OpenAI-compatible local inference engines.

Forensic Grounding Principles:
1. AI is an investigative assistant, not an evidence source.
2. Every assertion must cite SHA-256 verified Evidence IDs.
3. Observed valid-account authentication != unauthorized access.
4. Observed network/browser activity != confirmed exfiltration.
5. Missing evidence is explicitly stated as NOT ESTABLISHED.
6. Hypotheses are explicitly distinguished from observed facts.
7. General technical knowledge is interpretive only and cannot be used as case evidence.
8. Zero data leaves the local workstation (no external/online chatbots).
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("dfis.llm")

DEFAULT_MODEL = os.environ.get("DFIS_LLM_MODEL", "llama3.2:3b")
DEFAULT_OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_TIMEOUT = float(os.environ.get("DFIS_LLM_TIMEOUT", "20.0"))
DEFAULT_TEMPERATURE = float(os.environ.get("DFIS_LLM_TEMPERATURE", "0.1"))

GENERAL_SYSTEM_PROMPT = """You are a helpful, knowledgeable technical assistant.

Answer the user's question directly, clearly, and educationally.
Explain concepts in a structured, concise, and easy-to-understand manner.

Do NOT use forensic investigation case templates (do not generate Forensic Assessment, Observed Case Evidence, Not Established Findings, Evidence Gaps, or Case Conclusion).
Do NOT invent case evidence, workstation names, or investigative verdicts.
Provide a clear, objective educational answer to the question asked."""

TECHNICAL_FORENSIC_SYSTEM_PROMPT = """You are a digital forensics knowledge assistant.

Provide a concise, natural educational explanation of the forensic concept, artifact, or investigative methodology.
Use clean headings and bullet points where helpful.
Keep responses concise and suitable for a compact investigation panel (under 250 words).
Avoid excessively long lists of file paths or registry keys unless specifically asked.

Do NOT use a rigid mandatory report template.
Do NOT generate case assessments, observed evidence lists, evidence IDs, or case conclusions about the current case unless the user specifically asks about the loaded case.
Maintain the forensic principle: General forensic knowledge provides investigative guidance and does not constitute evidence in a specific case."""

FORENSIC_SYSTEM_PROMPT = """You are DFIS (Digital Forensics Investigation System) Assistant powered by the local LLM llama3.2:3b.
You assist forensic investigators in analyzing evidence. You are an investigative assistant, NOT an evidence source.

MANDATORY FORENSIC GROUNDING RULES:
1. STRICT EVIDENCE GROUNDING: Only state findings directly supported by the provided evidence artifacts and authoritative case state. Never fabricate artifacts, timestamps, or hashes.
2. CITATIONS: Always cite exact Evidence IDs (e.g. [Evidence IDs: 26, 29] or evidence_ids=[...]) for every case event mentioned.
3. AUTHENTICATION VS UNAUTHORIZED ACCESS: Valid-account authentication (Event ID 4624) proves authentication occurred, but DOES NOT by itself establish unauthorized access or account compromise.
4. NETWORK ACTIVITY VS EXFILTRATION: Observed network traffic / browser requests (e.g. over HTTPS/443) indicate communication, but DO NOT establish data exfiltration or malicious intent without corroborated staging/copying evidence.
5. UNCERTAINTY & GAPS: If evidence for an action (e.g. USB transfer, file copy, exfiltration) is not present, explicitly state that it is NOT ESTABLISHED or INSUFFICIENT EVIDENCE. Do not extrapolate beyond facts.
6. ATT&CK MAPPINGS & HYPOTHESES: MITRE ATT&CK technique labels (e.g. T1567, T1052.001, T1078) are analytical classifications, NOT established facts. Any ATT&CK mapping represents an analytical hypothesis requiring examiner verification and does not by itself establish that the technique succeeded or occurred maliciously.
7. GENERAL KNOWLEDGE: General technical explanations are interpretive context only and cannot be used as case evidence.
8. DISCLAIMERS: Always uphold the principle that AI is an investigative assistant, not an evidence source.

FORMATTING & PRESENTATION RULES:
- Do not output raw internal prompt instructions, bracketed labels, or pseudo-delimiters (do not output [RESPONSE GENERATION], [USER QUESTION ANSWER], etc.).
- Do not escape Markdown characters (do not output \\*\\* or \\*). Output clean standard Markdown only (use headings ##, bold **, bullet points -).
- Do not output empty bullet points, trailing asterisks (*), or malformed markdown headers.
- Put each section heading on its own line.
- For case investigation questions, use clean visible headings:
  ## Forensic Assessment
  ## Observed Case Evidence
  ## Evidence Gaps & Missing Evidence
  ## Investigative Interpretation
  ## Forensic Notice"""

DISCLAIMER_TEXT = (
    "\n\nGeneral forensic knowledge is interpretive only and cannot be used as case evidence.\n"
    "AI is an investigative assistant, not an evidence source."
)


def build_forensic_prompt(
    question: str,
    query_type: str,
    events: list[dict],
    inv: dict,
    rag: dict,
    forensic_state: dict | None = None,
) -> list[dict[str, str]]:
    """Construct structured context-injected messages for llama3.2:3b."""
    category = inv.get("category") or "Normal Activity"
    secondary = inv.get("secondary") or ""
    risk_score = inv.get("risk_score", 0)
    priority = inv.get("priority") or (inv.get("risk") or {}).get("priority") or "LOW"

    # Correlated groups summary
    groups_lines = []
    for g in (inv.get("correlations") or [])[:6]:
        groups_lines.append(
            f"  - {g.get('timestamp')} [{g.get('family')}] {g.get('entity')} (Evidence IDs: {g.get('source_event_ids')})"
        )
    groups_str = "\n".join(groups_lines) if groups_lines else "  - No multi-source correlated clusters."

    # Evidence artifacts summary
    ev_lines = []
    for e in events[:12]:
        ev_lines.append(
            f"  - ID {e.get('id')}: {e.get('timestamp')} [{e.get('source_type')}/{e.get('event_type')}] "
            f"Process: {e.get('process') or '—'}, Target: {e.get('target') or e.get('object') or '—'}, "
            f"Desc: {e.get('description')}"
        )
    ev_str = "\n".join(ev_lines) if ev_lines else "  - No raw events loaded."

    # Knowledge / RAG summary
    kb_docs = rag.get("knowledge") or []
    kb_str = "\n".join(f"  * {k}" for k in kb_docs[:3]) if kb_docs else "  * Standard digital forensics baseline."

    if query_type == "general":
        user_content = f"""[INVESTIGATION QUERY INTENT]: GENERAL FORENSIC CONCEPT DEFINITION
[USER QUESTION]: {question}

--- RETRIEVED FORENSIC KNOWLEDGE BASE (INTERPRETIVE ONLY) ---
{kb_str}

--- CASE-SPECIFIC EVIDENCE FOR CONTEXT ONLY ---
{ev_str}

INSTRUCTIONS:
1. Provide a clear, direct technical definition explaining what {question} means in digital forensics.
2. If related network or artifact activity exists in this case, add a short section titled 'CASE-SPECIFIC CONTEXT:' citing relevant Evidence IDs.
3. State clearly that common technical artifacts (e.g. HTTPS/443, port numbers) do not by themselves establish data exfiltration or malicious intent.
4. Do NOT dump the case incident classification or risk template for this general definition question."""
    else:
        # Canonical state presentation in prompt
        if forensic_state:
            obs = [f"  - {item['title']}: {item['description']} (Evidence IDs: {item.get('evidence_ids', [])})" for item in forensic_state.get("observed_evidence", [])]
            unp = [f"  - {item['title']}: {item['description']} [{item['status'].replace('_', ' ')}]" for item in forensic_state.get("unproven_findings", [])]
            gaps = [f"  - {item['title']}: {item['description']} [{item['severity']}]" for item in forensic_state.get("evidence_gaps", [])]
            state_repr = f"""--- CANONICAL FORENSIC STATE (PRE-CLASSIFIED BY DFIS BACKEND) ---
ASSESSMENT: {forensic_state.get('assessment', {}).get('status', 'NOT ESTABLISHED').replace('_', ' ')} — {forensic_state.get('assessment', {}).get('summary', '')}

OBSERVED EVIDENCE ({len(obs)}):
{chr(10).join(obs)}

NOT ESTABLISHED / UNPROVEN FINDINGS ({len(unp)}):
{chr(10).join(unp)}

EVIDENCE GAPS ({len(gaps)}):
{chr(10).join(gaps)}
"""
        else:
            states_lines = [f"  - {st.get('finding')}: {st.get('state')} ({st.get('detail', '')})" for st in inv.get('evidentiary_states') or []]
            state_repr = "--- 4-TIER EVIDENTIARY STATES ---\n" + "\n".join(states_lines)

        user_content = f"""[INVESTIGATION QUERY INTENT]: {query_type.upper()}
[USER QUESTION]: {question}

--- AUTHORITATIVE CASE STATE ---
Working classification: {category} {f'/ {secondary}' if secondary else ''}
Investigation Priority: {risk_score}/100 — {priority}

{state_repr}

--- CORRELATED ACTIVITY GROUPS ---
{groups_str}

--- INGESTED CASE EVIDENCE SAMPLES ---
{ev_str}

--- RETRIEVED FORENSIC KNOWLEDGE BASE (INTERPRETIVE ONLY) ---
{kb_str}

INSTRUCTIONS:
You are an investigative assistant explaining the canonical case evidence.
1. The evidence classification is already determined by the backend. Do NOT alter what is observed vs unproven.
2. Provide an analytical INVESTIGATIVE INTERPRETATION and ATT&CK ANALYSIS.
3. Provide a numbered EXAMINER VERIFICATION CHECKLIST (1..5) with specific verification steps."""

    return [
        {"role": "system", "content": FORENSIC_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


def check_local_llm_health(
    base_url: str = DEFAULT_OLLAMA_HOST,
    model: str = DEFAULT_MODEL,
) -> dict[str, Any]:
    """Check connectivity to local Ollama daemon and verify model availability."""
    clean_url = base_url.rstrip("/")
    result = {
        "provider": "Ollama (Local LLM)",
        "model": model,
        "base_url": clean_url,
        "connected": False,
        "available_models": [],
        "mode": "offline_grounded_fallback",
        "privacy": "100% Local Inference (Air-Gapped / Zero External Data Leakage)",
        "recommended_command": f"ollama run {model}",
    }

    try:
        with httpx.Client(timeout=2.0) as client:
            resp = client.get(f"{clean_url}/api/tags")
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name") for m in data.get("models", []) if m.get("name")]
                result["connected"] = True
                result["available_models"] = models
                if any(model in m for m in models):
                    result["mode"] = "local_inference_ready"
                else:
                    result["mode"] = "ollama_connected_model_missing"
                    result["recommended_command"] = f"ollama pull {model}"
    except Exception as exc:
        result["error"] = str(exc)
        result["connected"] = False

    return result


def query_ollama(
    messages: list[dict[str, str]],
    model: str = DEFAULT_MODEL,
    base_url: str = DEFAULT_OLLAMA_HOST,
    temperature: float = DEFAULT_TEMPERATURE,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[str]:
    """Send chat request to local Ollama instance."""
    clean_url = base_url.rstrip("/")
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": temperature,
        },
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(f"{clean_url}/api/chat", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                msg = data.get("message", {})
                content = msg.get("content", "").strip()
                if content:
                    return content
    except Exception as exc:
        logger.debug("Local Ollama endpoint unreachable or failed: %s", exc)

    return None


def normalize_llm_response(text: str) -> str:
    """Clean and normalize LLM markdown output, stripping escaped symbols and malformed markers."""
    if not text:
        return ""

    # Convert escaped Markdown into normal clean Markdown
    text = text.replace(r"\*\*", "**")
    text = text.replace(r"\*", "*")
    text = text.replace(r"\_", "_")
    text = text.replace(r"\#", "#")
    text = text.replace(r"\[", "[")
    text = text.replace(r"\]", "]")
    text = text.replace(r"\(", "(")
    text = text.replace(r"\)", ")")

    # Clean malformed heading markers like *IMPORTANT NOTE:** or **TECHNICAL DEFINITION:**
    text = re.sub(r"^\s*[\*\-]?\s*\*?IMPORTANT NOTE:?\*?\*?", "\n\n## Important Forensic Note\n", text, flags=re.MULTILINE | re.IGNORECASE)
    text = re.sub(r"^\s*[\*\-]?\s*\*?AUTHENTICATION VS UNAUTHORIZED ACCESS:?\*?\*?", "\n\n## Successful Logon ≠ Unauthorized Access\n", text, flags=re.MULTILINE | re.IGNORECASE)
    text = re.sub(r"^\s*[\*\-]?\s*\*?NETWORK ACTIVITY VS EXFILTRATION:?\*?\*?", "\n\n## Network Activity ≠ Data Exfiltration\n", text, flags=re.MULTILINE | re.IGNORECASE)
    text = re.sub(r"^\s*[\*\-]?\s*\*?USB CONNECTION VS DATA EXFILTRATION:?\*?\*?", "\n\n## USB Connection ≠ Data Exfiltration\n", text, flags=re.MULTILINE | re.IGNORECASE)
    text = re.sub(r"^\s*[\*\-]?\s*\*?TECHNICAL DEFINITION:?\*?\*?", "\n\n## Concept Definition\n", text, flags=re.MULTILINE | re.IGNORECASE)
    text = re.sub(r"^\s*[\*\-]?\s*\*?CASE-SPECIFIC CONTEXT:?\*?\*?", "\n\n## Case-Specific Context\n", text, flags=re.MULTILINE | re.IGNORECASE)

    # Clean isolated asterisks or empty bullet lines
    text = re.sub(r"^\s*[\*\-]\s*$", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*\*\*\s*$", "", text, flags=re.MULTILINE)

    # If the model produced a '--- FINAL RESPONSE ---' section, extract it
    if "--- FINAL RESPONSE ---" in text:
        final_part = text.split("--- FINAL RESPONSE ---")[-1].strip()
        if len(final_part) > 30:
            text = final_part

    # Strip internal prompt markers and pseudo-delimiters if echoed by the neural model
    prompt_markers = [
        r"^:\s*",
        r"---+\s*(OBJECTIVE RESPONSE|FINAL RESPONSE|EVIDENCE GROUNDING|CITATION|RETRIEVED FORENSIC KNOWLEDGE BASE[^\-]*)\s*---+",
        r"\[RESPONSE GENERATION\]",
        r"\[USER QUESTION ANSWER\]",
        r"\[AUTHORITATIVE CASE STATE CITATION\]",
        r"\[FORENSIC KNOWLEDGE BASE CITATION\]",
        r"\[INVESTIGATION QUERY INTENT CITATION\]",
        r"\[INVESTIGATION QUERY INTENT\]",
        r"\[USER QUESTION\]",
        r"\[FORENSIC GROUNDING RULES CITATION\]",
        r"\[FORENSIC GROUNDING RULES\]",
        r"\[MANDATORY FORENSIC GROUNDING RULES\]",
    ]
    for pattern in prompt_markers:
        text = re.sub(pattern, "", text, flags=re.IGNORECASE | re.MULTILINE)

    # Normalize inline bracketed section titles and list items onto dedicated lines
    section_replacements = [
        (r"\[?FORENSIC ASSESSMENT\]?:?", "\n\n## Forensic Assessment\n"),
        (r"\[?OBSERVED EVIDENCE\]?:?", "\n\n## Observed Case Evidence\n"),
        (r"\[?EVIDENTIARY STATE BREAKDOWN\]?:?", "\n\n## Evidentiary State Breakdown\n"),
        (r"\[?EVIDENCE GAPS(?:\s*&\s*UNVERIFIED ASPECTS)?\]?:?", "\n\n## Evidence Gaps & Missing Evidence\n"),
        (r"\[?INVESTIGATIVE INTERPRETATION(?:\s*&\s*ATT&CK ANALYSIS)?\]?:?", "\n\n## Investigative Interpretation\n"),
        (r"\[?CASE-SPECIFIC CONTEXT(?:\s*&\s*EVIDENCE OBSERVATIONS)?\]?:?", "\n\n## Case-Specific Context\n"),
        (r"(?<=\))\s*-\s*", "\n- "),
        (r"(?<=\.)\s*-\s*", "\n- "),
        (r"(?<=\])\s*-\s*", "\n- "),
    ]
    for pattern, replacement in section_replacements:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

    # Clean double blank lines
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")

    return text.strip()


def post_process_llm_answer(raw_answer: str, query_type: str) -> str:
    """Ensure grounded disclaimers and clean formatting on local LLM outputs."""
    answer = normalize_llm_response(raw_answer)

    # For greetings, ensure no case dumping
    if query_type == "greeting":
        if "Working classification:" in answer or "Investigation Priority:" in answer:
            lines = [l for l in answer.splitlines() if not l.startswith("Working classification:") and not l.startswith("Investigation Priority:")]
            answer = "\n".join(lines).strip()
        return answer

    # For general, hybrid, and case investigation, ensure forensic disclaimers are present
    if "AI is an investigative assistant" not in answer:
        answer = f"{answer}{DISCLAIMER_TEXT}"

    return answer


def extract_llm_analysis(raw_text: str, fallback_analysis: dict) -> dict[str, Any]:
    """Parse LLM narrative text into structured generated_analysis fields."""
    analysis = dict(fallback_analysis)
    if not raw_text:
        return analysis

    clean = normalize_llm_response(raw_text)

    # Search for ATT&CK mapping
    attck_match = re.search(r"(?:ATT&CK\s*Hypothesis|ATT&CK\s*mapping):\s*([^\n]+)", clean, re.IGNORECASE)
    if attck_match:
        analysis["attck_hypothesis"] = attck_match.group(1).strip()

    # Search for Status & Confidence
    status_match = re.search(r"Status:\s*([^\n]+)", clean, re.IGNORECASE)
    if status_match:
        analysis["attck_status"] = status_match.group(1).strip()

    conf_match = re.search(r"Confidence:\s*([^\n]+)", clean, re.IGNORECASE)
    if conf_match:
        analysis["attck_confidence"] = conf_match.group(1).strip()

    # Search for Assessment narrative
    narr_match = re.search(r"(?:Assessment|Investigative\s*Interpretation):\s*([^\n]+(?:\n[^\n#]+)*)", clean, re.IGNORECASE)
    if narr_match:
        narr_text = narr_match.group(1).strip()
        if "Examiner Verification Checklist" in narr_text or "1." in narr_text:
            narr_text = re.split(r"(?:Examiner\s*Verification\s*Checklist|1\.\s*)", narr_text)[0].strip()
        if len(narr_text) > 20:
            analysis["interpretation"] = narr_text

    # Search for Examiner verification steps
    steps = re.findall(r"(?:\d+\.\s+[^\n]+)", clean)
    if len(steps) >= 2:
        analysis["verification_steps"] = [s.strip() for s in steps if len(s.strip()) > 5]

    return analysis


def generate_chat_response(
    question: str,
    events: list[dict],
    inv: dict,
    rag: dict,
    model: str = DEFAULT_MODEL,
    base_url: str = DEFAULT_OLLAMA_HOST,
    temperature: float = DEFAULT_TEMPERATURE,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Execute complete Local LLM query with explicit intent classification and generation metadata.
    
    Guarantees:
    - 100% local execution.
    - Intent-based routing: GENERAL, TECHNICAL_FORENSIC, FORENSIC_CASE_ANALYSIS, GREETING.
    - General questions get clean educational responses without forensic templates.
    - Technical forensic questions get concept explanations with forensic notices.
    - Case investigation queries get canonical forensic state with evidence citations.
    """
    from app.services.investigation import (
        INTENT_CASE_ANALYSIS,
        INTENT_CASE_GUIDANCE,
        INTENT_CASE_QUERY,
        INTENT_FORENSIC_KNOWLEDGE,
        INTENT_GENERAL,
        INTENT_GREETING,
        INTENT_TECHNICAL_FORENSIC,
        METHODOLOGY_KEYWORDS,
        answer_question,
        build_canonical_forensic_state,
        classify_query_intent,
        classify_user_query,
        format_forensic_answer_markdown,
        generate_analysis_narrative,
        get_concept_definition,
        get_forensic_methodology_response,
        get_general_concept_response,
    )

    intent = classify_query_intent(question)
    q_type = classify_user_query(question)
    req_id = f"chat-{uuid.uuid4().hex[:8]}"
    gen_time = datetime.now().astimezone().isoformat()

    # 1. GREETING INTENT
    if intent == INTENT_GREETING:
        answer = answer_question(question, rag, events, inv)
        return {
            "answer": answer,
            "intent": INTENT_GREETING,
            "query_type": "greeting",
            "model": model,
            "provider": "dfis_assistant",
            "llm_mode": "local_greeting",
            "is_local": True,
            "forensic_state": None,
            "generated_analysis": None,
            "concept_data": None,
            "generator": {
                "type": "assistant",
                "provider": "dfis_assistant",
                "model": model,
                "mode": "local_assistant_guidance",
                "fallback": False,
                "verified": True,
                "reason": None,
                "provenance_id": req_id,
                "request_id": req_id,
                "generated_at": gen_time,
            },
        }

    # 2. GENERAL EDUCATIONAL INTENT (e.g., "What is HTTP?", "Explain cryptography", "What is AI?")
    if intent == INTENT_GENERAL:
        messages = [
            {"role": "system", "content": GENERAL_SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ]
        local_output = None
        ollama_error = None
        try:
            local_output = query_ollama(
                messages=messages,
                model=model,
                base_url=base_url,
                temperature=temperature,
                timeout=timeout,
            )
        except Exception as exc:
            ollama_error = str(exc)

        if local_output:
            clean_answer = normalize_llm_response(local_output)
            return {
                "answer": clean_answer,
                "intent": INTENT_GENERAL,
                "query_type": "general",
                "model": model,
                "provider": "ollama",
                "llm_mode": "local_general_ai",
                "is_local": True,
                "forensic_state": None,
                "generated_analysis": None,
                "concept_data": None,
                "generator": {
                    "type": "llm",
                    "provider": "ollama",
                    "model": model,
                    "mode": "local_general_ai",
                    "fallback": False,
                    "verified": True,
                    "reason": None,
                    "provenance_id": req_id,
                    "request_id": req_id,
                    "generated_at": gen_time,
                },
            }

        fallback_general = get_general_concept_response(question)
        return {
            "answer": fallback_general,
            "intent": INTENT_GENERAL,
            "query_type": "general",
            "model": f"{model} (Offline Grounded Local Engine)",
            "provider": "dfis_grounded_engine",
            "llm_mode": "local_grounded_engine",
            "is_local": True,
            "forensic_state": None,
            "generated_analysis": None,
            "concept_data": None,
            "generator": {
                "type": "fallback",
                "provider": "dfis_grounded_engine",
                "model": None,
                "mode": "deterministic_grounded_fallback",
                "fallback": True,
                "verified": False,
                "reason": ollama_error or "ollama_unreachable",
                "provenance_id": req_id,
                "request_id": req_id,
                "generated_at": gen_time,
            },
        }

    # 3. FORENSIC KNOWLEDGE INTENT (e.g., "Event ID 4624", "USBSTOR", "How to detect suspicious activity?")
    if intent in {INTENT_FORENSIC_KNOWLEDGE, INTENT_TECHNICAL_FORENSIC}:
        is_meth = any(k in question.lower() for k in METHODOLOGY_KEYWORDS)
        messages = [
            {"role": "system", "content": TECHNICAL_FORENSIC_SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ]
        local_output = None
        ollama_error = None
        try:
            local_output = query_ollama(
                messages=messages,
                model=model,
                base_url=base_url,
                temperature=temperature,
                timeout=timeout,
            )
        except Exception as exc:
            ollama_error = str(exc)

        if local_output:
            clean_output = normalize_llm_response(local_output)
            if "General forensic knowledge is interpretive only" not in clean_output:
                clean_output = f"{clean_output}\n\nGeneral forensic knowledge is interpretive only and does not constitute evidence in the current case."
            return {
                "answer": clean_output,
                "intent": INTENT_FORENSIC_KNOWLEDGE,
                "query_type": "technical_forensic",
                "model": model,
                "provider": "ollama",
                "llm_mode": "local_forensic_knowledge",
                "is_local": True,
                "forensic_state": None,
                "generated_analysis": None,
                "concept_data": {
                    "title": question,
                    "definition": clean_output,
                    "context": [],
                    "rules": [],
                },
                "generator": {
                    "type": "llm",
                    "provider": "ollama",
                    "model": model,
                    "mode": "local_forensic_knowledge",
                    "fallback": False,
                    "verified": True,
                    "reason": None,
                    "provenance_id": req_id,
                    "request_id": req_id,
                    "generated_at": gen_time,
                },
            }

        # Offline fallback
        if is_meth:
            meth_text = get_forensic_methodology_response(question)
            fallback_text = f"{meth_text}\n\nGeneral forensic knowledge is interpretive only and does not constitute evidence in the current case."
            return {
                "answer": fallback_text,
                "intent": INTENT_FORENSIC_KNOWLEDGE,
                "query_type": "technical_forensic",
                "model": f"{model} (Offline Grounded Local Engine)",
                "provider": "dfis_grounded_engine",
                "llm_mode": "local_forensic_knowledge",
                "is_local": True,
                "forensic_state": None,
                "generated_analysis": None,
                "concept_data": {
                    "title": question,
                    "definition": meth_text,
                    "context": [],
                    "rules": [],
                },
                "generator": {
                    "type": "fallback",
                    "provider": "dfis_grounded_engine",
                    "model": None,
                    "mode": "deterministic_grounded_fallback",
                    "fallback": True,
                    "verified": False,
                    "reason": ollama_error or "ollama_unreachable",
                    "provenance_id": req_id,
                    "request_id": req_id,
                    "generated_at": gen_time,
                },
            }
        else:
            q_title, definition = get_concept_definition(question)
            ans = f"### {q_title}\n\n{definition}\n\nGeneral forensic knowledge is interpretive only and does not constitute evidence in the current case."
            return {
                "answer": ans,
                "intent": INTENT_FORENSIC_KNOWLEDGE,
                "query_type": "technical_forensic",
                "model": f"{model} (Offline Grounded Local Engine)",
                "provider": "dfis_grounded_engine",
                "llm_mode": "local_forensic_knowledge",
                "is_local": True,
                "forensic_state": None,
                "generated_analysis": None,
                "concept_data": {"title": q_title, "definition": definition, "context": [], "rules": []},
                "generator": {
                    "type": "fallback",
                    "provider": "dfis_grounded_engine",
                    "model": None,
                    "mode": "deterministic_grounded_fallback",
                    "fallback": True,
                    "verified": False,
                    "reason": ollama_error or "ollama_unreachable",
                    "provenance_id": req_id,
                    "request_id": req_id,
                    "generated_at": gen_time,
                },
            }

    # 4. CASE GUIDANCE INTENT (e.g. "What are the recommended next steps?", "How should we investigate this case?")
    if intent == "CASE_GUIDANCE":
        from app.services.actions import format_actions, recommend_actions
        actions = inv.get("next_actions") or recommend_actions(events, inv.get("correlations") or [])
        formatted_acts = format_actions(actions)
        guidance_text = (
            f"### Recommended Investigation Actions (Derived from Evidentiary Gaps)\n\n"
            f"{formatted_acts}\n\n"
            "All recommendations represent examiner verification steps. "
            "AI is an investigative assistant, not an evidence source."
        )
        return {
            "answer": guidance_text,
            "intent": "CASE_GUIDANCE",
            "query_type": "case_guidance",
            "model": f"{model} (Local Forensic Assistant)",
            "provider": "dfis_assistant",
            "llm_mode": "local_case_guidance",
            "is_local": True,
            "forensic_state": None,
            "generated_analysis": None,
            "concept_data": None,
            "generator": {
                "type": "assistant",
                "provider": "dfis_assistant",
                "model": model,
                "mode": "local_case_guidance",
                "fallback": False,
                "verified": True,
                "reason": None,
                "provenance_id": req_id,
                "request_id": req_id,
                "generated_at": gen_time,
            },
        }

    # 5. CASE QUERY INTENT (Full DFIS Canonical State Engine)
    forensic_state = build_canonical_forensic_state(events, inv, question)
    fallback_analysis = generate_analysis_narrative(question, events, inv, forensic_state)
    messages = build_forensic_prompt(question, "case_investigation", events, inv, rag, forensic_state=forensic_state)

    local_output = None
    ollama_error = None
    try:
        local_output = query_ollama(
            messages=messages,
            model=model,
            base_url=base_url,
            temperature=temperature,
            timeout=timeout,
        )
    except Exception as exc:
        ollama_error = str(exc)
        logger.warning("Ollama generation error: %s", exc)

    if local_output:
        llm_analysis = extract_llm_analysis(local_output, fallback_analysis)
        answer = format_forensic_answer_markdown(forensic_state, llm_analysis)
        return {
            "answer": answer,
            "intent": "CASE_QUERY",
            "query_type": "case_investigation",
            "model": model,
            "provider": "ollama",
            "llm_mode": "local_neural_inference",
            "is_local": True,
            "forensic_state": forensic_state,
            "generated_analysis": llm_analysis,
            "concept_data": None,
            "generator": {
                "type": "llm",
                "provider": "ollama",
                "model": model,
                "mode": "local_neural_inference",
                "fallback": False,
                "verified": True,
                "reason": None,
                "provenance_id": req_id,
                "request_id": req_id,
                "generated_at": gen_time,
            },
        }

    # Fallback to Local Deterministic Grounded Reasoning Engine
    logger.info("Ollama unavailable or unverified. Using DFIS grounded fallback engine.")
    fallback_answer = format_forensic_answer_markdown(forensic_state, fallback_analysis)
    return {
        "answer": fallback_answer,
        "intent": "CASE_QUERY",
        "query_type": "case_investigation",
        "model": f"{model} (Offline Grounded Local Engine)",
        "provider": "dfis_grounded_engine",
        "llm_mode": "local_grounded_engine",
        "is_local": True,
        "forensic_state": forensic_state,
        "generated_analysis": fallback_analysis,
        "concept_data": None,
        "generator": {
            "type": "fallback",
            "provider": "dfis_grounded_engine",
            "model": None,
            "mode": "deterministic_grounded_fallback",
            "fallback": True,
            "verified": False,
            "reason": ollama_error or "ollama_unreachable",
            "provenance_id": req_id,
            "request_id": req_id,
            "generated_at": gen_time,
        },
    }
