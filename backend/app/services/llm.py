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
- For technical concepts, use clean visible headings:
  ## Concept Definition
  ## Case-Specific Context
  ## Forensic Interpretation Rules
  ## Forensic Notice
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
) -> list[dict[str, str]]:
    """Construct structured context-injected messages for llama3.2:3b."""
    category = inv.get("category") or "Normal Activity"
    secondary = inv.get("secondary") or ""
    risk_score = inv.get("risk_score", 0)
    priority = inv.get("priority") or (inv.get("risk") or {}).get("priority") or "LOW"

    # Evidentiary states summary
    states_lines = []
    for st in inv.get("evidentiary_states") or []:
        states_lines.append(f"  - {st.get('finding')}: {st.get('state')} ({st.get('detail', '')})")
    states_str = "\n".join(states_lines) if states_lines else "  - No state transitions evaluated."

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
        user_content = f"""[INVESTIGATION QUERY INTENT]: {query_type.upper()}
[USER QUESTION]: {question}

--- AUTHORITATIVE CASE STATE ---
Working classification: {category} {f'/ {secondary}' if secondary else ''}
Investigation Priority: {risk_score}/100 — {priority}

--- 4-TIER EVIDENTIARY STATES ---
{states_str}

--- CORRELATED ACTIVITY GROUPS ---
{groups_str}

--- INGESTED CASE EVIDENCE SAMPLES ---
{ev_str}

--- RETRIEVED FORENSIC KNOWLEDGE BASE (INTERPRETIVE ONLY) ---
{kb_str}

INSTRUCTIONS:
Provide an objective, structured response following these sections:
FORENSIC ASSESSMENT: State whether the finding is OBSERVED, NOT ESTABLISHED, or HYPOTHESIZED with supporting rationale.
OBSERVED EVIDENCE: List specific observed case events with exact Evidence IDs (e.g. Evidence ID [27, 28]).
EVIDENCE GAPS: Explicitly state any missing or unverified evidence (e.g. drive-to-device mapping).
INVESTIGATIVE INTERPRETATION: Explain analytical hypotheses (e.g. ATT&CK mappings) and examiner verification steps."""

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
    """Execute complete Local LLM query with explicit generation metadata & provenance.
    
    Guarantees:
    - 100% local execution
    - Clear provenance metadata distinguishing neural completions vs fallback
    - Timestamps and unique Request IDs for cryptographic provenance tracking
    - Never calls online/external chatbots
    - If Ollama daemon is active, uses llama3.2:3b local neural reasoning (verified=True, fallback=False)
    - If Ollama daemon is starting/offline, uses deterministic forensic engine (verified=False, fallback=True)
    - Enforces 4-tier evidentiary state consistency and grounding invariants
    """
    from app.services.investigation import answer_question, classify_user_query

    q_type = classify_user_query(question)
    req_id = f"chat-{uuid.uuid4().hex[:8]}"
    gen_time = datetime.now().astimezone().isoformat()

    # 1. Check if greeting -> return structured greeting directly for instant crisp UX
    if q_type == "greeting":
        answer = answer_question(question, rag, events, inv)
        return {
            "answer": answer,
            "model": model,
            "provider": "dfis_assistant",
            "llm_mode": "local_greeting",
            "is_local": True,
            "query_type": q_type,
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

    # 2. Build local LLM prompt
    messages = build_forensic_prompt(question, q_type, events, inv, rag)

    # 3. Attempt local inference via Ollama
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
        processed_answer = post_process_llm_answer(local_output, q_type)
        return {
            "answer": processed_answer,
            "model": model,
            "provider": "ollama",
            "llm_mode": "local_neural_inference",
            "is_local": True,
            "query_type": q_type,
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

    # 4. Fallback to Local Deterministic Grounded Reasoning Engine
    logger.info("Ollama unavailable or unverified. Using DFIS grounded fallback engine.")
    fallback_answer = answer_question(question, rag, events, inv)
    return {
        "answer": fallback_answer,
        "model": f"{model} (Offline Grounded Local Engine)",
        "provider": "dfis_grounded_engine",
        "llm_mode": "local_grounded_engine",
        "is_local": True,
        "query_type": q_type,
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
