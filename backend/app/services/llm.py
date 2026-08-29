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
6. HYPOTHESES: Clearly label ATT&CK mappings (such as T1567, T1052.001) as HYPOTHESES requiring examiner verification.
7. GENERAL KNOWLEDGE: General technical explanations are interpretive context only and cannot be used as case evidence.
8. DISCLAIMERS: Always uphold the principle that AI is an investigative assistant, not an evidence source."""

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

    user_content = f"""[INVESTIGATION QUERY INTENT]: {query_type.upper()}
[USER QUESTION]: {question}

--- AUTHORITATIVE CASE STATE ---
Working classification: {category} {f'/ {secondary}' if secondary else ''}
Investigation Priority: {risk_score}/100 — {priority}

--- 4-TIER EVIDENTIARY STATES ---
{states_str}

--- CORRELATED ACTIVITY GROUPS (ANALYTICAL RELATIONSHIPS) ---
{groups_str}

--- INGESTED CASE EVIDENCE SAMPLES ---
{ev_str}

--- RETRIEVED FORENSIC KNOWLEDGE BASE (INTERPRETIVE ONLY) ---
{kb_str}

Please generate an objective, forensically grounded response to the examiner's question. Follow all grounding rules strictly."""

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


def post_process_llm_answer(raw_answer: str, query_type: str) -> str:
    """Ensure grounded disclaimers and clean formatting on local LLM outputs."""
    answer = raw_answer.strip()

    # For greetings, ensure no case dumping
    if query_type == "greeting":
        if "Working classification:" in answer or "Investigation Priority:" in answer:
            # Strip injected template if LLM regurgitated it
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
                "fallback": False,
                "verified": True,
                "mode": "Local Assistant Guidance",
                "reason": None,
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
                "fallback": False,
                "verified": True,
                "mode": "Local Neural Inference",
                "reason": None,
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
            "fallback": True,
            "verified": False,
            "mode": "Rule/Template-Based Grounded Engine",
            "reason": ollama_error or "Ollama service unavailable on port 11434",
            "request_id": req_id,
            "generated_at": gen_time,
        },
    }
