import json
import os
import re
from collections import Counter

from app.services.investigation import answer_from_investigation, run_investigation

CATEGORIES = [
    "Data Theft",
    "Insider Threat",
    "Malware Infection",
    "Unauthorized Access",
    "Ransomware",
    "Credential Abuse",
    "Normal Activity",
]

RULES = [
    (r"usb", 18, "usb", "T1052", "Exfiltration"),
    (r"file_copy|file copy|copied to|e:/transfer|e:\\\\transfer", 16, "exfil_copy", "T1052", "Exfiltration"),
    (r"sensitive_|customer_list|confidential", 10, "collection", "T1005", "Collection"),
    (r"\.zip|archive|staging", 14, "archive", "T1560", "Collection"),
    (r"google drive|dropbox|wetransfer|onedrive", 16, "cloud", "T1567", "Exfiltration"),
    (r"failed.?logon|4625|credential", 12, "creds", "T1110", "Credential Access"),
    (r"ransom|encrypt|\.locked", 25, "ransom", "T1486", "Impact"),
    (r"run key|persistence|scheduled task|service_install|7045", 12, "persist", "T1543.003", "Persistence"),
    (r"powershell|cmd\.exe|4688|process_create", 8, "exec", "T1059", "Execution"),
    (r"logon|login|4624|admin_logon", 4, "access", "T1078", "Initial Access"),
]


def analyze_timeline(events: list[dict], case_id: int | None = None) -> dict:
    if case_id is not None:
        return run_investigation(case_id, events)
    blob = "\n".join(f"{e.get('description','')} {e.get('event_type','')}" for e in events).lower()
    score = 0
    hits = []
    stages = []
    mitre = []
    supporting = []
    for pat, pts, label, tid, stage in RULES:
        if re.search(pat, blob):
            score += pts
            hits.append(label)
            mitre.append(tid)
            stages.append(stage)
            for e in events:
                text = f"{e.get('description','')} {e.get('event_type','')}".lower()
                if re.search(pat, text):
                    supporting.append(e.get("id"))
    score = min(100, score)
    theftish = ("usb" in hits or "cloud" in hits or "exfil_copy" in hits) and (
        "archive" in hits or "collection" in hits or "exfil_copy" in hits
    )
    if score >= 30 and theftish:
        category = "Data Theft"
        if any(
            e.get("actor") or "logon" in str(e.get("event_type", "")).lower()
            for e in events
        ):
            category = "Insider Threat"
    elif "ransom" in hits:
        category = "Ransomware"
    elif "creds" in hits and score >= 12:
        category = "Credential Abuse"
    elif "persist" in hits and "usb" not in hits:
        category = "Malware Infection"
    elif score < 10:
        category = "Normal Activity"
    else:
        category = "Unauthorized Access" if "access" in hits else "Insider Threat"

    bullets = []
    for e in sorted(events, key=lambda x: x.get("timestamp") or ""):
        if e.get("source_type") == "correlated":
            bullets.append(f"- {e.get('timestamp')}: {e.get('description')}")
    if not bullets:
        for e in events:
            if e.get("event_type") in {"file_copy", "usb_connect", "usb_remove", "logon", "process_create"}:
                bullets.append(f"- [{e.get('id')}] {e.get('timestamp')} {e.get('description')}")
    narrative = (
        f"Preliminary classification: possible {category}. "
        "Findings are consistent with the reconstructed timeline; they do not prove intent.\n"
        + ("\n".join(bullets[:12]) if bullets else "No correlated multi-source activities identified.")
        + f"\nIndicators: {', '.join(hits) or 'none'}. "
        "AI is an assistant, not an evidence source."
    )

    findings = [
        {
            "category": category,
            "title": f"Possible {category}",
            "body": narrative,
            "risk_score": float(score),
            "confidence": 0.55 if score < 30 else 0.72 if score < 60 else 0.84,
            "attack_stage": " → ".join(dict.fromkeys(stages)),
            "mitre_ids": ", ".join(dict.fromkeys(mitre)),
            "artifact_ids": ",".join(str(i) for i in dict.fromkeys(supporting) if i is not None),
        }
    ]
    # chain narrative
    ordered = [e for e in events if e.get("timestamp")]
    chain = []
    for e in ordered:
        et = (e.get("event_type") or "").lower()
        if any(k in et or k in (e.get("description") or "").lower() for k in ("logon", "usb", "file", "zip", "url", "download", "copy")):
            chain.append(
                {
                    "time": str(e.get("timestamp")),
                    "event": e.get("description"),
                    "id": e.get("id"),
                    "type": e.get("event_type"),
                }
            )
    return {
        "category": category,
        "risk_score": score,
        "findings": findings,
        "attack_chain": chain[:20],
        "source_counts": dict(Counter(e.get("source_type") for e in events)),
    }


def answer_question(question: str, rag: dict, events: list[dict], analysis: dict) -> str:
    ev_ctx = "\n".join(rag.get("evidence") or []) or "No case embeddings yet."
    kn_ctx = "\n".join(rag.get("knowledge") or [])
    api_key = os.environ.get("OPENAI_API_KEY")
    if api_key:
        try:
            import httpx

            prompt = (
                "You are a digital-forensics assistant. Use only the evidence. "
                "Cite artifact lines. Do not invent events.\n\n"
                f"Knowledge:\n{kn_ctx}\n\nEvidence:\n{ev_ctx}\n\nQuestion: {question}"
            )
            r = httpx.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                },
                timeout=60,
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except Exception as exc:
            fallback = f"(Remote LLM unavailable: {exc})\n\n"
    else:
        fallback = ""
    # local grounded answer
    q = question.lower()
    lines = [fallback + f"**Grounded answer** (local ForensicLLM-style RAG, no weights required).\n"]
    lines.append(f"Working classification: **{analysis.get('category')}** (risk {analysis.get('risk_score')}).\n")
    lines.append("Retrieved case evidence:")
    if rag.get("evidence"):
        for e in rag["evidence"][:8]:
            lines.append(f"- {e}")
    else:
        # keyword filter
        for e in events:
            blob = json.dumps(e, default=str).lower()
            if any(tok in blob for tok in re.findall(r"[a-z0-9.]{3,}", q)):
                lines.append(f"- [{e.get('id')}] {e.get('timestamp')} {e.get('description')}")
    lines.append("\nGeneral forensic knowledge used:")
    for k in (rag.get("knowledge") or [])[:4]:
        lines.append(f"- {k}")
    lines.append(
        "\n_AI is an assistant, not an evidence source. Verify against original artifacts and hashes._"
    )
    return "\n".join(lines)
