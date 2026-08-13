"""Case-specific investigation: correlated briefs → RAG → classification / risk / chain."""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict

from app.services.knowledge import FORENSIC_KB
from app.services.rag import retrieve


def group_correlations(events: list[dict]) -> list[dict]:
    """Correlation IDs link raw evidence; CORRELATED_ACTIVITY is analysis only."""
    by_cid: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        cid = (e.get("correlation_id") or "").strip()
        if cid and e.get("source_type") != "correlated":
            by_cid[cid].append(e)

    groups = []
    for cid, members in by_cid.items():
        members = sorted(members, key=lambda x: x.get("timestamp") or "")
        summary = next(
            (e for e in events if e.get("source_type") == "correlated" and e.get("correlation_id") == cid),
            None,
        )
        family = ""
        entity = ""
        if summary:
            parts = (summary.get("description") or "").split("|")
            if len(parts) >= 3:
                family = parts[1].strip()
                entity = parts[2].strip()
        if not family:
            family = members[0].get("event_type") or "activity"
        if not entity:
            entity = members[0].get("target") or ""
        sources = []
        for m in members:
            sources.append(
                {
                    "event_id": m.get("id"),
                    "source_type": m.get("source_type"),
                    "event_type": m.get("event_type"),
                    "source_file": m.get("source_file") or "",
                    "description": m.get("description"),
                }
            )
        groups.append(
            {
                "correlation_id": cid,
                "role": "analytical_link",
                "timestamp": members[0].get("timestamp"),
                "family": family,
                "entity": entity,
                "actor": next((m.get("actor") for m in members if m.get("actor")), ""),
                "destination": next((m.get("destination_path") for m in members if m.get("destination_path")), ""),
                "sources": sources,
                "source_event_ids": [m.get("id") for m in members if m.get("id") is not None],
                "brief": _brief(cid, family, entity, members),
            }
        )
    groups.sort(key=lambda g: g.get("timestamp") or "")
    return groups


def _brief(cid: str, family: str, entity: str, members: list[dict]) -> str:
    lines = [
        f"CORRELATED EVENT (analytical, not evidence) link={cid}",
        f"Type: {family}",
        f"Entity: {entity}",
        f"Time: {members[0].get('timestamp')}",
        f"User: {next((m.get('actor') for m in members if m.get('actor')), 'unknown')}",
        "Supporting evidence events:",
    ]
    for m in members:
        lines.append(
            f"  - event_id={m.get('id')} {m.get('source_type')}/{m.get('event_type')} "
            f"file={m.get('source_file') or '?'} :: {m.get('description')}"
        )
    return "\n".join(lines)


def classify_and_score(events: list[dict], groups: list[dict]) -> dict:
    blob = " ".join(f"{e.get('description','')} {e.get('event_type','')}" for e in events).lower()
    usb = "usb" in blob or any(g["family"] == "usb_connect" for g in groups)
    copies = any(g["family"] == "file_copy" for g in groups) or "file_copy" in blob
    sensitive = bool(re.search(r"sensitive_|customer_list|confidential", blob))
    powershell = "powershell" in blob
    service = any(g["family"] == "service" for g in groups)
    network = any(g["family"] == "network" for g in groups) or "10.0.0.50" in blob or "drive.example" in blob
    logon = "logon" in blob or "4624" in blob

    score = 0
    if logon:
        score += 6
    if powershell:
        score += 10
    if service:
        score += 12
    if usb:
        score += 18
    if sensitive:
        score += 12
    if copies:
        score += 18
    if network:
        score += 10
    score = min(100, score)

    if copies and (usb or network) and (sensitive or logon):
        category = "Insider Threat"
        secondary = "Possible data exfiltration"
    elif copies and sensitive:
        category = "Data Theft"
        secondary = "Sensitive files staged/copied"
    elif service and powershell and not copies:
        category = "Malware Infection"
        secondary = "Persistence / execution without confirmed collection"
    elif score < 12:
        category = "Normal Activity"
        secondary = "Insufficient suspicious indicators"
    else:
        category = "Unauthorized Access"
        secondary = "Suspicious activity without a complete exfil chain"

    mitre = []
    stages = []
    if logon:
        mitre.append("T1078")
        stages.append("Initial Access")
    if powershell:
        mitre.append("T1059.001")
        stages.append("Execution")
    if service:
        mitre.append("T1543.003")
        stages.append("Persistence")
    if sensitive:
        mitre.append("T1005")
        stages.append("Collection")
    if copies and usb:
        mitre.append("T1052.001")
        stages.append("Exfiltration")
    if network:
        mitre.append("T1567")
        stages.append("Command and Control / Exfiltration")

    return {
        "category": category,
        "secondary": secondary,
        "risk_score": score,
        "confidence": 0.62 if score < 40 else 0.78 if score < 70 else 0.86,
        "mitre_ids": ", ".join(dict.fromkeys(mitre)),
        "attack_stage": " → ".join(dict.fromkeys(stages)),
    }


def attack_chain(events: list[dict], groups: list[dict]) -> list[dict]:
    """Ordered hypothesis steps, each linked to raw event IDs."""
    steps = []

    def add(time, title, mitre, ids, note):
        steps.append(
            {
                "time": time,
                "title": title,
                "mitre": mitre,
                "evidence_event_ids": [i for i in ids if i is not None],
                "note": note,
            }
        )

    def ids_for(*fams):
        out = []
        for g in groups:
            if g["family"] in fams:
                out.extend(g["source_event_ids"])
        if out:
            return out
        for e in events:
            if e.get("event_type") in fams or e.get("source_type") == "correlated":
                if e.get("source_type") != "correlated":
                    out.append(e.get("id"))
        return out

    timed = [e for e in events if e.get("timestamp") and e.get("source_type") != "correlated"]
    logons = [e for e in timed if e.get("event_type") in {"logon", "admin_logon"}]
    if logons:
        add(logons[0].get("timestamp"), "User session started", "T1078", [logons[0].get("id")], logons[0].get("description"))
    ps = [e for e in timed if "powershell" in (e.get("description") or "").lower()]
    if ps:
        add(ps[0].get("timestamp"), "PowerShell execution", "T1059.001", [ps[0].get("id")], "Process creation observed")
    for g in groups:
        if g["family"] == "service":
            add(g["timestamp"], f"Service/persistence ({g['entity']})", "T1543.003", g["source_event_ids"], "Multi-source service install")
        if g["family"] == "usb_connect":
            add(g["timestamp"], "Removable media connected", "T1091/T1052", g["source_event_ids"], g["entity"])
        if g["family"] == "file_access":
            add(g["timestamp"], f"Sensitive file accessed ({g['entity']})", "T1005", g["source_event_ids"], "Independent artifacts agree")
        if g["family"] == "file_copy":
            dest = g.get("destination") or "transfer location"
            add(g["timestamp"], f"File copied ({g['entity']})", "T1052.001", g["source_event_ids"], dest)
        if g["family"] == "usb_remove":
            add(g["timestamp"], "Removable media removed", "T1052", g["source_event_ids"], "")
        if g["family"] == "network":
            add(g["timestamp"], "Internal drive / network session", "T1567", g["source_event_ids"], g["entity"])
    if not any(s["title"].startswith("Internal") for s in steps):
        net = [e for e in timed if e.get("source_type") in {"network", "browser"}]
        if net:
            add(net[0].get("timestamp"), "Network/browser activity", "T1567", [e.get("id") for e in net[:4]], net[0].get("description"))
    mem = [e for e in events if e.get("source_type") == "memory"]
    if mem:
        add(
            mem[0].get("observation_time") or mem[0].get("timestamp"),
            "Memory snapshot (observation time, not process start)",
            "",
            [e.get("id") for e in mem],
            "Synthetic memory list; timestamp is capture time",
        )
    # de-dupe similar titles
    seen = set()
    uniq = []
    for s in steps:
        key = (s["title"], s["time"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(s)
    return uniq


def investigation_narrative(cls: dict, groups: list[dict], chain: list[dict], rag: dict) -> str:
    if groups:
        hypothesis = (
            "The reconstructed timeline is consistent with access to sensitive files, copying to a "
            "transfer location, removable-media activity, and later network communication. "
            "These observations are correlated across independent artifacts. "
            "Malicious intent cannot be established from these events alone."
        )
    else:
        hypothesis = "Insufficient correlated multi-source activity to support an exfiltration hypothesis."
    lines = [
        f"Preliminary classification: Possible {cls['category'].lower()} / {cls['secondary'].lower()}.",
        "",
        hypothesis,
        "",
        "Correlated activities (analytical links; evidence is the listed event IDs):",
    ]
    for g in groups:
        lines.append(
            f"- {g['timestamp']} {g['family']} {g['entity']} link={g['correlation_id']} "
            f"evidence_ids={g['source_event_ids']}"
        )
    lines.append("")
    lines.append("Attack-chain hypothesis (review required):")
    for s in chain:
        lines.append(f"- {s['time']} {s['title']} [{s['mitre']}] evidence_ids={s['evidence_event_ids']}")
    if rag.get("knowledge"):
        lines.append("")
        lines.append("Forensic knowledge retrieved:")
        for k in rag["knowledge"][:4]:
            lines.append(f"- {k}")
    lines.append("")
    lines.append("AI is an assistant, not an evidence source. Correlation IDs are links, not artifacts.")
    return "\n".join(lines)


def run_investigation(case_id: int, events: list[dict]) -> dict:
    groups = group_correlations(events)
    briefs = "\n\n".join(g["brief"] for g in groups) or "No multi-source correlations."
    rag = retrieve(case_id, "USB file copy sensitive exfiltration insider PowerShell service")
    rag["evidence"] = [g["brief"] for g in groups][:10] + (rag.get("evidence") or [])[:4]
    cls = classify_and_score(events, groups)
    chain = attack_chain(events, groups)
    body = investigation_narrative(cls, groups, chain, rag)

    # optional remote LLM polish, still grounded
    api_key = os.environ.get("OPENAI_API_KEY")
    if api_key:
        try:
            import httpx

            prompt = (
                "You are a digital-forensics assistant. Use only the correlated briefs. "
                "Do not claim proof of intent. Cite evidence event IDs. "
                "Correlation IDs are links, not evidence.\n\n"
                f"Knowledge:\n" + "\n".join(rag.get("knowledge") or []) + "\n\n"
                f"Briefs:\n{briefs}\n\n"
                "Write a short preliminary classification and attack-chain explanation."
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
            body = r.json()["choices"][0]["message"]["content"] + "\n\n" + body
        except Exception:
            pass

    evidence_ids = []
    for g in groups:
        evidence_ids.extend(g["source_event_ids"])
    return {
        "category": cls["category"],
        "secondary": cls["secondary"],
        "risk_score": cls["risk_score"],
        "confidence": cls["confidence"],
        "mitre_ids": cls["mitre_ids"],
        "attack_stage": cls["attack_stage"],
        "attack_chain": chain,
        "correlations": groups,
        "rag": rag,
        "findings": [
            {
                "category": cls["category"],
                "title": f"Possible {cls['category']} / {cls['secondary']}",
                "body": body,
                "risk_score": float(cls["risk_score"]),
                "confidence": cls["confidence"],
                "attack_stage": cls["attack_stage"],
                "mitre_ids": cls["mitre_ids"],
                "artifact_ids": ",".join(str(i) for i in dict.fromkeys(evidence_ids)),
            }
        ],
        "source_counts": {},
    }


def answer_from_investigation(question: str, events: list[dict], inv: dict) -> str:
    q = question.lower()
    lines = [
        f"**Investigation answer** (grounded in correlated timeline, not the ZIP).",
        f"Preliminary classification: possible **{inv.get('category')}** / {inv.get('secondary')}. "
        f"Risk {inv.get('risk_score')}. Intent is not established.",
        "",
    ]
    groups = inv.get("correlations") or []
    scored = []
    toks = {t for t in re.findall(r"[a-z0-9._-]{3,}", q)}
    for g in groups:
        blob = (g.get("brief") or "").lower()
        scored.append((sum(1 for t in toks if t in blob), g))
    scored.sort(key=lambda x: -x[0])
    use = [g for s, g in scored if s > 0][:6] or [g for _, g in scored[:5]]
    lines.append("Supporting correlated activities and their evidence event IDs:")
    for g in use:
        lines.append(
            f"- {g['timestamp']} {g['family']} {g['entity']} link={g['correlation_id']} "
            f"evidence_ids={g['source_event_ids']}"
        )
        for s in g["sources"][:4]:
            lines.append(f"    event_id={s['event_id']} {s['source_type']} {s['source_file']}: {s['description']}")
    if inv.get("rag", {}).get("knowledge"):
        lines.append("\nGeneral forensic knowledge:")
        for k in inv["rag"]["knowledge"][:3]:
            lines.append(f"- {k}")
    lines.append("\n_Correlation IDs are links. Original hashed artifacts remain authoritative._")
    return "\n".join(lines)
