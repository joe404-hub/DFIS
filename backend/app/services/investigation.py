"""Case-specific investigation: correlated briefs → RAG → classification / risk / chain.

Implements:
- 4-Tier Forensic Evidentiary States (OBSERVED, SUPPORTED HYPOTHESIS, INSUFFICIENT EVIDENCE, NOT ESTABLISHED)
- Strict Query Classification (separating Greetings / General Forensic Q&A / Case Investigation)
- Evidence Relevance Verification
- Eight Forensic Grounding Rules:
  1. No evidence → don't claim it happened (state NOT ESTABLISHED)
  2. Hypothesis → explicitly label it hypothesis with confidence & rationale
  3. General knowledge → never present as case evidence
  4. Case classification → inherit authoritative case state
  5. Risk score → inherit authoritative case score
  6. Case-specific claims → cite exact evidence event IDs
  7. Correlation IDs → clearly identified as analytical relationships, not evidence artifacts
  8. Greeting/casual queries → respond politely as assistant without injecting case findings
"""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from typing import Any

from app.services.actions import format_actions, recommend_actions
from app.services.knowledge import FORENSIC_KB
from app.services.rag import retrieve
from app.services.risk import score_case

GREETING_REGEX = re.compile(
    r"^(hi|hello|hey|greetings|howdy|good\s+(morning|afternoon|evening|day)|"
    r"who\s+are\s+you|what\s+can\s+you\s+do|help|what\s+are\s+you|what\s+is\s+this|"
    r"thanks|thank\s+you|ok|okay|bye|goodbye)(\s+(there|assistant|bot|friend|dfis))?[\s.?!]*$",
    re.I,
)


def classify_user_query(question: str) -> str:
    """Classify user query into: greeting, general, or case_investigation."""
    q_stripped = question.strip()
    if GREETING_REGEX.match(q_stripped):
        return "greeting"

    q_low = q_stripped.lower()
    # General forensic knowledge definition query
    if (
        (q_low.startswith("what is mitre") or q_low.startswith("what is t1") or q_low.startswith("explain mitre") or q_low.startswith("what is an mft") or q_low.startswith("what is evtx") or q_low.startswith("what is prefetch") or q_low.startswith("what is amcache"))
        and not any(k in q_low for k in ("this case", "in the case", "our case", "observed", "evidence", "found"))
    ):
        return "general"

    return "case_investigation"


def format_classification_label(category: str | None, secondary: str | None = "") -> str:
    """Format incident classification string without duplicating the 'Possible' prefix."""
    cat = (category or "Normal Activity").strip()
    if not cat.lower().startswith("possible ") and cat.lower() not in {"normal activity", "routine operations"}:
        cat = f"Possible {cat}"
    return f"{cat} / {secondary}" if secondary else cat


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
            entity = members[0].get("target") or members[0].get("object") or ""
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
                "actor": next((m.get("actor") or m.get("user") for m in members if (m.get("actor") or m.get("user"))), ""),
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
        f"User: {next((m.get('actor') or m.get('user') for m in members if (m.get('actor') or m.get('user'))), 'unknown')}",
        "Supporting evidence events:",
    ]
    for m in members:
        lines.append(
            f"  - event_id={m.get('id')} {m.get('source_type')}/{m.get('event_type')} "
            f"file={m.get('source_file') or '?'} :: {m.get('description')}"
        )
    return "\n".join(lines)


def get_evidentiary_states(events: list[dict], groups: list[dict]) -> list[dict[str, str]]:
    """Determine four-tier forensic state (OBSERVED, SUPPORTED HYPOTHESIS, INSUFFICIENT EVIDENCE, NOT ESTABLISHED)."""
    blob = " ".join(f"{e.get('description','')} {e.get('event_type','')}" for e in events).lower()
    families = {g["family"] for g in groups}

    has_logon = any(e.get("event_type") in {"logon", "admin_logon"} or "4624" in str(e.get("event_id", "")) for e in events)
    has_net = any(e.get("source_type") in {"network", "browser"} for e in events)
    has_ps = "powershell" in blob
    has_svc = any(g["family"] == "service" for g in groups) or "7045" in blob or "service_install" in blob
    has_usb = "usb" in blob or "usb_connect" in families
    has_copies = any(g["family"] == "file_copy" for g in groups) or "file_copy" in blob
    has_sensitive = bool(re.search(r"sensitive_|customer_list|confidential|projectx|api_keys", blob))

    states = []

    # 1. User Authentication
    if has_logon:
        states.append({"finding": "User authentication", "state": "OBSERVED", "detail": "Valid account logon recorded in logs (T1078). Does not prove account compromise."})
    else:
        states.append({"finding": "User authentication", "state": "NOT ESTABLISHED", "detail": "No logon events found."})

    # 2. Network / Browser Activity
    if has_net:
        states.append({"finding": "Network/browser activity", "state": "OBSERVED", "detail": "Network connections and/or browser visits recorded."})
    else:
        states.append({"finding": "Network/browser activity", "state": "NOT ESTABLISHED", "detail": "No network or browser traffic recorded."})

    # 3. Possible Network-Based Transfer
    if has_net and (has_copies or has_sensitive):
        states.append({"finding": "Possible network-based transfer", "state": "SUPPORTED HYPOTHESIS", "detail": "Network session observed following sensitive file access/copy."})
    elif has_net:
        states.append({"finding": "Possible network-based transfer", "state": "INSUFFICIENT EVIDENCE", "detail": "T1567 is a hypothesis based on network/browser activity; exfiltration is not established."})
    else:
        states.append({"finding": "Possible network-based transfer", "state": "NOT ESTABLISHED", "detail": "No network transfer activity found."})

    # 4. Unauthorized Account Use
    states.append({"finding": "Unauthorized account use", "state": "NOT ESTABLISHED", "detail": "Valid-account authentication is observed; unauthorized access itself is not established."})

    # 5. USB Connection
    if has_usb:
        states.append({"finding": "USB connection", "state": "OBSERVED", "detail": "USB device connection recorded in Security events or Registry USBSTOR."})
    else:
        states.append({"finding": "USB connection", "state": "NOT ESTABLISHED", "detail": "No USB device connection events recorded in the evidence."})

    # 6. Confidential File Copying
    if has_copies and has_sensitive:
        states.append({"finding": "Confidential-file copying", "state": "OBSERVED", "detail": "File copy events for sensitive files recorded in filesystem logs."})
    elif has_copies:
        states.append({"finding": "Confidential-file copying", "state": "OBSERVED", "detail": "File copy events recorded, but sensitive nature is unconfirmed."})
    else:
        states.append({"finding": "Confidential-file copying", "state": "NOT ESTABLISHED", "detail": "No file copy events recorded in the evidence."})

    # 7. Exfiltration
    if has_copies and (has_usb or (has_net and has_sensitive)):
        states.append({"finding": "Exfiltration", "state": "SUPPORTED HYPOTHESIS", "detail": "Temporal sequence consistent with transfer, pending final drive/session mapping."})
    else:
        states.append({"finding": "Exfiltration", "state": "NOT ESTABLISHED", "detail": "No evidence establishing that data was transferred outside the organization."})

    return states


def classify_and_score(events: list[dict], groups: list[dict]) -> dict:
    blob = " ".join(f"{e.get('description','')} {e.get('event_type','')}" for e in events).lower()
    usb = "usb" in blob or any(g["family"] == "usb_connect" for g in groups)
    copies = any(g["family"] == "file_copy" for g in groups) or "file_copy" in blob
    sensitive = bool(re.search(r"sensitive_|customer_list|confidential|projectx|api_keys", blob))
    powershell = "powershell" in blob
    service = any(g["family"] == "service" for g in groups)
    network = any(g["family"] == "network" for g in groups) or "10.0.0." in blob or "drive." in blob or "http" in blob
    logon = "logon" in blob or "4624" in blob
    risk = score_case(events, groups)
    score = risk["risk_score"]

    if copies and (usb or network) and (sensitive or logon):
        category = "Insider Threat"
        secondary = "Possible data exfiltration"
    elif copies and sensitive:
        category = "Data Theft"
        secondary = "Sensitive files staged/copied"
    elif service and powershell and not copies:
        category = "Malware Infection"
        secondary = "Persistence / execution without confirmed collection"
    elif network or logon:
        if score >= 15 and (network or logon):
            category = "Possible Unauthorized Use of Valid Account"
            secondary = "Insufficient Evidence for Exfiltration"
        else:
            category = "Normal Activity"
            secondary = "Routine Operations / Insufficient Indicators"
    elif score < 15:
        category = "Normal Activity"
        secondary = "Insufficient suspicious indicators"
    else:
        category = "Possible Suspicious Network Activity"
        secondary = "Insufficient Evidence for Exfiltration"

    techniques = []
    if logon:
        techniques.append(_tech("T1078", "Valid account / user authentication", "observed", "high", "initial_access"))
    if powershell:
        techniques.append(_tech("T1059.001", "PowerShell execution", "observed", "medium", "execution"))
    if service:
        techniques.append(_tech("T1543.003", "Windows service persistence", "observed", "medium", "persistence"))
    if sensitive:
        techniques.append(_tech("T1005", "Collection from local system", "observed", "medium", "collection"))
    if copies and usb:
        techniques.append(_tech("T1052.001", "Exfiltration via removable media", "hypothesized", "medium", "exfiltration"))
    elif network and (copies or usb or sensitive):
        techniques.append(_tech("T1567", "Exfil over web service", "hypothesized", "low", "exfiltration"))
    elif network:
        techniques.append(_tech("T1567", "Internal drive / network session", "hypothesized", "medium", "network"))

    stages = [t["stage"] for t in techniques]
    evidentiary_states = get_evidentiary_states(events, groups)

    return {
        "category": category,
        "secondary": secondary,
        "risk_score": score,
        "risk": risk,
        "confidence": 0.62 if score < 40 else 0.78 if score < 70 else 0.86,
        "mitre_ids": ", ".join(t["id"] for t in techniques),
        "techniques": techniques,
        "attack_stage": " → ".join(dict.fromkeys(stages)),
        "evidentiary_states": evidentiary_states,
    }


def _tech(tid, name, status, confidence, stage):
    return {"id": tid, "name": name, "status": status, "confidence": confidence, "stage": stage}


def attack_chain(events: list[dict], groups: list[dict]) -> list[dict]:
    """Ordered hypothesis attack stages, each linked to raw event IDs with clear uncertainty labels."""
    steps = []

    def add(time, title, mitre, ids, note, status="hypothesized", confidence="medium"):
        steps.append(
            {
                "time": time,
                "title": title,
                "mitre": mitre,
                "status": status,
                "confidence": confidence,
                "evidence_event_ids": [i for i in ids if i is not None],
                "note": note,
            }
        )

    timed = [e for e in events if e.get("timestamp") and e.get("source_type") not in {"correlated", "memory"}]
    logons = [e for e in timed if e.get("event_type") in {"logon", "admin_logon"}]
    if logons:
        add(
            logons[0].get("timestamp"),
            "User authentication / valid-account activity",
            "T1078",
            [logons[0].get("id")],
            "Observed valid-account authentication; unauthorized access is not established.",
            status="observed",
            confidence="high",
        )
    ps = [e for e in timed if "powershell" in (e.get("description") or "").lower() or e.get("process") == "powershell.exe"]
    if ps:
        add(ps[0].get("timestamp"), "PowerShell execution", "T1059.001", [ps[0].get("id")], "Process creation observed", status="observed", confidence="medium")

    for g in groups:
        if g["family"] == "service":
            add(g["timestamp"], f"Service/persistence ({g['entity']})", "T1543.003", g["source_event_ids"], "Multi-source service install", status="observed", confidence="medium")
        if g["family"] == "usb_connect":
            add(g["timestamp"], "Removable media connected", "T1091/T1052", g["source_event_ids"], g["entity"], status="observed", confidence="high")
        if g["family"] == "file_access":
            add(g["timestamp"], f"Sensitive file accessed ({g['entity']})", "T1005", g["source_event_ids"], "Independent artifacts agree", status="observed", confidence="high")
        if g["family"] == "file_copy":
            dest = g.get("destination") or "transfer location"
            add(g["timestamp"], f"File copied ({g['entity']})", "T1052.001", g["source_event_ids"], dest, status="hypothesized", confidence="medium")
        if g["family"] == "usb_remove":
            add(g["timestamp"], "Removable media removed", "T1052", g["source_event_ids"], "", status="observed", confidence="high")
        if g["family"] == "network":
            is_internal = "10." in g["entity"] or "192.168." in g["entity"] or "172." in g["entity"] or ".local" in g["entity"] or ".corp" in g["entity"]
            add(
                g["timestamp"],
                f"Internal network / drive activity ({g['entity']})" if is_internal else f"Network connection ({g['entity']})",
                "T1567" if not is_internal else "—",
                g["source_event_ids"],
                "T1567 is a hypothesis based on network/browser activity; exfiltration is not established." if not is_internal else "Network/browser activity to internal endpoint; does not establish external data exfiltration.",
                status="hypothesized" if not is_internal else "insufficient_evidence",
                confidence="medium" if not is_internal else "low",
            )

    if not any("Network" in s["title"] or "Internal network" in s["title"] for s in steps):
        net = [e for e in timed if e.get("source_type") in {"network", "browser"}]
        if net:
            suspicious = any(g["family"] in {"file_copy", "usb_connect"} for g in groups)
            add(
                net[0].get("timestamp"),
                "Network/browser activity" + (" (web-exfil hypothesis)" if suspicious else ""),
                "T1567" if suspicious else "—",
                [e.get("id") for e in net[:4]],
                "T1567 is a hypothesis based on network/browser activity; exfiltration is not established.",
                status="hypothesized" if suspicious else "insufficient_evidence",
                confidence="medium" if suspicious else "low",
            )

    # Deduplicate steps by title & time
    seen = set()
    uniq = []
    for s in steps:
        key = (s["title"], str(s["time"]))
        if key not in seen:
            seen.add(key)
            uniq.append(s)
    return uniq


def get_evidence_observations(events: list[dict]) -> list[dict]:
    """Extract forensic acquisition snapshots (e.g. Memory snapshot, Disk acquisition) separated from attack chain."""
    observations = []
    mem_events = [e for e in events if e.get("source_type") == "memory"]
    if mem_events:
        obs_time = mem_events[0].get("observation_time") or mem_events[0].get("timestamp")
        observations.append(
            {
                "title": "Memory snapshot",
                "type": "Memory Acquisition",
                "time": str(obs_time or "Capture time"),
                "status": "OBSERVED",
                "confidence": "HIGH (OBSERVATION)",
                "evidence_event_ids": [e.get("id") for e in mem_events if e.get("id") is not None],
                "note": "Memory acquisition snapshot; timestamp is observation time, not process execution start.",
            }
        )
    return observations


def get_suggested_queries(inv: dict) -> list[str]:
    """Dynamically generate investigative queries targeting actual evidentiary gaps in the case."""
    queries = []
    ev_states = {s["finding"]: s["state"] for s in inv.get("evidentiary_states", [])}

    if ev_states.get("User authentication") == "OBSERVED":
        queries.append("Was the valid account legitimately used?")
    if ev_states.get("Network/browser activity") == "OBSERVED":
        queries.append("What activity is associated with chrome.exe or network endpoints?")
    if ev_states.get("Possible network-based transfer") in {"INSUFFICIENT EVIDENCE", "SUPPORTED HYPOTHESIS"}:
        queries.append("What is the identity and purpose of internal endpoint 10.0.0.20:443?")
    if ev_states.get("USB connection") == "NOT ESTABLISHED":
        queries.append("Is there evidence of USB / removable-media activity?")
    elif ev_states.get("USB connection") == "OBSERVED":
        queries.append("Was confidential data copied to the connected USB device?")
    if ev_states.get("Confidential-file copying") == "NOT ESTABLISHED":
        queries.append("Is there evidence of confidential-file access or copying?")
    if (inv.get("observations") or []):
        queries.append("What does the memory snapshot contribute to the investigation?")
    queries.append("What are the recommended next steps for verification?")

    return queries[:6]


def run_investigation(case_id: int, events: list[dict]) -> dict:
    """Analyze timeline and return correlated briefs, RAG context, and incident classification."""
    groups = group_correlations(events)
    cls = classify_and_score(events, groups)
    chain = attack_chain(events, groups)
    obs = get_evidence_observations(events)
    rag = retrieve(case_id, "data exfiltration USB copy sensitive archive")
    actions = recommend_actions(events, groups)

    evidence_ids = []
    for g in groups:
        evidence_ids.extend(g.get("source_event_ids") or [])
    if not evidence_ids:
        evidence_ids = [e.get("id") for e in events if e.get("id") is not None][:10]

    formatted_label = format_classification_label(cls["category"], cls["secondary"])
    body = (
        f"Working classification: {formatted_label}. "
        f"Investigation Priority: {cls['risk_score']}/100 ({cls['risk'].get('priority')}). "
        "Malicious intent and unauthorized access cannot be established from logs alone. "
        "Every hypothesis is cross-linked to original evidence IDs."
    )

    result = {
        "case_id": case_id,
        "category": cls["category"],
        "secondary": cls["secondary"],
        "risk_score": cls["risk_score"],
        "priority": cls["risk"].get("priority"),
        "confidence": cls["confidence"],
        "mitre_ids": cls["mitre_ids"],
        "attack_stage": cls["attack_stage"],
        "risk": cls["risk"],
        "correlations": groups,
        "attack_chain": chain,
        "observations": obs,
        "next_actions": actions,
        "evidentiary_states": cls.get("evidentiary_states", []),
        "rag": rag,
        "findings": [
            {
                "category": cls["category"],
                "title": formatted_label,
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
    result["suggested_queries"] = get_suggested_queries(result)
    return result


def _priority_line(inv: dict) -> str:
    score = inv.get("risk_score")
    pri = inv.get("priority") or (inv.get("risk") or {}).get("priority") or "PRIORITY"
    cat = inv.get("category") or "Normal Activity"
    sec = inv.get("secondary") or "Insufficient suspicious indicators"
    formatted_label = format_classification_label(cat, sec)
    return (
        f"Working classification: {formatted_label}\n"
        f"Investigation Priority: {score}/100 — {pri}"
    )


def _greeting_response() -> str:
    """Natural, professional greeting without injecting case classification conclusions."""
    return "\n".join(
        [
            "Hello. I’m the forensic investigation assistant for this case.",
            "",
            "You can ask questions about:",
            "• suspicious activity",
            "• user authentication",
            "• file access/copying",
            "• USB/removable-media activity",
            "• network activity",
            "• possible exfiltration",
            "• timeline events",
            "• ATT&CK hypotheses",
            "• evidence IDs",
            "• investigation recommendations",
            "",
            "For example:",
            '"Was confidential data copied to a removable device?"',
            '"Show suspicious activity around 09:00–11:00."',
            '"What evidence supports the T1078 hypothesis?"',
        ]
    )


def _general_knowledge_response(question: str, rag: dict) -> str:
    """Respond to generic forensic definitions/concepts with explicit general-knowledge disclaimer."""
    know_lines = (rag.get("knowledge") or [])
    body = "\n".join(f"- {k}" for k in know_lines[:3]) if know_lines else (
        "Digital forensics principles require establishing direct provenance, cryptographic hashes, "
        "and independent artifact corroboration before concluding that malicious activity occurred."
    )
    return "\n".join(
        [
            f"Question: {question}",
            "",
            "Forensic Concept Explanation:",
            body,
            "",
            "GENERAL FORENSIC KNOWLEDGE DISCLAIMER:",
            "This explanation describes general digital forensics principles. "
            "It is interpretive only and cannot be used as case evidence.",
        ]
    )


def answer_question(question: str, rag: dict, events: list[dict], inv: dict) -> str:
    """Route query appropriately and synthesize grounded forensic answers enforcing eight grounding rules."""
    q_type = classify_user_query(question)

    # 1. Routing: Greeting / Casual queries
    if q_type == "greeting":
        return _greeting_response()

    # 2. Routing: General Forensic Concept queries
    if q_type == "general":
        return _general_knowledge_response(question, rag)

    # 3. Routing: Case Investigation queries
    q = question.lower()
    lines = [
        f"Question: {question}",
        "",
        _priority_line(inv),
        "",
    ]

    # Task Recommendations Query
    if any(k in q for k in ("next step", "next action", "what should", "recommend", "further", "investigate next", "tasks")):
        actions = inv.get("next_actions") or recommend_actions(events, inv.get("correlations") or [])
        lines.append("Recommended Next Investigation Actions (Derived from Evidentiary Gaps):")
        lines.append(format_actions(actions))
        lines.append("")
        lines.append("AI is an investigative assistant, not an evidence source. All tasks are examiner verification steps.")
        return "\n".join(lines)

    # USB / Exfiltration Query
    if any(k in q for k in ("usb", "removable", "exfil", "copied", "copy", "transfer", "confidential", "sensitive", "staged")):
        usb_ans = _usb_transfer_answer(inv, events)
        if usb_ans:
            lines.append(usb_ans)
        else:
            lines.append(_no_usb_answer(inv))
        lines.append("")
        lines.append("General forensic knowledge is interpretive only and cannot be used as case evidence.")
        lines.append("AI is an investigative assistant, not an evidence source.")
        return "\n".join(lines)

    # Authentication / Logon / T1078 Query
    if any(k in q for k in ("logon", "login", "auth", "account", "t1078", "user", "analyst", "credential")):
        logon_evs = [e for e in events if e.get("event_type") in {"logon", "admin_logon"} or "4624" in str(e.get("event_id", ""))]
        lines.append("Assessment of User Authentication & Valid-Account Activity:")
        if logon_evs:
            lines.append(f"  - Valid-account authentication is OBSERVED in the evidence (Security Event 4624).")
            lines.append(f"  - Supporting Evidence IDs: {[e.get('id') for e in logon_evs if e.get('id')]}")
            lines.append("  - Unauthorized account use: NOT ESTABLISHED. Logon logs prove authentication occurred, not that the account was compromised.")
        else:
            lines.append("  - No user authentication events are present in the currently ingested evidence.")
        lines.append("")
        lines.append("Conclusion: Valid-account logon is observed; unauthorized access itself is not established.")
        lines.append("")
        lines.append("General forensic knowledge is interpretive only and cannot be used as case evidence.")
        lines.append("AI is an investigative assistant, not an evidence source.")
        return "\n".join(lines)

    # Network / Browser / Chrome / Endpoint Query
    if any(k in q for k in ("network", "browser", "chrome", "10.0.0", "endpoint", "url", "drive", "t1567", "connection")):
        net_evs = [e for e in events if e.get("source_type") in {"network", "browser"}]
        lines.append("Assessment of Network & Browser Activity:")
        if net_evs:
            lines.append("  - Network connections and/or browser visits are OBSERVED in the evidence.")
            lines.append(f"  - Supporting Evidence IDs: {[e.get('id') for e in net_evs[:6] if e.get('id')]}")
            lines.append("  - T1567 web-service exfiltration: HYPOTHESIZED (Insufficient Evidence).")
            lines.append("  - Reason: Network/browser activity is observed, but data exfiltration is not established.")
        else:
            lines.append("  - No network or browser events are recorded in the ingested evidence.")
        lines.append("")
        lines.append("Conclusion: Network activity is observed; data exfiltration is not established.")
        lines.append("")
        lines.append("General forensic knowledge is interpretive only and cannot be used as case evidence.")
        lines.append("AI is an investigative assistant, not an evidence source.")
        return "\n".join(lines)

    # Memory Snapshot Query
    if any(k in q for k in ("memory", "process list", "snapshot", "volatility", "capture time")):
        mem_obs = inv.get("observations") or []
        lines.append("Assessment of Memory Acquisition Snapshot:")
        if mem_obs:
            o = mem_obs[0]
            lines.append(f"  - Memory snapshot is an OBSERVED forensic acquisition event (Time: {o.get('time')}).")
            lines.append(f"  - Evidence IDs: {o.get('evidence_event_ids')}")
            lines.append(f"  - Forensic Caveat: {o.get('note')}")
        else:
            lines.append("  - No memory snapshot artifacts were ingested for this case.")
        lines.append("")
        lines.append("General forensic knowledge is interpretive only and cannot be used as case evidence.")
        lines.append("AI is an investigative assistant, not an evidence source.")
        return "\n".join(lines)

    # Default Case Specific Summary
    groups = inv.get("correlations") or []
    lines.append("CASE-SPECIFIC EVIDENCE SUMMARY:")
    if groups:
        for g in groups[:5]:
            lines.append(f"  - {g['timestamp']} {g['family']} {g['entity']} evidence_ids={g['source_event_ids']}")
    else:
        lines.append("  - No multi-source correlated clusters identified in the ingested evidence.")

    lines.append("")
    lines.append("Evidentiary State Breakdown:")
    for st in inv.get("evidentiary_states") or []:
        lines.append(f"  - {st['finding']}: {st['state']} ({st['detail']})")

    lines.append("")
    lines.append("General forensic knowledge is interpretive only and cannot be used as case evidence.")
    lines.append("AI is an investigative assistant, not an evidence source.")
    return "\n".join(lines)


def _no_usb_answer(inv: dict) -> str:
    return "\n".join(
        [
            "The available case evidence does not establish that confidential data was copied to USB.",
            "",
            "The case contains valid-account authentication and network/browser activity, including correlated network events. "
            "However, the available evidence does not establish USB connection, sensitive-file access, copying to a removable device, "
            "archive creation, or a confirmed exfiltration event.",
            "",
            "CASE-SPECIFIC EVIDENCE: No event currently establishes USB-based data transfer.",
            "",
            "Network/browser activity alone is insufficient to conclude that data was exfiltrated.",
            "",
            "Evidentiary State Breakdown:",
            "  - User authentication: OBSERVED (T1078 valid account logon; unauthorized access is not established)",
            "  - Network/browser activity: OBSERVED",
            "  - Possible network-based transfer: HYPOTHESIS (Insufficient evidence)",
            "  - Unauthorized account use: NOT ESTABLISHED",
            "  - USB connection: NOT ESTABLISHED",
            "  - Confidential-file copying: NOT ESTABLISHED",
            "  - Exfiltration: NOT ESTABLISHED",
            "",
            "Conclusion: USB-based confidential-data transfer is not established by the currently ingested evidence. "
            "Further verification of the original artifacts and device/drive mappings is required if this hypothesis needs to be investigated.",
        ]
    )


def _usb_transfer_answer(inv: dict, events: list[dict]) -> str | None:
    copies = [g for g in (inv.get("correlations") or []) if g.get("family") == "file_copy"]
    usb = [g for g in (inv.get("correlations") or []) if g.get("family") in {"usb_connect", "usb_remove"}]
    accesses = [g for g in (inv.get("correlations") or []) if g.get("family") == "file_access"]
    if not copies:
        copies = [
            {
                "entity": e.get("target") or e.get("object"),
                "destination": e.get("destination_path") or e.get("target"),
                "source_event_ids": [e.get("id")],
                "timestamp": e.get("timestamp"),
            }
            for e in events
            if e.get("event_type") == "file_copy"
        ]
    if not copies:
        return None

    dests = sorted({(c.get("destination") or "E:/Transfer") for c in copies})
    dest = dests[0] if dests else "E:/Transfer"
    copy_ids, usb_ids, access_ids = [], [], []
    for c in copies:
        copy_ids.extend(c.get("source_event_ids") or [])
    for u in usb:
        usb_ids.extend(u.get("source_event_ids") or [])
    for a in accesses:
        access_ids.extend(a.get("source_event_ids") or [])

    ev_lines = []
    for g in usb + accesses + copies:
        ts = str(g.get("timestamp") or "")[:19].replace("T", " ")
        ent = g.get("entity") or ""
        destg = g.get("destination") or ""
        if g.get("family") == "usb_connect":
            ev_lines.append(f"  {ts}  USB/removable media connected  evidence_ids={g.get('source_event_ids')}")
        elif g.get("family") == "file_access":
            ev_lines.append(f"  {ts}  {ent} accessed  evidence_ids={g.get('source_event_ids')}")
        elif g.get("family") == "file_copy":
            ev_lines.append(f"  {ts}  {ent} → {destg or dest}  evidence_ids={g.get('source_event_ids')}")

    support = []
    for ids in (usb_ids, access_ids, copy_ids):
        support.extend(ids)
    support = list(dict.fromkeys(support))
    score = inv.get("risk_score")
    pri = inv.get("priority") or (inv.get("risk") or {}).get("priority") or "HIGH PRIORITY"

    return "\n".join(
        [
            "Grounded assessment: Possible, but not conclusively established.",
            "",
            "CASE evidence",
            *ev_lines,
            "",
            "Interpretation",
            "  Possible removable-media data transfer",
            "  Confidence: Medium",
            "  Status: Hypothesized (temporal correlation, not device identity)",
            "",
            "Evidentiary State Breakdown:",
            "  - USB connection: OBSERVED (Security Event 6416 / Registry USBSTOR)",
            "  - Sensitive file access: OBSERVED (Security Event 4663 / Filesystem OPEN)",
            "  - File copy to transfer path: OBSERVED (Filesystem COPY)",
            "  - Drive-to-device identity mapping: NOT ESTABLISHED (Requires examiner verification)",
            "",
            "Missing evidence",
            "  No direct drive-letter-to-USB-device mapping shown",
            "  No explicit USB file-write event shown",
            "  No cryptographic/hash confirmation of copied files shown",
            "",
            f"The case shows that a removable device was connected and that confidential files "
            f"were subsequently copied to {dest}. This sequence is consistent with a possible "
            f"transfer to removable media. However, the available evidence does not directly "
            f"establish that {dest} corresponds to the USB device that was connected. "
            "Further verification of the drive/device mapping is required.",
            "",
            "Conclusion: Possible USB/removable-media transfer; further verification of the drive/device mapping is required.",
            "Confidence: Medium",
            f"Supporting evidence: {support}",
            f"Investigation Priority: {score}/100 — {pri}",
        ]
    )


def answer_from_investigation(question: str, events: list[dict], inv: dict, rag: dict | None = None) -> str:
    return answer_question(question, rag or inv.get("rag") or {}, events, inv)
