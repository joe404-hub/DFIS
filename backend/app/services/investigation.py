"""Case-specific investigation: correlated briefs → RAG → classification / risk / chain.

Implements:
- 4-Tier Forensic Evidentiary States (OBSERVED, SUPPORTED HYPOTHESIS, INSUFFICIENT EVIDENCE, NOT ESTABLISHED)
- Strict Query Intent Classification:
  1. GREETING (casual greetings, assistant guidance)
  2. GENERAL (forensic/technical concept definitions with optional case context)
  3. HYBRID (evaluating a technical concept applied directly to the case)
  4. CASE_INVESTIGATION (evidence-grounded case queries)
- Evidence Relevance Verification
- Eight Forensic Grounding Rules:
  1. No evidence → don't claim it happened (state NOT ESTABLISHED)
  2. Hypothesis → explicitly label it hypothesis with confidence & rationale
  3. General knowledge → never present as case evidence (disclaimer)
  4. Case classification → inherit authoritative case state
  5. Risk score → inherit authoritative case score
  6. Case-specific claims → cite exact evidence event IDs
  7. Correlation IDs → clearly identified as analytical relationships, not evidence artifacts
  8. Greeting/general queries → don't dump the incident classification template
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

INTENT_GREETING = "GREETING"
INTENT_GENERAL = "GENERAL"
INTENT_FORENSIC_KNOWLEDGE = "FORENSIC_KNOWLEDGE"
INTENT_CASE_TIMELINE = "CASE_TIMELINE"
INTENT_CASE_SUMMARY = "CASE_SUMMARY"
INTENT_CASE_GUIDANCE = "CASE_GUIDANCE"
INTENT_CASE_QUERY = "CASE_QUERY"

# Backward compatibility aliases
INTENT_TECHNICAL_FORENSIC = "FORENSIC_KNOWLEDGE"
INTENT_CASE_ANALYSIS = "CASE_QUERY"

TIMELINE_KEYWORDS = [
    "timeline", "timelime", "timline", "time line", "timelines", "chronology", "chronological",
    "sequence of events", "events occurred", "events occured", "events that occurred", "events that occured",
    "what happened first", "order of events", "event sequence", "time sequence",
    "show timeline", "generate timeline", "generate the timeline", "build timeline", "create timeline",
    "events that took place", "what took place"
]

SUMMARY_KEYWORDS = [
    "summarize the case", "case summary", "summarize case", "summarise the case", "summarise case",
    "overview of case", "briefing on the case", "case overview", "executive summary",
    "overview of the investigation", "briefing of the case"
]

FORENSIC_TECHNICAL_CONCEPTS = [
    "pcap", "pcapng", "evtx", "event id", "event 4624", "event 4688", "event 7045",
    "event 6416", "event 4104", "event 4634", "event 4663", "4624", "6416",
    "t1078", "t1567", "t1052", "t1059", "t1543", "t1005", "mitre", "att&ck",
    "usbstor", "userassist", "recentdocs", "run key", "mft", "$mft",
    "prefetch", "amcache", "shimcache", "volatility", "memory snapshot",
    "memory acquisition", "disk acquisition", "chain of custody",
    "digital forensic", "forensic analysis", "forensic", "forensics", "usn journal"
]

CASE_GUIDANCE_KEYWORDS = [
    "next step", "next action", "what should we", "what should the examiner",
    "recommend next", "recommended next", "investigate next", "investigation tasks",
    "examiner verification steps", "how should we investigate this case",
    "recommended actions", "verification steps", "what to do next"
]

CASE_QUERY_KEYWORDS = [
    "this case", "the case", "our case", "in the case", "in this case",
    "this incident", "the incident", "in this workstation", "workstation-14",
    "was confidential", "was any confidential", "was data copied", "was usb connected", "was file copied",
    "did the user", "did analyst", "did j.patel", "who accessed", "who logged in", "who performed",
    "at 09:", "at 10:", "at 11:", "around 09:", "between 09:", "09:00", "09:05", "09:14",
    "in our evidence", "in the evidence", "in current evidence", "ingested evidence",
    "evidence #", "artifact #", "event #",
    "api_keys.env", "projectx", "sourcecode.zip", "sensitive_projectx",
    "was there exfiltration", "was anything exfiltrated", "exfiltrated in this case",
    "indicate exfiltration in this case", "what was chrome.exe accessing in this case"
]

METHODOLOGY_KEYWORDS = [
    "how could we find", "how to find", "how can we find", "how do we find",
    "how can we identify", "how to identify", "how do investigators find",
    "how to detect", "how can we detect", "how do we detect",
    "how to investigate", "how can we investigate", "how do we investigate",
    "how is suspicious activity", "how to spot", "how do you find"
]


def classify_query_intent(question: str) -> str:
    """Classify user query into distinct intents: GREETING, GENERAL, FORENSIC_KNOWLEDGE, CASE_TIMELINE, CASE_SUMMARY, CASE_GUIDANCE, CASE_QUERY."""
    q_stripped = question.strip()
    if GREETING_REGEX.match(q_stripped):
        return INTENT_GREETING

    q_low = q_stripped.lower()

    # 1. Timeline requests (e.g. "generate the timeline of events occured", "generate the timelime of events occured")
    if bool(re.search(r"\btime\s*l[inm]{1,2}e\b", q_low)) or any(k in q_low for k in TIMELINE_KEYWORDS):
        return INTENT_CASE_TIMELINE

    # 2. Case Summary requests (e.g. "summarize the case")
    if bool(re.search(r"\bsummar(y|ize|ise)\b", q_low)) or any(k in q_low for k in SUMMARY_KEYWORDS):
        return INTENT_CASE_SUMMARY

    # 3. Case Guidance Check (e.g. "what are the recommended next steps?")
    if any(k in q_low for k in CASE_GUIDANCE_KEYWORDS):
        return INTENT_CASE_GUIDANCE

    # 4. Specific Case Queries
    if any(k in q_low for k in CASE_QUERY_KEYWORDS):
        return INTENT_CASE_QUERY

    if any(k in q_low for k in ["was confidential data", "was any confidential", "was data copied to usb", "was usb copied", "who accessed"]):
        return INTENT_CASE_QUERY

    # 5. Forensic Methodology & Knowledge Check (e.g. "how could we find suspicious activity?")
    if any(k in q_low for k in METHODOLOGY_KEYWORDS):
        return INTENT_FORENSIC_KNOWLEDGE

    if any(re.search(r"\b" + re.escape(c) + r"\b", q_low) for c in FORENSIC_TECHNICAL_CONCEPTS):
        return INTENT_FORENSIC_KNOWLEDGE

    # 6. Pure General Educational / Technical Questions (e.g. "What is HTTP?", "Explain cryptography", "What is AI?")
    return INTENT_GENERAL
    if any(k in q_low for k in CASE_GUIDANCE_KEYWORDS):
        return INTENT_CASE_GUIDANCE

    # 4. Specific Case Queries
    if any(k in q_low for k in CASE_QUERY_KEYWORDS):
        return INTENT_CASE_QUERY

    if any(k in q_low for k in ["was confidential data", "was any confidential", "was data copied to usb", "was usb copied", "who accessed"]):
        return INTENT_CASE_QUERY

    # 5. Forensic Methodology & Knowledge Check (e.g. "how could we find suspicious activity?")
    if any(k in q_low for k in METHODOLOGY_KEYWORDS):
        return INTENT_FORENSIC_KNOWLEDGE

    if any(re.search(r"\b" + re.escape(c) + r"\b", q_low) for c in FORENSIC_TECHNICAL_CONCEPTS):
        return INTENT_FORENSIC_KNOWLEDGE

    # 6. Pure General Educational / Technical Questions (e.g. "What is HTTP?", "Explain cryptography", "What is AI?")
    return INTENT_GENERAL


def classify_user_query(question: str) -> str:
    """Backward-compatible wrapper mapping to lowercase query types."""
    intent = classify_query_intent(question)
    if intent == INTENT_GREETING:
        return "greeting"
    if intent == INTENT_GENERAL:
        return "general"
    if intent in {INTENT_FORENSIC_KNOWLEDGE, INTENT_TECHNICAL_FORENSIC}:
        return "technical_forensic"
    if intent == INTENT_CASE_TIMELINE:
        return "case_timeline"
    if intent == INTENT_CASE_SUMMARY:
        return "case_summary"
    if intent == INTENT_CASE_GUIDANCE:
        return "case_guidance"
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
        queries.append("Was the valid account legitimately used at 09:00?")
    if ev_states.get("Network/browser activity") == "OBSERVED":
        queries.append("What activity is associated with chrome.exe at 09:05?")
        queries.append("What is 10.0.0.20:443?")
    if ev_states.get("USB connection") == "NOT ESTABLISHED":
        queries.append("Is there evidence of USB/removable-media activity?")
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


def get_concept_definition(query: str) -> tuple[str, str]:
    """Return authoritative forensic concept definition for technical terms."""
    q_low = query.lower()

    if "https" in q_low or "http" in q_low or "tls" in q_low or "ssl" in q_low or "443" in q_low:
        return (
            "What does HTTPS mean?",
            "HTTPS stands for Hypertext Transfer Protocol Secure.\n\n"
            "It is the secure version of HTTP. HTTPS uses TLS (Transport Layer Security) encryption "
            "to protect data exchanged between a browser and a web server and helps provide confidentiality "
            "and integrity of the communication over TCP port 443."
        )
    if "t1078" in q_low or "4624" in q_low or "valid account" in q_low:
        return (
            "What is Windows Security Event 4624 / MITRE ATT&CK T1078 (Valid Accounts)?",
            "Windows Security Event 4624 records a successful logon event on the system. It captures logon type (e.g., Type 2 Interactive, Type 3 Network, Type 10 RemoteInteractive), target account name, domain, and logon process.\n\n"
            "MITRE ATT&CK T1078 (Valid Accounts) refers to the use of legitimate credentials to access systems. "
            "In forensic logs, Event 4624 proves authentication occurred, but does not by itself establish that the account was compromised or used without authorization."
        )
    if "4688" in q_low or "process creation" in q_low:
        return (
            "What is Windows Security Event 4688 (Process Creation)?",
            "Windows Security Event 4688 records new process creation events on Windows endpoints. When command-line process auditing is enabled, it captures the full executable path, parent process ID, creator process name, and command-line execution arguments."
        )
    if "7045" in q_low or "service install" in q_low:
        return (
            "What is Windows System Event 7045 (New Service Installation)?",
            "Windows System Event 7045 records when a new service is installed in the Windows Service Control Manager. It logs the service name, image path (executable path), and service type, making it a critical artifact for detecting persistence mechanisms (MITRE ATT&CK T1543.003)."
        )
    if "6416" in q_low:
        return (
            "What is Windows Security Event 6416 (New External Device Recognized)?",
            "Windows Security Event 6416 is generated when a new plug-and-play external device (such as a USB mass storage flash drive) is connected and recognized by the Windows operating system. It records the device ID, vendor ID (VID), product ID (PID), and class GUID."
        )
    if "4104" in q_low or "powershell script" in q_low:
        return (
            "What is Windows Event 4104 (PowerShell Script Block Logging)?",
            "Windows Event 4104 captures full PowerShell script block execution content as it is decoded and executed by the PowerShell engine, enabling forensic reconstruction of obfuscated or encoded commands."
        )
    if "t1567" in q_low or "exfil over web" in q_low:
        return (
            "What is MITRE ATT&CK T1567 (Exfiltration Over Web Service)?",
            "MITRE ATT&CK T1567 refers to transferring sensitive data to external cloud storage or web services. "
            "Forensically, web/browser activity alone represents an unconfirmed hypothesis; establishing exfiltration "
            "requires corroborating evidence of sensitive file staging, file copying, and transmission."
        )
    if "t1052" in q_low or "usbstor" in q_low or "usb" in q_low:
        return (
            "What is MITRE ATT&CK T1052 (Exfiltration Over Physical Medium)?",
            "MITRE ATT&CK T1052 involves copying data to removable USB storage. In Windows forensics, USB connections "
            "are tracked in the SYSTEM registry hive under CurrentControlSet\\Enum\\USBSTOR and Security Event 6416/20001."
        )
    if "prefetch" in q_low or ".pf" in q_low:
        return (
            "What is Windows Prefetch?",
            "Windows Prefetch (.pf) files are execution artifacts created to optimize application loading. "
            "Forensically, Prefetch proves that a specific binary executed on the system, recording executable name, "
            "run count, execution timestamps, and referenced files."
        )
    if "amcache" in q_low:
        return (
            "What is Windows Amcache?",
            "Amcache.hve is a Windows registry hive located in %SystemRoot%\\appcompat\\Programs\\Amcache.hve. "
            "It tracks application execution and installation details, including executable full paths, "
            "SHA-1 application hashes, file sizes, and compile times."
        )
    if "sha-256" in q_low or "sha256" in q_low or "hash" in q_low:
        return (
            "What is SHA-256 Hash Verification?",
            "SHA-256 is a cryptographic hash algorithm producing a unique 64-character hexadecimal digest for any file. "
            "In digital forensics, SHA-256 verifies evidence integrity and proves that files have not been modified, "
            "altered, or corrupted since acquisition."
        )
    if "mft" in q_low:
        return (
            "What is the Master File Table ($MFT)?",
            "The Master File Table ($MFT) is the central filesystem database in NTFS that records all file metadata, "
            "standard information timestamps (created, modified, MFT altered, accessed), file sizes, and cluster allocations."
        )

    return (
        f"Explanation for {query.strip()}:",
        "Digital forensics principles require establishing direct provenance, cryptographic hashes, "
        "and independent artifact corroboration before concluding that malicious activity occurred."
    )


def get_general_concept_response(query: str) -> str:
    """Generate clear, educational explanation for general technical questions without forensic templates."""
    q_low = query.lower()

    if "https" in q_low:
        return (
            "HTTPS stands for Hypertext Transfer Protocol Secure.\n\n"
            "It is the secure version of HTTP. HTTPS uses TLS (Transport Layer Security) encryption "
            "to protect data exchanged between a browser and a web server and helps provide confidentiality "
            "and integrity of the communication over TCP port 443."
        )

    if "cryptography" in q_low or "crypto" in q_low or "encryption" in q_low:
        return (
            "Cryptography is the scientific practice of securing information and communications through mathematical techniques and algorithms.\n\n"
            "### Core Security Goals\n"
            "- **Confidentiality**: Ensuring that information is accessible only to authorized entities.\n"
            "- **Integrity**: Verifying that data has not been altered or tampered with in transit or storage.\n"
            "- **Authentication**: Confirming the identity of users, processes, or devices.\n"
            "- **Non-Repudiation**: Preventing a sender from denying the authenticity of a sent message.\n\n"
            "### Primary Branches\n"
            "1. **Symmetric Encryption**: Uses a single shared secret key for both encryption and decryption (e.g. AES-256, ChaCha20).\n"
            "2. **Asymmetric Encryption**: Uses a mathematically linked key pair (public key for encryption, private key for decryption; e.g. RSA, ECC).\n"
            "3. **Cryptographic Hashing**: One-way mathematical transformation that generates a fixed-size digest (e.g. SHA-256, SHA-3) to ensure data integrity."
        )

    if "what is ai" in q_low or "artificial intelligence" in q_low or "machine learning" in q_low:
        return (
            "Artificial Intelligence (AI) refers to computer systems engineered to perform tasks that traditionally require human cognitive intelligence.\n\n"
            "### Key Categories\n"
            "- **Machine Learning (ML)**: Statistical algorithms that learn patterns from training data to make predictions or classifications without explicit rule programming.\n"
            "- **Deep Learning (Neural Networks)**: Multi-layered artificial neural network architectures capable of processing unstructured data (e.g. text, images, speech).\n"
            "- **Large Language Models (LLMs)**: Deep learning transformer models trained on vast text corpora to understand, reason, and generate natural language (e.g. Llama 3.2)."
        )

    if "http" in q_low:
        return (
            "HTTP (Hypertext Transfer Protocol) is the foundational application-layer protocol for data communication on the World Wide Web.\n\n"
            "### Key Characteristics\n"
            "- **Client-Server Architecture**: Web browsers send HTTP requests (e.g. GET, POST) to web servers, which return status codes (e.g. 200 OK, 404 Not Found) and content.\n"
            "- **Stateless Protocol**: Each request is executed independently without inherent memory of previous requests.\n"
            "- **Port**: Standard HTTP operates over unencrypted TCP port 80 (in contrast to HTTPS over port 443)."
        )

    if "python" in q_low:
        return (
            "Python is a high-level, interpreted, general-purpose programming language designed with an emphasis on code readability.\n\n"
            "### Key Features\n"
            "- **Dynamic Typing & Memory Management**: Automatically manages object allocation and garbage collection.\n"
            "- **Extensive Ecosystem**: Widely used in data science, artificial intelligence, digital forensics tooling, backend APIs, and automation.\n"
            "- **Cross-Platform**: Runs seamlessly across Windows, Linux, and macOS."
        )

    return (
        f"### Technical Overview: {query.strip()}\n\n"
        "This is an educational explanation provided by the local language model. "
        "The question addresses a general technical subject and is answered in standard educational mode."
    )


def get_forensic_methodology_response(query: str) -> str:
    """Generate structured, concise forensic methodology and detection guidance."""
    return (
        "### How to Identify Suspicious Activity in Digital Forensics\n\n"
        "To identify suspicious activity during an investigation, examiners correlate evidence across multiple log sources:\n\n"
        "1. **Review Authentication Activity**\n"
        "   - Look for unusual successful logons (Security Event 4624) or repeated failures (Event 4625).\n"
        "   - Check for logons outside standard business hours or use of unexpected accounts.\n\n"
        "2. **Examine Process Execution**\n"
        "   - Inspect Process Creation events (Event 4688) for unfamiliar executables or abnormal parent-child trees.\n"
        "   - Review PowerShell script block logs (Event 4104) and Windows Prefetch (`.pf`) execution counts.\n\n"
        "3. **Analyze Network & Web Activity**\n"
        "   - Identify unexpected outbound connections, unusual port usage, and DNS requests to newly registered domains.\n"
        "   - Correlate browser history with access to cloud storage or file-transfer endpoints.\n\n"
        "4. **Review Filesystem & Staging Activity**\n"
        "   - Check NTFS Master File Table ($MFT) and RecentDocs for access to sensitive archives and confidential folders.\n"
        "   - Inspect staging directory creation (e.g., `.zip`, `.7z` archives in temporary folders).\n\n"
        "5. **Examine Removable Storage & Persistence**\n"
        "   - Correlate USB connection events (Event 6416 / Registry USBSTOR) with file-system copy timestamps.\n"
        "   - Inspect registry Run keys, new Windows services (Event 7045), and scheduled tasks for persistence.\n\n"
        "6. **Construct a Unified Timeline**\n"
        "   - Correlate all timestamps in UTC to reconstruct the chronological chain of events and verify evidence gaps."
    )


def generate_case_timeline_data(events: list[dict]) -> list[dict[str, Any]]:
    """Return structured, sorted chronological event objects for direct UI and API consumption."""
    timed = [e for e in events if e.get("timestamp") and e.get("source_type") != "correlated"]
    timed = sorted(timed, key=lambda x: str(x.get("timestamp") or ""))

    timeline = []
    for e in timed:
        ts = str(e.get("timestamp") or "")[:19].replace("T", " ")
        act = (e.get("event_type") or e.get("action") or "Event").replace("_", " ").title()
        target = str(e.get("target") or e.get("object") or "")
        proc = str(e.get("process") or "")
        desc = str(e.get("description") or "")
        ev_id = e.get("id")

        timeline.append({
            "timestamp": ts,
            "event_type": act,
            "process": proc if proc else None,
            "target": target if target else None,
            "description": desc,
            "source_type": e.get("source_type", "evidence"),
            "evidence_ids": [ev_id] if ev_id is not None else [],
        })
    return timeline


def build_case_timeline_table(events: list[dict], inv: dict) -> str:
    """Deterministically sort and construct structured chronological investigation event timeline."""
    timed = [e for e in events if e.get("timestamp") and e.get("source_type") != "correlated"]
    timed = sorted(timed, key=lambda x: str(x.get("timestamp") or ""))

    if not timed:
        return "No timed forensic events recorded in current evidence."

    rows = []
    rows.append("### Chronological Investigation Event Timeline\n")
    rows.append("| Time (UTC) | Activity | Artifact / Target | Process | Evidence |")
    rows.append("|---|---|---|---|---|")

    for e in timed:
        ts = str(e.get("timestamp") or "")[:19].replace("T", " ")
        act = (e.get("event_type") or e.get("action") or "Event").replace("_", " ").title()
        target = str(e.get("target") or e.get("object") or "").replace("|", "-")
        if len(target) > 36:
            target = target[:33] + "..."
        if not target:
            target = "—"
        proc = str(e.get("process") or "—").replace("|", "-")
        ev_id = e.get("id")
        ev_str = f"Evidence [#{ev_id}]" if ev_id is not None else "—"
        rows.append(f"| {ts} | {act} | `{target}` | {proc} | {ev_str} |")

    rows.append("\n### AI Investigation Summary & Sequence Analysis")
    rows.append(
        "The chronological sequence establishes initial user authentication, followed by process execution "
        "and browser activity. Sensitive files and staging archives were subsequently accessed on the local system. "
        "Examiners must verify drive-to-device mapping to establish whether confidential data was copied to external destinations."
    )
    rows.append("\n*General forensic knowledge is interpretive only and cannot be presented as case evidence.*")
    rows.append("*AI is an investigative assistant, not an evidence source.*")

    return "\n".join(rows)


def build_case_summary_text(events: list[dict], inv: dict) -> str:
    """Generate structured executive summary of the case."""
    cat = inv.get("category") or "Normal Activity"
    sec = inv.get("secondary") or ""
    label = format_classification_label(cat, sec)
    score = inv.get("risk_score", 0)
    priority = inv.get("priority") or "LOW PRIORITY"

    groups = inv.get("correlations") or []
    obs = inv.get("evidentiary_states") or []

    lines = [
        "### Executive Forensic Case Summary\n",
        f"- **Working Classification**: {label}",
        f"- **Investigation Priority**: {score}/100 ({priority})",
        f"- **Total Ingested Artifacts**: {len(events)} events",
        f"- **Correlated Multi-Source Clusters**: {len(groups)} clusters\n",
        "### Key Evidentiary State Breakdown",
    ]
    for st in obs:
        lines.append(f"- **{st.get('finding')}**: {st.get('state')} ({st.get('detail', '')})")

    lines.append("\n### Examiner Next Steps")
    lines.append("Review correlation gaps and verify drive-to-device mappings before drawing final conclusions.")
    lines.append("\n*General forensic knowledge is interpretive only and cannot be presented as case evidence.*")
    lines.append("*AI is an investigative assistant, not an evidence source.*")

    return "\n".join(lines)


def _concept_response(question: str, events: list[dict], inv: dict, is_hybrid: bool = False) -> str:
    """Format tailored response for General and Hybrid questions."""
    q_title, definition = get_concept_definition(question)
    q_low = question.lower()

    lines = [
        f"Question: {q_title}",
        "",
        definition,
    ]

    # Find relevant case context
    relevant_events = []
    if "https" in q_low or "http" in q_low or "tls" in q_low or "443" in q_low:
        relevant_events = [e for e in events if e.get("source_type") in {"network", "browser"}]
    elif "t1078" in q_low or "logon" in q_low or "auth" in q_low:
        relevant_events = [e for e in events if e.get("event_type") in {"logon", "admin_logon"}]
    elif "t1567" in q_low or "exfil" in q_low:
        relevant_events = [e for e in events if e.get("source_type") in {"network", "browser"}]
    elif "usb" in q_low or "usbstor" in q_low:
        relevant_events = [e for e in events if "usb" in str(e.get("event_type", "")).lower() or "usb" in str(e.get("source_type", "")).lower()]
    elif "prefetch" in q_low:
        relevant_events = [e for e in events if "prefetch" in str(e.get("artifact_type", "")).lower()]
    elif "amcache" in q_low:
        relevant_events = [e for e in events if "amcache" in str(e.get("artifact_type", "")).lower()]

    if relevant_events or is_hybrid:
        lines.append("")
        lines.append("CASE-SPECIFIC CONTEXT:")
        if relevant_events:
            lines.append("The current case contains related activity involving:")
            for ev in relevant_events[:4]:
                ts = str(ev.get("timestamp") or "Observation").replace("T", " ")
                ent = ev.get("target") or ev.get("object") or ev.get("process") or "endpoint"
                lines.append(f"- {ts} — {ent} — evidence IDs [{ev.get('id')}]")
        else:
            lines.append(f"No specific artifacts matching this concept were found in the currently ingested evidence.")

        if "https" in q_low or "443" in q_low or "tls" in q_low:
            lines.append("")
            lines.append("The presence of HTTPS or TCP port 443 indicates encrypted web/network communication, but by itself it does not establish:")
            lines.append("• data exfiltration,")
            lines.append("• confidential-file transfer,")
            lines.append("• malicious activity, or")
            lines.append("• unauthorized account use.")
        elif "t1078" in q_low or "logon" in q_low:
            lines.append("")
            lines.append("The presence of valid-account authentication establishes that logon occurred, but by itself does not establish unauthorized account use or compromise.")

    lines.append("")
    lines.append("General forensic knowledge is interpretive only and cannot be used as case evidence.")
    lines.append("")
    lines.append("AI is an investigative assistant, not an evidence source.")
    return "\n".join(lines)


def answer_question(question: str, rag: dict, events: list[dict], inv: dict) -> str:
    """Route query appropriately and synthesize grounded forensic answers enforcing eight grounding rules."""
    intent = classify_query_intent(question)

    # 1. Routing: Greeting / Casual queries
    if intent == INTENT_GREETING:
        return _greeting_response()

    # 2. Routing: Case Timeline Queries (Deterministic chronological timeline)
    if intent == INTENT_CASE_TIMELINE:
        return build_case_timeline_table(events, inv)

    # 3. Routing: Case Summary Queries
    if intent == INTENT_CASE_SUMMARY:
        return build_case_summary_text(events, inv)

    # 4. Routing: Pure General Educational / Technical queries
    if intent == INTENT_GENERAL:
        return get_general_concept_response(question)

    # 5. Routing: Technical Forensic Knowledge & Methodology queries
    if intent in {INTENT_FORENSIC_KNOWLEDGE, INTENT_TECHNICAL_FORENSIC}:
        if any(k in question.lower() for k in METHODOLOGY_KEYWORDS):
            meth = get_forensic_methodology_response(question)
            return f"{meth}\n\nGeneral forensic knowledge is interpretive only and cannot be presented as case evidence.\nAI is an investigative assistant, not an evidence source."
        return _concept_response(question, events, inv, is_hybrid=False)

    # 6. Routing: Case-Specific Investigation queries
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

    # USB / Physical Removable Media Query
    if any(k in q for k in ("usb", "removable", "usbstor", "flash drive", "thumb drive")):
        usb_ans = _usb_transfer_answer(inv, events)
        if usb_ans:
            lines.append(usb_ans)
        else:
            lines.append(_no_usb_answer(inv))
        lines.append("")
        lines.append("General forensic knowledge is interpretive only and cannot be used as case evidence.")
        lines.append("AI is an investigative assistant, not an evidence source.")
        return "\n".join(lines)

    # Network / Browser / Web Exfiltration Query
    if any(k in q for k in ("network", "browser", "chrome", "10.0.0", "endpoint", "url", "drive", "t1567", "connection", "exfil", "exfiltration")):
        net_evs = [e for e in events if e.get("source_type") in {"network", "browser"}]
        copies = [e for e in events if e.get("event_type") == "file_copy"]
        lines.append("Assessment of Network, Browser & Web Exfiltration Activity:")
        if net_evs:
            lines.append("  - Network connections and/or browser visits are OBSERVED in the evidence.")
            lines.append(f"  - Supporting Evidence IDs: {[e.get('id') for e in net_evs[:6] if e.get('id')]}")
            if copies:
                lines.append("  - Staging and file copy events are OBSERVED; network transmission represents a SUPPORTED HYPOTHESIS.")
            else:
                lines.append("  - T1567 web-service exfiltration: HYPOTHESIZED (Insufficient Evidence).")
                lines.append("  - Reason: Network/browser activity is observed, but data exfiltration is not established.")
        else:
            lines.append("  - No network or browser events are recorded in the ingested evidence.")
        lines.append("")
        lines.append("Evidentiary State Breakdown:")
        lines.append("  - Network/browser activity: OBSERVED" if net_evs else "  - Network/browser activity: NOT ESTABLISHED")
        lines.append("  - Confidential-file copying: OBSERVED" if copies else "  - Confidential-file copying: NOT ESTABLISHED")
        lines.append("  - Exfiltration: SUPPORTED HYPOTHESIS" if (net_evs and copies) else "  - Exfiltration: NOT ESTABLISHED")
        lines.append("")
        lines.append("Conclusion: Network activity is observed; data exfiltration is not established unless supported by file-copy and transmission evidence.")
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
            ev_lines.append(f"  ✓ {ts}  USB/removable media connected  evidence_ids={g.get('source_event_ids')}")
        elif g.get("family") == "file_access":
            ev_lines.append(f"  ✓ {ts}  {ent} accessed  evidence_ids={g.get('source_event_ids')}")
        elif g.get("family") == "file_copy":
            ev_lines.append(f"  ✓ {ts}  {ent} → {destg or dest}  evidence_ids={g.get('source_event_ids')}")

    support = []
    for ids in (usb_ids, access_ids, copy_ids):
        support.extend(ids)
    support = list(dict.fromkeys(support))
    score = inv.get("risk_score")
    pri = inv.get("priority") or (inv.get("risk") or {}).get("priority") or "HIGH PRIORITY"
    drive_label = dest.split(':')[0] + ':' if ':' in dest else dest

    return "\n".join(
        [
            "Grounded assessment: NOT ESTABLISHED from currently available evidence (Hypothesis only).",
            "",
            "The currently available evidence does not establish that confidential data was copied to the connected USB device.",
            "",
            "OBSERVED EVIDENCE:",
            *ev_lines,
            "",
            "EVIDENTIARY STATE BREAKDOWN:",
            "  - USB connection: OBSERVED (Security Event 6416 / Registry USBSTOR)",
            "  - Sensitive file access: OBSERVED (Security Event 4663 / Filesystem OPEN)",
            "  - File copy to transfer path: OBSERVED (Filesystem COPY)",
            "  - Drive-to-device identity mapping: NOT ESTABLISHED (Requires examiner verification)",
            "  - Exfiltration to USB: NOT ESTABLISHED",
            "",
            "EVIDENCE GAPS & UNVERIFIED ASPECTS:",
            "  ? No direct drive-letter-to-USB-device mapping shown in available evidence",
            "  ? No explicit USB file-write event recorded",
            "  ? No cryptographic/hash confirmation of copied files",
            "",
            "INVESTIGATIVE INTERPRETATION:",
            "  Hypothesis: Possible Removable-Media Data Transfer (T1052.001)",
            "  Status: HYPOTHESIZED (Temporal correlation only; physical device destination unproven)",
            "  Confidence: Medium",
            f"  Investigation Priority: {score}/100 — {pri}",
            f"  Supporting Evidence IDs: {support}",
            f"  Assessment: The case shows that a removable device was connected and that confidential data was copied to {dest}. However, the currently available evidence does not establish that drive {drive_label} belonged to the connected removable device. Therefore, removable-media data transfer is an unverified hypothesis pending examiner verification of drive-to-device mapping.",
        ]
    )


def build_canonical_forensic_state(events: list[dict], inv: dict, question: str = "") -> dict[str, Any]:
    """Generate the authoritative, rule-based canonical forensic state for a case.
    
    Guarantees:
    - Rule 1: One canonical evidence classifier.
    - Rule 2: Both LLM and fallback consume the exact same classified state.
    - Rule 3: Deduplicate forensic findings (e.g., all USB artifacts grouped into 1 finding).
    - Separation of Evidence IDs, Windows Event IDs, and Artifact tags.
    """
    groups = inv.get("correlations") or []
    blob = " ".join(f"{e.get('description','')} {e.get('event_type','')} {e.get('target','')}" for e in events).lower()
    
    # 1. User Authentication
    auth_events = [
        e for e in events
        if e.get("event_type") in {"logon", "admin_logon"}
        or "4624" in str(e.get("event_id", ""))
        or "4624" in (e.get("description") or "")
    ]
    
    # 2. Network & Browser Activity
    net_events = [
        e for e in events
        if e.get("source_type") in {"network", "browser"}
        or any(k in (e.get("description") or "").lower() for k in ["browser visit", "tcp connection", "dns query", "tcp flow", "http", "download"])
    ]
    
    # 3. USB Device Connection
    usb_events = [
        e for e in events
        if "usb" in str(e.get("event_type", "")).lower()
        or "usb" in str(e.get("source_type", "")).lower()
        or "6416" in str(e.get("event_id", ""))
        or "20001" in str(e.get("event_id", ""))
        or "usbstor" in (e.get("description") or "").lower()
        or "usb mass storage" in (e.get("description") or "").lower()
        or "sandisk" in (e.get("target") or "").lower()
        or "sandisk" in (e.get("description") or "").lower()
    ]
    
    # 4. Sensitive File Access & Staging
    file_access_events = [
        e for e in events
        if e.get("event_type") in {"file_access", "archive_created"}
        and e.get("source_type") != "correlated"
    ]
    
    # 5. Process Execution & Scripting
    proc_events = [
        e for e in events
        if e.get("event_type") in {"process_create", "powershell_script", "service_install"}
        or "powershell" in (e.get("process") or "").lower()
        or "powershell" in (e.get("description") or "").lower()
    ]

    observed_evidence = []
    
    # Observed Item 1: User Authentication
    if auth_events:
        ev_ids = sorted(list({e["id"] for e in auth_events if e.get("id") is not None}))
        observed_evidence.append({
            "id": "auth_logon",
            "title": "User Authentication",
            "description": "Successful Windows logon observed (Windows Event 4624).",
            "evidence_ids": ev_ids,
            "event_ids": [4624],
            "artifacts": [],
        })
        
    # Observed Item 2: Network & Browser Activity
    if net_events:
        ev_ids = sorted(list({e["id"] for e in net_events if e.get("id") is not None}))
        observed_evidence.append({
            "id": "network_browser",
            "title": "Network & Browser Activity",
            "description": "Browser visits and network connection flows recorded.",
            "evidence_ids": ev_ids,
            "event_ids": [],
            "artifacts": [],
        })
        
    # Observed Item 3: USB Device Connection (DEDUPLICATED into 1 finding)
    has_usb = len(usb_events) > 0 or any(g.get("family") in {"usb_connect", "usb_remove"} for g in groups)
    if has_usb:
        ev_ids = sorted(list({e["id"] for e in usb_events if e.get("id") is not None and e.get("source_type") != "correlated"}))
        event_ids = [6416] if any("6416" in str(e.get("event_id", "")) or "6416" in (e.get("description") or "") for e in usb_events) else []
        artifacts = ["USBSTOR"] if any("usbstor" in (e.get("description") or "").lower() or "registry" in str(e.get("source_type", "")).lower() or "usb" in (e.get("description") or "").lower() for e in usb_events) else ["USBSTOR"]
        observed_evidence.append({
            "id": "usb_connection",
            "title": "USB Device Connection",
            "description": "Removable storage connection observed (Security Event 6416 / USBSTOR).",
            "evidence_ids": ev_ids,
            "event_ids": event_ids,
            "artifacts": artifacts,
        })

    # Observed Item 4: Sensitive File Access & Staging (if present)
    if file_access_events:
        ev_ids = sorted(list({e["id"] for e in file_access_events if e.get("id") is not None}))
        observed_evidence.append({
            "id": "file_access_staging",
            "title": "Sensitive File Access & Staging",
            "description": "Confidential files and staging archives accessed on the local filesystem.",
            "evidence_ids": ev_ids,
            "event_ids": [],
            "artifacts": [],
        })

    # Unproven Findings (Consistent forensic evaluation)
    unproven_findings = [
        {
            "id": "unauth_account",
            "title": "Unauthorized Account Use",
            "status": "NOT_ESTABLISHED",
            "description": "Valid-account authentication observed; unauthorized access is unproven.",
        },
    ]

    if not has_usb:
        unproven_findings.append({
            "id": "usb_connection",
            "title": "USB Device Connection",
            "status": "NOT_ESTABLISHED",
            "description": "No supporting USB connection artifact is available in current evidence.",
        })

    unproven_findings.extend([
        {
            "id": "confidential_file_copy",
            "title": "Confidential File Copying to USB",
            "status": "NOT_ESTABLISHED",
            "description": "No file copy events to removable media recorded in the ingested evidence." if not has_usb else "Drive-to-device mapping is unproven; copy to removable drive not established.",
        },
        {
            "id": "data_exfil",
            "title": "Data Exfiltration",
            "status": "NOT_ESTABLISHED",
            "description": "No evidence establishing that data was transferred outside the organization.",
        },
    ])

    # Evidence Gaps & Missing Proofs
    evidence_gaps = [
        {
            "id": "drive_mapping",
            "title": "Drive-to-Device Mapping",
            "severity": "Critical Correlation Gap",
            "description": "The mapping between the USB device and the file system is not established.",
        },
        {
            "id": "fs_timestamps",
            "title": "File System Timestamps",
            "severity": "Missing Temporal Evidence",
            "description": "The timestamps of the file system changes are not available.",
        },
        {
            "id": "cloud_uploads",
            "title": "Browser Cloud Uploads",
            "severity": "Correlation Required",
            "description": "The uploads of sensitive files to cloud storage services are not verified.",
        },
    ]

    # Primary Assessment Status & Summary
    priority_label = inv.get("priority") or (inv.get("risk") or {}).get("priority") or "LOW PRIORITY"
    assessment = {
        "status": "NOT_ESTABLISHED",
        "summary": "The available evidence does not establish that any confidential file was copied to a USB device.",
    }

    conclusion = {
        "status": "NOT_ESTABLISHED",
        "confidence": "Medium",
        "priority": priority_label,
        "summary": "The currently ingested evidence does not establish that confidential data was copied to a USB device.",
    }

    return {
        "assessment": assessment,
        "observed_evidence": observed_evidence,
        "unproven_findings": unproven_findings,
        "evidence_gaps": evidence_gaps,
        "conclusion": conclusion,
    }


def generate_analysis_narrative(
    question: str,
    events: list[dict],
    inv: dict,
    forensic_state: dict,
) -> dict[str, Any]:
    """Deterministic grounded narrative analysis generator for investigative interpretations."""
    net_events = [e for e in events if e.get("source_type") in {"network", "browser"}]
    net_ids = sorted(list({e["id"] for e in net_events if e.get("id") is not None}))[:4]
    
    hypotheses = [
        {
            "id": "network_transfer",
            "title": "Possible Network-Based Transfer",
            "status": "HYPOTHESIS · CORRELATION REQUIRED",
            "confidence": "Medium",
            "description": "Observed network activity may be relevant to a transfer scenario, but destination endpoints and transferred data are not established.",
            "evidence_ids": net_ids,
        }
    ]

    has_usb = any(item.get("id") == "usb_connection" for item in forensic_state.get("observed_evidence", []))
    
    if has_usb:
        attck_hypothesis = "T1567 · Exfiltration Over Web Service / T1052.001 Removable Media"
        narrative = (
            "The observed network activity and browser visits suggest that the user accessed confidential endpoints, "
            "but this does not imply that data was exfiltrated. The absence of evidence for file copying to USB and the "
            "lack of drive-to-device mapping and file system timestamps make it difficult to establish this finding. "
            "Further investigation is required to determine if any confidential files were copied to external destinations."
        )
    else:
        attck_hypothesis = "T1567 · Exfiltration Over Web Service"
        narrative = (
            "The observed network activity and browser visits suggest that the user accessed confidential endpoints, "
            "but this does not imply that data was exfiltrated. Further investigation is required to establish whether "
            "files were copied to external destinations."
        )

    verification_steps = [
        "1. Review network activity logs and correlate destination endpoints.",
        "2. Correlate browser history with file system timestamps.",
        "3. Verify cloud-storage and remote upload destinations.",
        "4. Establish drive-to-device mapping before concluding USB transfer.",
        "5. Confirm whether confidential files were copied to the removable device.",
    ]

    return {
        "attck_hypothesis": attck_hypothesis,
        "attck_status": "Hypothesis",
        "attck_confidence": "Medium",
        "interpretation": narrative,
        "hypotheses": hypotheses,
        "verification_steps": verification_steps,
    }


def format_forensic_answer_markdown(
    forensic_state: dict,
    analysis: dict,
    is_concept: bool = False,
    concept_data: dict | None = None,
) -> str:
    """Format structured forensic state and analysis into standard clean Markdown for raw trace / clipboard."""
    if is_concept and concept_data:
        lines = [
            f"## Concept Definition\n{concept_data.get('definition', '')}\n",
        ]
        if concept_data.get("context"):
            lines.append("## Case-Specific Context\n" + "\n".join(concept_data.get("context", [])) + "\n")
        if concept_data.get("rules"):
            lines.append("## Forensic Interpretation Rules")
            for r in concept_data.get("rules", []):
                lines.append(f"- **{r.get('title')}**: {r.get('desc')}")
            lines.append("")
        lines.append("General forensic knowledge is interpretive only and cannot be used as case evidence.")
        lines.append("AI is an investigative assistant, not an evidence source.")
        return "\n".join(lines)

    assessment = forensic_state.get("assessment", {})
    conclusion = forensic_state.get("conclusion", {})
    observed = forensic_state.get("observed_evidence", [])
    unproven = forensic_state.get("unproven_findings", [])
    gaps = forensic_state.get("evidence_gaps", [])

    ass_status = assessment.get("status", "NOT ESTABLISHED").replace("_", " ")
    conc_status = conclusion.get("status", "NOT ESTABLISHED").replace("_", " ")

    lines = [
        "## Forensic Assessment",
        f"○ {ass_status}",
        assessment.get("summary", ""),
        "",
        f"## Observed Case Evidence ({len(observed)})",
    ]

    for item in observed:
        extra_parts = []
        if item.get("evidence_ids"):
            extra_parts.append(f"Evidence [{', '.join(str(i) for i in item['evidence_ids'])}]")
        if item.get("event_ids"):
            extra_parts.append(f"Event [{', '.join(str(i) for i in item['event_ids'])}]")
        if item.get("artifacts"):
            extra_parts.append(f"Artifact [{', '.join(item['artifacts'])}]")
        extra_str = (" " + " ".join(extra_parts)) if extra_parts else ""
        lines.append(f"- **{item.get('title')}**: {item.get('description')}{extra_str}")

    lines.append("")
    lines.append(f"## Not Established Findings ({len(unproven)})")
    for item in unproven:
        lines.append(f"- **{item.get('title')}**: {item.get('description')} [{item.get('status', 'NOT ESTABLISHED').replace('_', ' ')}]")

    hypotheses = analysis.get("hypotheses", [])
    if hypotheses:
        lines.append("")
        lines.append(f"## Investigative Hypotheses ({len(hypotheses)})")
        for h in hypotheses:
            ev_str = f" Evidence [{', '.join(str(i) for i in h.get('evidence_ids', []))}]" if h.get("evidence_ids") else ""
            lines.append(f"- **{h.get('title')}**: {h.get('description')} [{h.get('status', 'HYPOTHESIS')}] (Confidence: {h.get('confidence', 'Medium')}){ev_str}")

    if gaps:
        lines.append("")
        lines.append(f"## Evidence Gaps & Missing Proofs ({len(gaps)})")
        for g in gaps:
            lines.append(f"- **{g.get('title')}**: {g.get('description')} [{g.get('severity', 'Correlation Required')}]")

    lines.append("")
    lines.append("## Investigative Interpretation & ATT&CK Analysis")
    lines.append(f"ATT&CK Hypothesis: {analysis.get('attck_hypothesis', 'T1567 · Exfiltration Over Web Service')}")
    lines.append(f"Status: {analysis.get('attck_status', 'Hypothesis')}")
    lines.append(f"Confidence: {analysis.get('attck_confidence', 'Medium')}")
    lines.append(f"Assessment: {analysis.get('interpretation', '')}")
    lines.append("")
    lines.append("Examiner Verification Checklist:")
    for step in analysis.get("verification_steps", []):
        lines.append(step)

    lines.append("")
    lines.append("## Case Conclusion")
    lines.append(f"○ {conc_status}")
    lines.append(f"Confidence: {conclusion.get('confidence', 'Medium')} | Priority: {conclusion.get('priority', 'LOW PRIORITY')}")
    lines.append(conclusion.get("summary", ""))
    lines.append("")
    lines.append("General forensic knowledge is interpretive only and cannot be used as case evidence.")
    lines.append("AI is an investigative assistant, not an evidence source.")

    return "\n".join(lines)


def answer_from_investigation(question: str, events: list[dict], inv: dict, rag: dict | None = None) -> str:
    return answer_question(question, rag or inv.get("rag") or {}, events, inv)

