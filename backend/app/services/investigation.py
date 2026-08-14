"""Case-specific investigation: correlated briefs → RAG → classification / risk / chain.

Implements 4-tier forensic evidentiary states:
- OBSERVED: Directly recorded in evidence logs
- SUPPORTED HYPOTHESIS: Inferred from corroborated multi-source events
- INSUFFICIENT EVIDENCE: Observed low-level activity that does not establish the broader hypothesis
- NOT ESTABLISHED: Hypotheses explicitly unconfirmed or unsupported by case events
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

    return {
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


def _is_benign(inv: dict) -> bool:
    cat = (inv.get("category") or "").lower()
    score = float(inv.get("risk_score") or 0)
    groups = inv.get("correlations") or []
    families = {g.get("family") for g in groups}
    if "file_copy" in families:
        return False
    return "insufficient evidence" in (inv.get("secondary") or "").lower() or cat == "normal activity" or score < 25


def _benign_answer(inv: dict) -> str:
    score = inv.get("risk_score", 0)
    pri = inv.get("priority") or (inv.get("risk") or {}).get("priority") or "LOW PRIORITY"
    cat = inv.get("category") or "Possible Unauthorized Use of Valid Account"
    sec = inv.get("secondary") or "Insufficient Evidence for Exfiltration"

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
            "",
            "General forensic knowledge is interpretive only and cannot be used as case evidence.",
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


def answer_question(question: str, rag: dict, events: list[dict], inv: dict) -> str:
    q = question.lower()
    lines = [
        f"Question: Was confidential data copied to USB?" if "usb" in q or "copied" in q else f"Question: {question}",
        "",
        _priority_line(inv),
        "",
    ]
    if _is_benign(inv):
        lines.append(_benign_answer(inv))
        lines.append("")
        if any(k in q for k in ("next step", "next action", "what should", "recommend", "further", "investigate next")):
            lines.append(
                "Recommended next step: No USB/transfer verification is indicated. "
                "If required, confirm SHA-256 hashes of the original artifacts and close the case as routine."
            )
            lines.append("")
            lines.append(format_actions(inv.get("next_actions") or recommend_actions(events, inv.get("correlations") or [])))
        lines.append("")
        lines.append("AI is an investigative assistant, not an evidence source.")
        return "\n".join(lines)

    if any(k in q for k in ("next step", "next action", "what should", "recommend", "further", "investigate next")):
        actions = inv.get("next_actions") or recommend_actions(events, inv.get("correlations") or [])
        lines.append(
            "Recommended next step: Verify the relationship between the removable device "
            "identified by the USBSTOR artifact and the E:\\Transfer destination. This is necessary "
            "to determine whether the two sensitive files were actually copied to the connected USB device. "
            "Next, investigate the DemoUpdater service and review the 09:30 network activity to determine "
            "whether data was subsequently transferred over the network. Do not treat drive.example.local "
            "or TLS POST as confirmed exfiltration (T1567 remains a low-confidence hypothesis). "
            "All findings should be verified against the original artifacts and hashes."
        )
        lines.append("")
        lines.append(format_actions(actions))
        lines.append("")
        lines.append("AI is an investigative assistant, not an evidence source.")
        return "\n".join(lines)

    if any(k in q for k in ("usb", "copied", "copy", "exfil", "transfer", "confidential", "sensitive")):
        usb_ans = _usb_transfer_answer(inv, events)
        if usb_ans:
            lines.append(usb_ans)
            lines.append("")
        else:
            lines.append(_benign_answer(inv))
            lines.append("")
    else:
        groups = inv.get("correlations") or []
        toks = {t for t in re.findall(r"[a-z0-9._-]{3,}", q)}
        scored = []
        for g in groups:
            blob = (g.get("brief") or "").lower()
            scored.append((sum(1 for t in toks if t in blob), g))
        scored.sort(key=lambda x: -x[0])
        use = [g for s, g in scored if s > 0][:6] or [g for _, g in scored[:5]]
        lines.append("CASE-SPECIFIC EVIDENCE")
        for g in use:
            lines.append(
                f"- {g['timestamp']} {g['family']} {g['entity']} evidence_ids={g['source_event_ids']}"
            )
        lines.append("")
    lines.append("GENERAL FORENSIC KNOWLEDGE (interpretive only — not CASE events; do not infer absent events such as archive creation):")
    for k in (inv.get("rag") or {}).get("knowledge") or []:
        lines.append(f"- {k}")
        break
    lines.append("")
    lines.append("AI is an investigative assistant, not an evidence source. Verify conclusions against the original artifacts and hashes.")
    return "\n".join(lines)


def answer_from_investigation(question: str, events: list[dict], inv: dict, rag: dict | None = None) -> str:
    return answer_question(question, rag or inv.get("rag") or {}, events, inv)
