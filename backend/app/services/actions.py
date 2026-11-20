"""Recommended next investigation actions — examiner verification tasks, not AI conclusions.

Derives prioritized examiner tasks directly from NOT ESTABLISHED, INSUFFICIENT EVIDENCE,
and SUPPORTED HYPOTHESIS findings to complete the forensic workflow:
Evidence → Observation → Correlation → Hypothesis → Evidentiary State → Investigation Recommendation.
"""

from __future__ import annotations

import re
from typing import Any


def recommend_actions(events: list[dict[str, Any]], groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Derive grounded verification tasks from case evidentiary states and gaps."""
    blob = " ".join(f"{e.get('description','')} {e.get('event_type','')}" for e in events).lower()
    families = {g.get("family") for g in groups}

    def ids_for(*fams):
        out = []
        for g in groups:
            if g.get("family") in fams:
                out.extend(g.get("source_event_ids") or [])
        if out:
            return list(dict.fromkeys(out))
        for e in events:
            if e.get("event_type") in fams or e.get("source_type") in fams:
                if e.get("id") is not None:
                    out.append(e.get("id"))
        return list(dict.fromkeys(out))

    actions: list[dict[str, Any]] = []

    # Evidence ID lookups
    logon_ids = ids_for("logon", "admin_logon", "windows_event")
    usb_ids = ids_for("usb_connect", "usb_remove", "usb_history")
    copy_ids = ids_for("file_copy")
    access_ids = ids_for("file_access")
    net_ids = ids_for("network", "browser")
    ps_ids = [e.get("id") for e in events if "powershell" in (e.get("description") or "").lower() and e.get("id") is not None]
    svc_ids = ids_for("service", "service_install", "persistence")
    mem_ids = [e.get("id") for e in events if e.get("source_type") == "memory" and e.get("id") is not None]

    has_copies = bool(copy_ids) or "file_copy" in blob
    has_usb = bool(usb_ids) or "usb" in blob
    has_sensitive = bool(re.search(r"sensitive_|customer_list|confidential|projectx|api_keys", blob))
    has_net = bool(net_ids)
    has_logon = bool(logon_ids)

    # 1. Removable media & USB copy verification (High priority if copy/USB activity exists)
    if has_usb and has_copies:
        actions.append(
            {
                "question": "Was confidential data actually copied to the connected USB device?",
                "action": "Verify E:\\ ↔ USB device mapping and write confirmations",
                "reason": "USB connection and file copies are observed, but drive-letter mapping to device identity is not established. Temporal correlation does not prove destination identity.",
                "evidence_ids": (usb_ids + copy_ids)[:8],
                "status": "pending_examiner_verification",
                "layer": "verify",
                "evidentiary_state": "SUPPORTED HYPOTHESIS",
            }
        )
    elif not has_usb:
        actions.append(
            {
                "question": "Was any removable device connected?",
                "action": "Verify USBSTOR and PnP device connection logs",
                "reason": "USB transfer is NOT ESTABLISHED in the evidence. If this hypothesis is investigated, inspect registry USBSTOR and Event 6416/20001 logs.",
                "evidence_ids": usb_ids[:6],
                "status": "pending_examiner_verification",
                "layer": "verify",
                "evidentiary_state": "NOT ESTABLISHED",
            }
        )

    # 2. Confidential file access & copy verification
    if not has_copies:
        actions.append(
            {
                "question": "Was confidential data accessed or copied?",
                "action": "Audit filesystem access and file-copy records",
                "reason": "Confidential-file copying is NOT ESTABLISHED in the currently ingested evidence. Audit $MFT and security object access (Event 4663) logs.",
                "evidence_ids": access_ids[:6],
                "status": "pending_examiner_verification",
                "layer": "verify",
                "evidentiary_state": "NOT ESTABLISHED",
            }
        )
    elif has_copies and not has_sensitive:
        actions.append(
            {
                "question": "Were copied files confidential or business-sensitive?",
                "action": "Inspect copied file contents and classifications",
                "reason": "File copy events are observed, but sensitive classification is not confirmed.",
                "evidence_ids": copy_ids[:6],
                "status": "pending_examiner_verification",
                "layer": "verify",
                "evidentiary_state": "INSUFFICIENT EVIDENCE",
            }
        )

    # 3. Valid Account Legitimacy & T1078 Verification
    if has_logon:
        actions.append(
            {
                "question": "Was the valid account legitimately used?",
                "action": "Verify legitimacy of valid-account logon (T1078)",
                "reason": "T1078 is OBSERVED in logs, but unauthorized account compromise is NOT ESTABLISHED. Verify authentication source, logon type, workstation, and time.",
                "evidence_ids": logon_ids[:4],
                "status": "pending_examiner_verification",
                "layer": "verify",
                "evidentiary_state": "INSUFFICIENT EVIDENCE",
            }
        )

    # 4. Network / Browser Activity (T1567 hypothesis & internal endpoint verification)
    if has_net:
        # Check if internal IP
        internal_events = [e.get("id") for e in events if e.get("source_type") in {"network", "browser"} and ("10." in str(e.get("target") or e.get("destination_ip") or "") or "192.168." in str(e.get("target") or e.get("destination_ip") or ""))]
        if internal_events:
            actions.append(
                {
                    "question": "What is the identity and purpose of the internal endpoint (10.0.0.x:443)?",
                    "action": "Verify internal endpoint purpose and data flow volume",
                    "reason": "Internal network session is OBSERVED, but T1567 exfiltration is INSUFFICIENT EVIDENCE. Verify whether traffic represents routine intranet/drive access.",
                    "evidence_ids": internal_events[:6],
                    "status": "pending_examiner_verification",
                    "layer": "verify",
                    "evidentiary_state": "INSUFFICIENT EVIDENCE",
                }
            )
        else:
            actions.append(
                {
                    "question": "What was the browser / process accessing?",
                    "action": "Examine browser history and network flows (T1567)",
                    "reason": "T1567 is only HYPOTHESIZED based on network/browser activity; data exfiltration is NOT ESTABLISHED.",
                    "evidence_ids": net_ids[:6],
                    "status": "pending_examiner_verification",
                    "layer": "verify",
                    "evidentiary_state": "INSUFFICIENT EVIDENCE",
                }
            )

    # 5. Service / Persistence Investigation
    if svc_ids:
        actions.append(
            {
                "question": "Is the installed service legitimate or persistence?",
                "action": "Investigate installed service configuration and binary path",
                "reason": "Service installation (T1543.003) is OBSERVED; determine whether the binary is an authorized administrative utility or unauthorized persistence.",
                "evidence_ids": svc_ids[:6],
                "status": "pending_examiner_verification",
                "layer": "verify",
                "evidentiary_state": "SUPPORTED HYPOTHESIS",
            }
        )

    # 6. PowerShell Command Line Review
    if ps_ids:
        actions.append(
            {
                "question": "What commands were executed via PowerShell?",
                "action": "Review PowerShell script block and command line parameters",
                "reason": "PowerShell execution (T1059.001) is OBSERVED; inspect script block logs (Event 4104) to review exact commands executed.",
                "evidence_ids": ps_ids[:4],
                "status": "pending_examiner_verification",
                "layer": "verify",
                "evidentiary_state": "OBSERVED",
            }
        )

    # 7. Memory Snapshot Validation
    if mem_ids:
        actions.append(
            {
                "question": "What does the memory image show regarding active processes and sockets?",
                "action": "Corroborate memory processes against original acquisition",
                "reason": "Memory snapshot exists, but acquisition time is observation time, not process execution start. Corroborate processes and network sockets.",
                "evidence_ids": mem_ids[:6],
                "status": "pending_examiner_verification",
                "layer": "verify",
                "evidentiary_state": "OBSERVED",
            }
        )

    # 8. Cryptographic Hash Integrity Verification
    actions.append(
        {
            "question": "Are all original evidence files cryptographically intact?",
            "action": "Verify original evidence SHA-256 integrity hashes",
            "reason": "Preserve forensic defensibility. AI output is an investigative aid, not evidence.",
            "evidence_ids": [],
            "status": "pending_examiner_verification",
            "layer": "verify",
            "evidentiary_state": "OBSERVED",
        }
    )

    for i, a in enumerate(actions, 1):
        a["priority"] = i

    return actions


def format_actions(actions: list[dict[str, Any]]) -> str:
    """Format examiner recommendation tasks with investigation questions and reasons."""
    lines = [
        "Recommended next investigation actions",
        "(These are examiner tasks derived from evidentiary gaps. They are not findings of fact.)",
        "",
    ]
    for a in actions:
        ev = a.get("evidence_ids") or []
        q = a.get("question")
        lines.append(f"{a['priority']}. {a['action']}")
        if q:
            lines.append(f"   Investigation question: {q}")
        lines.append(f"   Why investigate: {a['reason']}")
        if ev:
            lines.append(f"   Evidence IDs: {ev}")
        lines.append("")
    return "\n".join(lines).rstrip()
