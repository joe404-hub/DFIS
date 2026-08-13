"""Recommended next investigation actions — examiner tasks, not AI conclusions."""


def recommend_actions(events: list[dict], groups: list[dict]) -> list[dict]:
    def ids(*fams):
        out = []
        for g in groups:
            if g.get("family") in fams:
                out.extend(g.get("source_event_ids") or [])
        return list(dict.fromkeys(out))

    def ev_ids(*types):
        return [e.get("id") for e in events if e.get("event_type") in types and e.get("id") is not None]

    actions = []
    usb_ids = ids("usb_connect", "usb_remove") or ev_ids("usb_connect", "usb_remove", "usb_history")
    copy_ids = ids("file_copy") or ev_ids("file_copy")
    if usb_ids and copy_ids:
        actions.append(
            {
                "priority": 1,
                "action": "Verify E:\\ ↔ USB device mapping",
                "reason": "Establish whether copies to the transfer path went to the connected removable device. Temporal correlation is not device identity.",
                "evidence_ids": usb_ids + copy_ids,
            }
        )
    svc = ids("service") or ev_ids("service_install", "persistence")
    if svc:
        actions.append(
            {
                "priority": 2,
                "action": "Investigate DemoUpdater / installed service",
                "reason": "Determine whether the service is legitimate, unauthorized persistence, or synthetic noise.",
                "evidence_ids": svc,
            }
        )
    net = [e.get("id") for e in events if e.get("source_type") in {"network", "browser"} and e.get("id")]
    if net:
        actions.append(
            {
                "priority": 3,
                "action": "Examine 09:30 network / drive.example.local activity",
                "reason": "T1567 is a low-confidence hypothesis only. Do not treat TLS/cookie as confirmed exfiltration.",
                "evidence_ids": net[:8],
            }
        )
    ps = [e.get("id") for e in events if "powershell" in (e.get("description") or "").lower() and e.get("id")]
    if ps:
        actions.append(
            {
                "priority": 4,
                "action": "Review PowerShell activity",
                "reason": "Determine what commands or scripts were executed around 09:04.",
                "evidence_ids": ps,
            }
        )
    mem = [e.get("id") for e in events if e.get("source_type") == "memory" and e.get("id")]
    if mem:
        actions.append(
            {
                "priority": 5,
                "action": "Validate memory snapshot against original acquisition",
                "reason": "09:40 is observation/capture time, not process start. Corroborate processes and network state.",
                "evidence_ids": mem,
            }
        )
    actions.append(
        {
            "priority": 6,
            "action": "Verify original artifacts and SHA-256 hashes",
            "reason": "Preserve forensic defensibility. AI output is not evidence.",
            "evidence_ids": [],
        }
    )
    for i, a in enumerate(actions, 1):
        a["priority"] = i
    return actions


def format_actions(actions: list[dict]) -> str:
    lines = [
        "Recommended next investigation actions",
        "(These are examiner tasks. They are not findings of fact.)",
        "",
    ]
    for a in actions:
        ev = a.get("evidence_ids") or []
        lines.append(f"{a['priority']}. {a['action']}")
        lines.append(f"   Reason: {a['reason']}")
        if ev:
            lines.append(f"   Evidence IDs: {ev}")
        lines.append("")
    return "\n".join(lines).rstrip()
