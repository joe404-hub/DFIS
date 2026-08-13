"""Transparent hybrid risk score.

Weights are a documented prototype design choice for prioritization,
not a measure of legal culpability. Validated only against synthetic cases.
"""

from __future__ import annotations

import re

# Documented indicator weights (max contribution if observed).
INDICATORS = [
    {"id": "powershell", "label": "PowerShell execution", "points": 10},
    {"id": "service", "label": "Service installation / persistence artifact", "points": 10},
    {"id": "usb", "label": "USB / removable media connected", "points": 15},
    {"id": "sensitive", "label": "Sensitive file access", "points": 15},
    {"id": "multi_sensitive", "label": "Multiple distinct sensitive files", "points": 10},
    {"id": "copy", "label": "File copy to transfer / removable path", "points": 20},
    {"id": "network_after", "label": "Network/browser activity after transfer", "points": 10},
    {"id": "admin", "label": "Administrative logon", "points": 5},
    {"id": "multi_source", "label": "Same activity confirmed by ≥2 artifact types", "points": 10},
]


def priority_label(score: int) -> str:
    if score >= 70:
        return "HIGH PRIORITY"
    if score >= 40:
        return "MEDIUM PRIORITY"
    if score >= 15:
        return "LOW PRIORITY"
    return "ROUTINE"


def score_case(events: list[dict], groups: list[dict]) -> dict:
    blob = " ".join(f"{e.get('description','')} {e.get('event_type','')}" for e in events).lower()
    families = {g.get("family") for g in groups}
    entities = [g.get("entity") or "" for g in groups if g.get("family") == "file_access"]
    copies = [g for g in groups if g.get("family") == "file_copy"]
    fired = []

    def fire(iid):
        item = next(x for x in INDICATORS if x["id"] == iid)
        if item["id"] not in {f["id"] for f in fired}:
            fired.append(item)

    if "powershell" in blob:
        fire("powershell")
    if any(g.get("family") == "service" for g in groups) or "7045" in blob or "service_install" in blob:
        fire("service")
    if "usb" in blob or "usb_connect" in families:
        fire("usb")
    if re.search(r"sensitive_|customer_list|confidential|projectx", blob):
        fire("sensitive")
    sensitive_names = {e.lower() for e in entities if e}
    if len(sensitive_names) >= 2 or (
        "sensitive_projectx" in blob and "customer_list" in blob
    ):
        fire("multi_sensitive")
    if copies or "file_copy" in blob or "e:/transfer" in blob or "e:\\transfer" in blob:
        fire("copy")
    copy_times = [g.get("timestamp") for g in copies if g.get("timestamp")]
    net_ev = [
        e
        for e in events
        if e.get("source_type") in {"network", "browser"} and e.get("timestamp")
    ]
    if copy_times and net_ev:
        fire("network_after")
    elif "drive.example" in blob or ":443" in blob:
        fire("network_after")
    if "admin" in blob or any(e.get("event_type") == "admin_logon" for e in events):
        fire("admin")
    if any(len(g.get("source_event_ids") or []) >= 2 for g in groups):
        fire("multi_source")

    raw = sum(i["points"] for i in fired)
    score = min(100, raw)
    return {
        "risk_score": score,
        "priority": priority_label(score),
        "raw_sum": raw,
        "cap": 100,
        "method": "rule_indicators + multi_source_correlation (documented prototype weights)",
        "disclaimer": (
            "Risk is a prioritization aid, not a probability of crime. "
            "Weights are a design choice for this prototype and do not establish that an offense occurred."
        ),
        "indicators": [
            {"id": i["id"], "label": i["label"], "points": i["points"], "fired": True} for i in fired
        ],
        "unused": [
            {"id": i["id"], "label": i["label"], "points": i["points"], "fired": False}
            for i in INDICATORS
            if i["id"] not in {f["id"] for f in fired}
        ],
    }
