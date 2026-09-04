"""Unified Forensic Timeline Normalization, Deduplication & Correlation Engine.

Transforms disparate forensic events into a unified chronological sequence,
computes deterministic cryptographic fingerprints for deduplication,
and correlates multi-source corroborating evidence.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def normalize_ts(dt: datetime | None) -> datetime | None:
    """Normalize datetime object, preserving wall-clock values."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt


def fingerprint(ev: dict[str, Any]) -> str:
    """Generate deterministic SHA-256 fingerprint for forensic event deduplication."""
    ts_str = str(ev.get("timestamp") or "")
    if isinstance(ev.get("timestamp"), datetime):
        ts_str = ev["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

    key_parts = [
        str(ev.get("source_type") or "").strip().lower(),
        str(ev.get("event_type") or "").strip().lower(),
        ts_str,
        str(ev.get("user") or ev.get("actor") or "").strip().lower(),
        str(ev.get("target") or ev.get("object") or "").strip().lower(),
        str(ev.get("process") or "").strip().lower(),
        str(ev.get("description") or "")[:180].strip().lower(),
    ]
    key = "|".join(key_parts)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _entity(ev: dict[str, Any]) -> str:
    """Extract primary forensic entity (filename, domain, device, IP) from event."""
    blob = " ".join(
        str(ev.get(k) or "")
        for k in ("source_path", "destination_path", "target", "object", "process", "description")
    )
    # Match sensitive filenames
    m_file = re.search(r"([A-Za-z0-9._-]+\.(?:xlsx|csv|docx|zip|exe|env|txt|pdf|log))", blob, re.I)
    if m_file:
        return m_file.group(1).lower()

    fam = _family(ev)
    if fam in {"usb_connect", "usb_remove", "usb_history"}:
        m_usb = re.search(r"(sandisk|kingston|corsair|cruzer|ultra|usb[a-z0-9_-]+)", blob, re.I)
        if m_usb:
            return m_usb.group(1).lower()
        return "removable_media"

    if fam == "service" or "demoupdater" in blob.lower():
        return "demoupdater"

    m_domain = re.search(r"([a-z0-9.-]+\.(?:com|corp|local|net|org|io))", blob, re.I)
    if m_domain:
        return m_domain.group(1).lower()

    if ev.get("destination_ip"):
        return f"{ev.get('destination_ip')}:{ev.get('destination_port') or ''}".rstrip(":")

    return ""


def _family(ev: dict[str, Any]) -> str:
    """Determine high-level activity family for correlation grouping."""
    et = (ev.get("event_type") or "").lower()
    art = (ev.get("artifact_type") or "").lower()

    if et in {"usb_connect", "usb_history", "usb_inserted", "usb_device_connected"} or "usb" in art:
        return "usb_connect"
    if et in {"usb_remove", "usb_device_removed"}:
        return "usb_remove"
    if et in {"file_access", "recent_docs", "file_open", "object_access"} or "recent" in art:
        return "file_access"
    if et in {"file_copy", "file_staged"} or "copy" in et:
        return "file_copy"
    if et in {"network_flow", "cookie", "url_visit", "dns_query", "http_request"} or "network" in art or "browser" in art:
        return "network"
    if et in {"service_install", "persistence", "service_state"} or "service" in art or "persistence" in art:
        return "service"
    if et in {"process_create", "process_list", "powershell_script", "powershell_module"} or "process" in art:
        return "process"
    if et in {"logon", "failed_logon", "admin_logon", "logoff"}:
        return "authentication"

    return et


def correlate(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Correlate multi-source events into analytical links without mutating raw evidence."""
    indexed: list[dict[str, Any]] = []
    for ev in events:
        ev_copy = dict(ev)
        ev_copy["entity"] = _entity(ev_copy)
        ev_copy["family"] = _family(ev_copy)
        indexed.append(ev_copy)

    used: set[int] = set()
    extras: list[dict[str, Any]] = []

    for i, a in enumerate(indexed):
        if i in used:
            continue
        if not a.get("timestamp") or not a.get("entity") or a.get("source_type") == "correlated":
            continue

        group = [a]
        for j, b in enumerate(indexed):
            if i == j or j in used:
                continue
            if not b.get("timestamp") or b.get("source_type") == "correlated":
                continue
            if a["family"] != b["family"] and not (
                (a["family"] == "usb_connect" and b["family"] in {"file_copy", "usb_remove", "usb_connect"})
                or (a["family"] in {"usb_connect", "usb_remove"} and b["family"] == "file_copy")
                or (a["family"] == "file_copy" and b["family"] in {"usb_connect", "usb_remove", "file_access"})
                or (a["family"] == "file_access" and b["family"] == "file_copy")
            ):
                continue
            if a["entity"] != b["entity"] and a["family"] not in {"usb_connect", "usb_remove"}:
                continue
            if a.get("source_type") == b.get("source_type") and a.get("event_type") == b.get("event_type") and a.get("description") == b.get("description"):
                continue

            delta = abs((a["timestamp"] - b["timestamp"]).total_seconds())
            if delta <= 900:  # 15-minute temporal window for multi-source correlation
                group.append(b)
                used.add(j)

        if len(group) < 2:
            continue

        used.add(i)
        cid = hashlib.sha1(f"{a['family']}|{a['entity']}|{a['timestamp']}".encode()).hexdigest()[:12]
        sources = []
        for g in group:
            g["correlation_id"] = cid
            sources.append(f"{g.get('source_type')}/{g.get('event_type')} ({g.get('source_file') or 'artifact'})")

        times = [g["timestamp"] for g in group if g.get("timestamp")]
        min_time = min(times) if times else datetime.utcnow()
        actor = next((g.get("actor") or g.get("user") for g in group if (g.get("actor") or g.get("user"))), "")

        src_p = next((g.get("source_path") for g in group if g.get("source_path")), "")
        dst_p = next((g.get("destination_path") for g in group if g.get("destination_path")), "")

        correlated_row = {
            "event_id": f"corr_{cid}",
            "timestamp": min_time,
            "timestamp_utc": min_time.isoformat() + "Z",
            "source": "Cross-Artifact Correlator",
            "source_type": "correlated",
            "artifact_type": "Correlated Activity Group",
            "event_type": "CORRELATED_ACTIVITY",
            "user": actor,
            "actor": actor,
            "host": next((g.get("host") for g in group if g.get("host")), ""),
            "process": next((g.get("process") for g in group if g.get("process")), ""),
            "pid": "",
            "action": f"Multi-Source Correlation: {a['family'].replace('_', ' ').title()}",
            "object": a["entity"],
            "target": a["entity"],
            "path": dst_p or src_p or a["entity"],
            "source_path": src_p,
            "destination_path": dst_p,
            "source_ip": next((g.get("source_ip") for g in group if g.get("source_ip")), ""),
            "source_port": next((g.get("source_port") for g in group if g.get("source_port")), ""),
            "destination_ip": next((g.get("destination_ip") for g in group if g.get("destination_ip")), ""),
            "destination_port": next((g.get("destination_port") for g in group if g.get("destination_port")), ""),
            "description": (
                f"CORRELATED_ACTIVITY | {a['family']} | {a['entity']} | "
                f"independent sources: {'; '.join(dict.fromkeys(sources))}"
            ),
            "evidence_hash": "",
            "fingerprint": fingerprint({
                "source_type": "correlated",
                "event_type": cid,
                "timestamp": min_time,
                "description": a["entity"],
                "target": a["entity"],
            }),
            "correlation_id": cid,
            "raw_data": "",
            "parser_name": "correlator",
            "source_file": "cross-artifact",
            "time_kind": "event",
            "observation_time": "",
        }
        extras.append(correlated_row)

    out = indexed + extras
    out.sort(key=lambda e: e.get("timestamp") or datetime.min)
    return out


def build_timeline(raw_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize timestamps, deduplicate events, and execute cross-artifact correlation."""
    seen: set[str] = set()
    out: list[dict[str, Any]] = []

    for ev in raw_events:
        ev_norm = dict(ev)
        ev_norm["timestamp"] = normalize_ts(ev_norm.get("timestamp"))
        if ev_norm.get("timestamp") and not ev_norm.get("timestamp_utc"):
            ev_norm["timestamp_utc"] = ev_norm["timestamp"].isoformat() + "Z"

        fp = ev_norm.get("fingerprint") or fingerprint(ev_norm)
        ev_norm["fingerprint"] = fp

        if fp in seen:
            continue
        seen.add(fp)
        out.append(ev_norm)

    out.sort(key=lambda e: e["timestamp"] or datetime.min)
    return correlate(out)
