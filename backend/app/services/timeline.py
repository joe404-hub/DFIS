import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path


def normalize_ts(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        # Keep investigator wall-clock from the evidence (CASE001 is +05:30)
        return dt.replace(tzinfo=None)
    return dt


def fingerprint(ev: dict) -> str:
    key = "|".join(
        [
            str(ev.get("source_type") or ""),
            str(ev.get("event_type") or ""),
            str(ev.get("timestamp") or ""),
            str(ev.get("description") or "")[:200],
            str(ev.get("target") or ""),
            str(ev.get("source_file") or ""),
        ]
    )
    return hashlib.sha256(key.encode()).hexdigest()


def _entity(ev: dict) -> str:
    blob = " ".join(
        str(ev.get(k) or "")
        for k in ("source_path", "destination_path", "target", "process", "description")
    )
    m = re.search(r"([A-Za-z0-9._-]+\.(?:xlsx|csv|docx|zip|exe|env|txt))", blob, re.I)
    if m:
        return m.group(1).lower()
    fam = _family(ev)
    if fam in {"usb_connect", "usb_remove"}:
        return "removable_media"
    if fam == "service" or "demoupdater" in blob.lower():
        return "demoupdater"
    m = re.search(r"(drive\.[a-z0-9.-]+)", blob, re.I)
    if m:
        return m.group(1).lower()
    if ev.get("destination_ip"):
        return f"{ev.get('destination_ip')}:{ev.get('destination_port') or ''}".rstrip(":")
    return ""


def _family(ev: dict) -> str:
    et = (ev.get("event_type") or "").lower()
    if et in {"usb_connect", "usb_history"}:
        return "usb_connect"
    if et == "usb_remove":
        return "usb_remove"
    if et in {"file_access", "recent_docs"}:
        return "file_access"
    if et == "file_copy":
        return "file_copy"
    if et in {"network_flow", "cookie", "url_visit", "dns_query"}:
        return "network"
    if et in {"service_install", "persistence"}:
        return "service"
    if et in {"process_create", "process_list"}:
        return "process"
    return et


def correlate(events: list[dict]) -> list[dict]:
    """Keep raw events and add CORRELATED_ACTIVITY rows when sources agree."""
    indexed = []
    for ev in events:
        ev = dict(ev)
        ev["entity"] = _entity(ev)
        ev["family"] = _family(ev)
        indexed.append(ev)

    used = set()
    extras = []
    for i, a in enumerate(indexed):
        if i in used:
            continue
        if not a.get("timestamp") or not a.get("entity"):
            continue
        group = [a]
        for j, b in enumerate(indexed):
            if i == j or j in used:
                continue
            if not b.get("timestamp"):
                continue
            if a["family"] != b["family"]:
                continue
            if a["entity"] != b["entity"]:
                continue
            if a.get("source_type") == b.get("source_type"):
                continue
            delta = abs((a["timestamp"] - b["timestamp"]).total_seconds())
            if delta <= 180:
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
        times = [g["timestamp"] for g in group]
        extras.append(
            {
                "source_type": "correlated",
                "event_type": "CORRELATED_ACTIVITY",
                "timestamp": min(times),
                "description": (
                    f"CORRELATED_ACTIVITY | {a['family']} | {a['entity']} | "
                    f"independent sources: {'; '.join(dict.fromkeys(sources))}"
                ),
                "actor": next((g.get("actor") for g in group if g.get("actor")), ""),
                "target": a["entity"],
                "raw_data": "",
                "fingerprint": fingerprint({"source_type": "correlated", "event_type": cid, "timestamp": min(times), "description": a["entity"], "target": a["entity"]}),
                "parser_name": "correlator",
                "source_file": "cross-artifact",
                "correlation_id": cid,
                "source_path": next((g.get("source_path") for g in group if g.get("source_path")), ""),
                "destination_path": next((g.get("destination_path") for g in group if g.get("destination_path")), ""),
            }
        )
    out = indexed + extras
    out.sort(key=lambda e: e.get("timestamp") or datetime.min)
    return out


def build_timeline(raw_events: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for ev in raw_events:
        ev = dict(ev)
        ev["timestamp"] = normalize_ts(ev.get("timestamp"))
        fp = ev.get("fingerprint") or fingerprint(ev)
        ev["fingerprint"] = fp
        if fp in seen:
            continue
        seen.add(fp)
        out.append(ev)
    out.sort(key=lambda e: e["timestamp"] or datetime.min)
    return correlate(out)
