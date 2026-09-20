"""JSON & NDJSON Structured Forensic Parser."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from dateutil import parser as dtp

SOURCE = "structured"


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    if name in {"case_manifest.json"} or "manifest" in name:
        return False
    if hint in {"json", "structured"}:
        return True
    return suffix in {".json", ".ndjson"} and "chrome" not in name.lower()


def _ts(value: Any) -> tuple[datetime | None, str]:
    if not value:
        return None, ""
    if isinstance(value, (int, float)):
        if value > 10**14:
            dt = datetime.utcfromtimestamp(value / 1_000_000 - 11644473600)
            return dt, dt.isoformat() + "Z"
        if value > 10**11:
            dt = datetime.utcfromtimestamp(value / 1000)
            return dt, dt.isoformat() + "Z"
        dt = datetime.utcfromtimestamp(value)
        return dt, dt.isoformat() + "Z"
    try:
        dt = dtp.parse(str(value))
        return (dt.replace(tzinfo=None) if dt.tzinfo else dt), dt.isoformat()
    except Exception:
        return None, ""


def parse(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        data = json.loads(text)
    except Exception:
        # Try NDJSON
        data = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    data.append(json.loads(line))
                except Exception:
                    pass

    rows = data if isinstance(data, list) else data.get("events") or data.get("artifacts") or [data]
    out: list[dict] = []
    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        ts, ts_utc = _ts(row.get("timestamp") or row.get("time") or row.get("timestamp_utc"))
        src_type = row.get("source_type") or row.get("source") or "structured"
        event_type = row.get("event_type") or row.get("type") or "event"
        actor = str(row.get("user") or row.get("actor") or "")
        target = str(row.get("target") or row.get("object") or "")

        out.append(
            {
                "event_id": str(row.get("event_id") or f"json_{idx}"),
                "timestamp": ts,
                "timestamp_utc": ts_utc,
                "source": f"{src_type.replace('_', ' ').title()} ({path.name})",
                "source_type": src_type,
                "artifact_type": row.get("artifact_type") or src_type.title(),
                "event_type": event_type,
                "user": actor,
                "actor": actor,
                "host": str(row.get("host") or ""),
                "process": str(row.get("process") or ""),
                "pid": str(row.get("pid") or ""),
                "action": str(row.get("action") or event_type.replace("_", " ").title()),
                "object": target,
                "target": target,
                "path": str(row.get("path") or ""),
                "source_path": str(row.get("source_path") or ""),
                "destination_path": str(row.get("destination_path") or ""),
                "source_ip": str(row.get("source_ip") or ""),
                "source_port": str(row.get("source_port") or ""),
                "destination_ip": str(row.get("destination_ip") or ""),
                "destination_port": str(row.get("destination_port") or ""),
                "description": row.get("description") or json.dumps(row)[:300],
                "raw_data": json.dumps(row)[:4000],
                "parser_name": "json_parser",
                "source_file": path.name,
                "time_kind": row.get("time_kind") or "event",
                "observation_time": row.get("observation_time") or "",
            }
        )
    return out
