import json
from datetime import datetime
from pathlib import Path
from dateutil import parser as dtp

SOURCE = "structured"


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    return suffix in {".json", ".ndjson"} and "chrome" not in name


def _ts(value):
    if not value:
        return None
    if isinstance(value, (int, float)):
        # chrome-like or unix
        if value > 10**14:
            return datetime.utcfromtimestamp(value / 1_000_000 - 11644473600)
        if value > 10**11:
            return datetime.utcfromtimestamp(value / 1000)
        return datetime.utcfromtimestamp(value)
    try:
        return dtp.parse(str(value))
    except Exception:
        return None


def parse(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    data = json.loads(text)
    rows = data if isinstance(data, list) else data.get("events") or data.get("artifacts") or [data]
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append(
            {
                "source_type": row.get("source_type") or row.get("source") or "structured",
                "event_type": row.get("event_type") or row.get("type") or "event",
                "timestamp": _ts(row.get("timestamp") or row.get("time")),
                "description": row.get("description") or json.dumps(row)[:500],
                "actor": str(row.get("actor") or row.get("user") or ""),
                "target": str(row.get("target") or row.get("object") or ""),
                "raw_data": json.dumps(row)[:4000],
            }
        )
    return out
