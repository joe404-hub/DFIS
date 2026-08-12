import os
from datetime import datetime
from pathlib import Path

SOURCE = "filesystem"


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    return suffix in {".mft", ".csv"} and ("mft" in name or "files" in name or "fs" in name)


def parse(path: Path) -> list[dict]:
    events = []
    if path.suffix.lower() == ".csv":
        import csv

        with path.open(newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ts = None
                for k in ("timestamp", "mtime", "created", "time"):
                    if row.get(k):
                        try:
                            ts = datetime.fromisoformat(row[k].replace("Z", ""))
                        except Exception:
                            ts = None
                        break
                events.append(
                    {
                        "source_type": SOURCE,
                        "event_type": row.get("event_type") or "file_meta",
                        "timestamp": ts,
                        "description": row.get("description") or f"File {row.get('path') or row.get('name')}",
                        "actor": row.get("actor") or "",
                        "target": row.get("path") or row.get("name") or "",
                        "raw_data": str(row)[:2000],
                    }
                )
        return events
    st = path.stat()
    events.append(
        {
            "source_type": SOURCE,
            "event_type": "file_meta",
            "timestamp": datetime.utcfromtimestamp(st.st_mtime),
            "description": f"File metadata for {path.name} size={st.st_size}",
            "actor": "",
            "target": path.name,
            "raw_data": "",
        }
    )
    return events
