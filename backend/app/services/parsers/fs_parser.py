"""Filesystem & MFT Forensic Parser."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

SOURCE = "filesystem"


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    if hint in {"filesystem", "mft"}:
        return True
    return suffix in {".mft", ".bodyfile"} or (suffix == ".csv" and ("mft" in name.lower() or "filesystem" in name.lower()))


def parse(path: Path) -> list[dict]:
    events: list[dict] = []
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                ts = None
                for k in ("timestamp", "mtime", "created", "time", "modified", "accessed"):
                    if row.get(k):
                        try:
                            ts = datetime.fromisoformat(row[k].replace("Z", ""))
                            break
                        except Exception:
                            ts = None
                ts_utc = ts.isoformat() + "Z" if ts else ""
                target_path = row.get("path") or row.get("name") or row.get("filename") or ""
                actor = row.get("actor") or row.get("user") or ""
                et = row.get("event_type") or "file_meta"

                events.append(
                    {
                        "event_id": f"fs_{idx}",
                        "timestamp": ts,
                        "timestamp_utc": ts_utc,
                        "source": f"Filesystem ({path.name})",
                        "source_type": SOURCE,
                        "artifact_type": "Filesystem Activity",
                        "event_type": et,
                        "user": actor,
                        "actor": actor,
                        "host": "",
                        "process": "",
                        "pid": "",
                        "action": et.replace("_", " ").title(),
                        "object": target_path,
                        "target": target_path,
                        "path": target_path,
                        "source_path": target_path,
                        "destination_path": "",
                        "source_ip": "",
                        "source_port": "",
                        "destination_ip": "",
                        "destination_port": "",
                        "description": row.get("description") or f"File {target_path}",
                        "raw_data": json.dumps(row, default=str),
                        "parser_name": "fs_csv",
                        "source_file": path.name,
                        "time_kind": "event",
                        "observation_time": "",
                    }
                )
        return events

    # Binary/stat metadata
    st = path.stat()
    mtime = datetime.utcfromtimestamp(st.st_mtime)
    events.append(
        {
            "event_id": "fs_stat",
            "timestamp": mtime,
            "timestamp_utc": mtime.isoformat() + "Z",
            "source": f"Filesystem ({path.name})",
            "source_type": SOURCE,
            "artifact_type": "File Metadata",
            "event_type": "file_meta",
            "user": "",
            "actor": "",
            "host": "",
            "process": "",
            "pid": "",
            "action": "File Metadata Recorded",
            "object": path.name,
            "target": path.name,
            "path": str(path),
            "source_path": str(path),
            "destination_path": "",
            "source_ip": "",
            "source_port": "",
            "destination_ip": "",
            "destination_port": "",
            "description": f"File metadata for {path.name} | Size: {st.st_size} bytes | Modified: {mtime}",
            "raw_data": json.dumps({"size": st.st_size, "mtime": st.st_mtime, "ctime": st.st_ctime}),
            "parser_name": "fs_stat",
            "source_file": path.name,
            "time_kind": "observation",
            "observation_time": mtime.isoformat(),
        }
    )
    return events
