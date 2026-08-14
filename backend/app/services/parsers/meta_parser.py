"""Document & Media Metadata Parser."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

SOURCE = "metadata"


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    if hint in {"metadata", "document_metadata"}:
        return True
    return suffix in {".jpg", ".jpeg", ".png", ".docx", ".pdf", ".xlsx", ".pptx"}


def parse(path: Path) -> list[dict]:
    st = path.stat()
    mtime = datetime.utcfromtimestamp(st.st_mtime)
    ts_utc = mtime.isoformat() + "Z"
    return [
        {
            "event_id": "doc_meta",
            "timestamp": mtime,
            "timestamp_utc": ts_utc,
            "source": f"Metadata ({path.name})",
            "source_type": SOURCE,
            "artifact_type": "Document Metadata",
            "event_type": "file_metadata",
            "user": "",
            "actor": "",
            "host": "",
            "process": "",
            "pid": "",
            "action": "Metadata Ingested",
            "object": path.name,
            "target": path.name,
            "path": str(path),
            "source_path": "",
            "destination_path": "",
            "source_ip": "",
            "source_port": "",
            "destination_ip": "",
            "destination_port": "",
            "description": f"Metadata for {path.name} ({path.suffix}, {st.st_size} bytes)",
            "raw_data": json.dumps({"size": st.st_size, "mtime": st.st_mtime}),
            "parser_name": "meta_parser",
            "source_file": path.name,
            "time_kind": "observation",
            "observation_time": ts_utc,
        }
    ]
