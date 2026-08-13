from datetime import datetime
from pathlib import Path

SOURCE = "metadata"


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    return suffix in {".jpg", ".jpeg", ".png", ".docx", ".pdf", ".xlsx"}


def parse(path: Path) -> list[dict]:
    st = path.stat()
    return [
        {
            "source_type": SOURCE,
            "event_type": "file_metadata",
            "timestamp": datetime.utcfromtimestamp(st.st_mtime),
            "description": f"Metadata for {path.name} ({path.suffix}, {st.st_size} bytes)",
            "actor": "",
            "target": path.name,
            "raw_data": f"mtime={st.st_mtime}",
        }
    ]
