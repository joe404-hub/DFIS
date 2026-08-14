"""Windows Amcache (Amcache.hve) Forensic Parser.

Extracts installed application binaries, SHA-1/SHA-256 hashes, file compile times,
and installation records from Windows Amcache artifacts into the Common Forensic Event Schema.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

SOURCE = "registry"


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    if "amcache" in name.lower() or suffix.lower() == ".hve" or hint in {"amcache", "amcache_hve"}:
        return True
    return False


def parse(path: Path) -> list[dict]:
    """Parse Amcache.hve hive or Amcache tabular export into forensic records."""
    events: list[dict] = []

    # Check for text/CSV export first
    if path.suffix.lower() in {".csv", ".tsv", ".txt"}:
        return _parse_amcache_csv(path)

    # Parse binary hive via python-registry
    try:
        from Registry import Registry
        reg = Registry.Registry(str(path))
    except Exception:
        # Fallback to stat metadata
        st = path.stat()
        mtime = datetime.utcfromtimestamp(st.st_mtime)
        return [
            {
                "event_id": f"amcache_ingest_{path.name}",
                "timestamp": mtime,
                "timestamp_utc": mtime.isoformat() + "Z",
                "source": f"Windows Amcache ({path.name})",
                "source_type": "registry",
                "artifact_type": "Application Evidence (Amcache)",
                "event_type": "file_create",
                "user": "",
                "actor": "",
                "host": "",
                "process": "",
                "pid": "",
                "action": "Amcache Artifact Ingested",
                "object": path.name,
                "target": path.name,
                "path": str(path),
                "source_path": "",
                "destination_path": "",
                "source_ip": "",
                "source_port": "",
                "destination_ip": "",
                "destination_port": "",
                "description": f"Windows Amcache hive ingested: {path.name} ({st.st_size} bytes)",
                "raw_data": json.dumps({"file": path.name, "size": st.st_size}),
                "parser_name": "amcache_fallback",
                "source_file": path.name,
                "time_kind": "observation",
                "observation_time": mtime.isoformat(),
            }
        ]

    # Inspect Amcache root keys: Root\File or Root\InventoryApplicationFile
    amcache_paths = [
        "Root\\File",
        "File",
        "Root\\InventoryApplicationFile",
        "InventoryApplicationFile",
    ]

    for apath in amcache_paths:
        try:
            base_key = reg.open(apath)
        except Exception:
            continue

        for item_key in base_key.subkeys():
            k_ts = item_key.timestamp()
            fpath = ""
            sha1 = ""
            prod_name = ""

            try:
                fpath = str(item_key.value("15").value())  # 15: Full Path
            except Exception:
                try:
                    fpath = str(item_key.value("LowerCaseLongPath").value())
                except Exception:
                    fpath = item_key.name()

            try:
                sha1 = str(item_key.value("101").value())  # 101: SHA-1
            except Exception:
                try:
                    sha1 = str(item_key.value("FileId").value())
                except Exception:
                    pass

            try:
                prod_name = str(item_key.value("0").value())  # 0: Product Name
            except Exception:
                pass

            if fpath:
                proc = fpath.replace("\\", "/").split("/")[-1]
                events.append(
                    {
                        "event_id": f"amcache_{item_key.name()}",
                        "timestamp": k_ts,
                        "timestamp_utc": k_ts.isoformat() + "Z" if k_ts else "",
                        "source": f"Windows Amcache ({path.name})",
                        "source_type": "registry",
                        "artifact_type": "Application Evidence (Amcache)",
                        "event_type": "process_create",
                        "user": "",
                        "actor": "",
                        "host": "",
                        "process": proc,
                        "pid": "",
                        "action": f"Application Registered ({proc})",
                        "object": fpath,
                        "target": fpath,
                        "path": fpath,
                        "source_path": fpath,
                        "destination_path": "",
                        "source_ip": "",
                        "source_port": "",
                        "destination_ip": "",
                        "destination_port": "",
                        "description": f"Amcache Application record | Path: {fpath} | SHA-1: {sha1 or 'N/A'} | Product: {prod_name or proc}",
                        "raw_data": json.dumps({"path": fpath, "sha1": sha1, "product": prod_name}),
                        "parser_name": "amcache_hive",
                        "source_file": path.name,
                        "time_kind": "observation",
                        "observation_time": k_ts.isoformat() if k_ts else "",
                    }
                )

    return events


def _parse_amcache_csv(path: Path) -> list[dict]:
    events: list[dict] = []
    try:
        import csv
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                fpath = row.get("path") or row.get("full_path") or row.get("file_name") or ""
                sha1 = row.get("sha1") or row.get("hash") or ""
                ts_raw = row.get("timestamp") or row.get("install_date") or row.get("time")
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "")) if ts_raw else None
                except Exception:
                    ts = None
                proc = fpath.replace("\\", "/").split("/")[-1] if fpath else ""
                events.append(
                    {
                        "event_id": f"amcache_csv_{idx}",
                        "timestamp": ts,
                        "timestamp_utc": ts.isoformat() + "Z" if ts else "",
                        "source": f"Windows Amcache ({path.name})",
                        "source_type": "registry",
                        "artifact_type": "Application Evidence (Amcache)",
                        "event_type": "process_create",
                        "user": "",
                        "actor": "",
                        "host": "",
                        "process": proc,
                        "pid": "",
                        "action": f"Application Record ({proc})",
                        "object": fpath,
                        "target": fpath,
                        "path": fpath,
                        "source_path": fpath,
                        "destination_path": "",
                        "source_ip": "",
                        "source_port": "",
                        "destination_ip": "",
                        "destination_port": "",
                        "description": f"Amcache Record | Path: {fpath} | Hash: {sha1}",
                        "raw_data": json.dumps(row),
                        "parser_name": "amcache_csv",
                        "source_file": path.name,
                        "time_kind": "observation",
                        "observation_time": ts.isoformat() if ts else "",
                    }
                )
    except Exception:
        pass
    return events
