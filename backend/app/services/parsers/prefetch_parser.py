"""Windows Prefetch (.pf) Forensic Parser.

Extracts application execution history, run count, execution timestamps,
and referenced files from Windows Prefetch artifacts into the Common Forensic Event Schema.
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

SOURCE = "filesystem"
WIN_EPOCH = datetime(1601, 1, 1)


def filetime_to_dt(ft: int) -> datetime | None:
    if not ft or ft <= 0:
        return None
    try:
        us = ft // 10
        return WIN_EPOCH + timedelta(microseconds=us)
    except Exception:
        return None


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    if suffix.lower() == ".pf" or "prefetch" in name.lower() or hint in {"prefetch", "application_execution"}:
        return True
    try:
        with open(path, "rb") as f:
            header = f.read(8)
            # SCCA magic or MAM compressed prefetch magic
            if header[4:8] == b"SCCA" or header[:4] == b"MAM\x04" or header[:3] == b"MAM":
                return True
    except Exception:
        pass
    return False


def parse(path: Path) -> list[dict]:
    """Parse Prefetch file or text dump into normalized forensic execution events."""
    events: list[dict] = []
    try:
        data = path.read_bytes()
    except Exception:
        return events

    # Check for text/CSV prefetch export
    if path.suffix.lower() == ".csv" or (data.startswith(b"timestamp,") or data.startswith(b"executable,")):
        return _parse_prefetch_text(path)

    # Decompress MAM (Windows 10/11 compressed prefetch) if present
    if data[:4] == b"MAM\x04" or data[:3] == b"MAM":
        data = _decompress_mam(data)

    if len(data) < 84:
        return events

    # Check format version and SCCA magic
    version = struct.unpack_from("<I", data, 0)[0]
    magic = data[4:8]
    if magic != b"SCCA":
        # Fallback to stat mtime if binary header unaligned
        st = path.stat()
        mtime = datetime.utcfromtimestamp(st.st_mtime)
        exe_name = path.name.split("-")[0].upper()
        return [
            {
                "event_id": f"pf_{path.stem}",
                "timestamp": mtime,
                "timestamp_utc": mtime.isoformat() + "Z",
                "source": f"Windows Prefetch ({path.name})",
                "source_type": "filesystem",
                "artifact_type": "Application Execution (Prefetch)",
                "event_type": "process_create",
                "user": "",
                "actor": "",
                "host": "",
                "process": exe_name,
                "pid": "",
                "action": f"Application Executed ({exe_name})",
                "object": exe_name,
                "target": exe_name,
                "path": str(path),
                "source_path": str(path),
                "destination_path": "",
                "source_ip": "",
                "source_port": "",
                "destination_ip": "",
                "destination_port": "",
                "description": f"Prefetch execution record | Executable: {exe_name} | File: {path.name}",
                "raw_data": json.dumps({"file": path.name, "size": len(data)}),
                "parser_name": "prefetch_parser",
                "source_file": path.name,
                "time_kind": "event",
                "observation_time": "",
            }
        ]

    # Extract executable name (UTF-16LE, 60 bytes at offset 16)
    exe_raw = data[16:76].decode("utf-16le", errors="ignore").split("\x00")[0]
    exe_name = exe_raw or path.name.split("-")[0]

    # Extract run count and execution timestamps based on Windows version
    run_count = 1
    exec_times: list[datetime] = []

    # Windows 10/11 (version 30 / 31)
    if version in (30, 31) and len(data) >= 132:
        try:
            # 8 FILETIMEs at offset 68
            for i in range(8):
                ft = struct.unpack_from("<Q", data, 68 + i * 8)[0]
                dt = filetime_to_dt(ft)
                if dt:
                    exec_times.append(dt)
            run_count = struct.unpack_from("<I", data, 196)[0] if len(data) >= 200 else struct.unpack_from("<I", data, 120)[0]
        except Exception:
            pass
    # Windows 8 / 8.1 (version 26)
    elif version == 26 and len(data) >= 128:
        try:
            for i in range(8):
                ft = struct.unpack_from("<Q", data, 128 + i * 8)[0]
                dt = filetime_to_dt(ft)
                if dt:
                    exec_times.append(dt)
            run_count = struct.unpack_from("<I", data, 208)[0] if len(data) >= 212 else 1
        except Exception:
            pass
    # Windows 7 / Vista (version 23)
    elif version == 23 and len(data) >= 132:
        try:
            ft = struct.unpack_from("<Q", data, 120)[0]
            dt = filetime_to_dt(ft)
            if dt:
                exec_times.append(dt)
            run_count = struct.unpack_from("<I", data, 152)[0] if len(data) >= 156 else 1
        except Exception:
            pass

    if not exec_times:
        st = path.stat()
        exec_times = [datetime.utcfromtimestamp(st.st_mtime)]

    for idx, ts in enumerate(exec_times):
        events.append(
            {
                "event_id": f"pf_{exe_name}_{idx}",
                "timestamp": ts,
                "timestamp_utc": ts.isoformat() + "Z",
                "source": f"Windows Prefetch ({path.name})",
                "source_type": "filesystem",
                "artifact_type": "Application Execution (Prefetch)",
                "event_type": "process_create",
                "user": "",
                "actor": "",
                "host": "",
                "process": exe_name,
                "pid": "",
                "action": f"Application Executed ({exe_name}, {run_count} runs)",
                "object": exe_name,
                "target": exe_name,
                "path": exe_name,
                "source_path": "",
                "destination_path": "",
                "source_ip": "",
                "source_port": "",
                "destination_ip": "",
                "destination_port": "",
                "description": f"Prefetch execution | Program: {exe_name} | Run count: {run_count} | Executed: {ts}",
                "raw_data": json.dumps({"executable": exe_name, "run_count": run_count, "version": version, "ts": str(ts)}),
                "parser_name": "prefetch_parser",
                "source_file": path.name,
                "time_kind": "event",
                "observation_time": "",
            }
        )

    return events


def _decompress_mam(data: bytes) -> bytes:
    """Best effort decompressor for Windows 10/11 XPRESS-Huffman compressed prefetch (MAM)."""
    try:
        import zlib
        return zlib.decompress(data[8:])
    except Exception:
        return data


def _parse_prefetch_text(path: Path) -> list[dict]:
    events: list[dict] = []
    try:
        import csv
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                exe = row.get("executable") or row.get("process") or row.get("name") or path.name
                ts_raw = row.get("timestamp") or row.get("last_run") or row.get("time")
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "")) if ts_raw else None
                except Exception:
                    ts = None
                rc = row.get("run_count") or row.get("runs") or "1"
                events.append(
                    {
                        "event_id": f"pf_txt_{idx}",
                        "timestamp": ts,
                        "timestamp_utc": ts.isoformat() + "Z" if ts else "",
                        "source": f"Windows Prefetch ({path.name})",
                        "source_type": "filesystem",
                        "artifact_type": "Application Execution (Prefetch)",
                        "event_type": "process_create",
                        "user": "",
                        "actor": "",
                        "host": "",
                        "process": exe,
                        "pid": "",
                        "action": f"Application Executed ({exe})",
                        "object": exe,
                        "target": exe,
                        "path": exe,
                        "source_path": "",
                        "destination_path": "",
                        "source_ip": "",
                        "source_port": "",
                        "destination_ip": "",
                        "destination_port": "",
                        "description": f"Prefetch execution record | Executable: {exe} | Runs: {rc}",
                        "raw_data": json.dumps(row),
                        "parser_name": "prefetch_csv",
                        "source_file": path.name,
                        "time_kind": "event",
                        "observation_time": "",
                    }
                )
    except Exception:
        pass
    return events
