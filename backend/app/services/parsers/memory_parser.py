"""Memory Image & Volatility Dump Forensic Parser.

Extracts running processes, network connections, command lines, and injected code
from memory snapshots and Volatility outputs into the Common Forensic Event Schema.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from .csv_util import parse_ts

SOURCE = "memory"

PROC_RE = re.compile(
    r"^(?:[-*]\s*)?(?P<proc>[^\s|]+)\s*\|\s*PID\s*(?P<pid>\d+)\s*\|\s*(?:User\s+)?(?P<user>.+)$",
    re.I,
)
PROC_ALT_RE = re.compile(r"^(?:[-*]\s*)?Process:\s*(?P<proc>[^\s|]+)\s*(?:\|\s*)?(?:PID:\s*(?P<pid>\d+))?", re.I)
PIPE_EVENT_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s*\|\s*(?P<etype>[^|]+)\s*\|\s*(?P<desc>.+)$",
    re.I,
)
NET_RE = re.compile(
    r"^(?:[-*]\s*)?(?P<src>\d+\.\d+\.\d+\.\d+):(?P<sport>\d+)\s*(?:->|→)\s*(?P<dst>\d+\.\d+\.\d+\.\d+):(?P<dport>\d+)"
)


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    parent = path.parent.name.lower()
    if hint in {"memory", "memory_dump", "memory_text"}:
        return True
    if "memory" in name.lower() or parent == "memory" or name.lower().endswith(".raw.txt") or suffix in {".dmp", ".raw", ".vmem"}:
        return True
    return False


def parse(path: Path) -> list[dict]:
    """Parse memory dump text / Volatility table into forensic observation events."""
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        try:
            text = path.read_text(encoding="latin1", errors="replace")
        except Exception:
            return []

    events: list[dict] = []
    captured_dt: datetime | None = None
    captured_iso = ""

    lines = text.splitlines()
    for line_idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line:
            continue
        line_low = line.lower()

        # Capture timestamp header
        if line_low.startswith("captured:") or "captured at:" in line_low:
            val = line.split(":", 1)[1].strip()
            captured_dt = parse_ts(val)
            if captured_dt:
                captured_iso = captured_dt.isoformat()
            continue

        if line_low.startswith("case:") or line_low.startswith("note:") or line_low in {"processes:", "network:", "processes", "network"}:
            continue
        if "not a real memory" in line_low or line_low.startswith("synthetic memory snapshot"):
            continue

        # 1. Pipe-formatted event: timestamp | event_type | description
        m_pipe = PIPE_EVENT_RE.match(line)
        if m_pipe:
            ts_parsed = parse_ts(m_pipe.group("ts"))
            et = m_pipe.group("etype").strip().lower()
            desc = m_pipe.group("desc").strip()
            proc_match = re.search(r"([a-zA-Z0-9._-]+\.exe)", desc, re.I)
            pid_match = re.search(r"pid[=:\s]+(\d+)", desc, re.I)
            proc_name = proc_match.group(1) if proc_match else ""
            pid_str = pid_match.group(1) if pid_match else ""

            events.append(
                {
                    "event_id": f"mem_ev_{line_idx}",
                    "timestamp": ts_parsed or captured_dt,
                    "timestamp_utc": (ts_parsed or captured_dt).isoformat() if (ts_parsed or captured_dt) else "",
                    "source": f"Memory Snapshot ({path.name})",
                    "source_type": SOURCE,
                    "artifact_type": "Memory Event",
                    "event_type": et if et in {"process_create", "network_flow", "logon"} else "process_create",
                    "user": "analyst",
                    "actor": "analyst",
                    "host": "",
                    "process": proc_name,
                    "pid": pid_str,
                    "action": f"Memory Event: {et}",
                    "object": proc_name or desc,
                    "target": proc_name or desc,
                    "path": proc_name,
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": desc,
                    "raw_data": json.dumps({"line": line}),
                    "parser_name": "memory_pipe",
                    "source_file": path.name,
                    "time_kind": "observation",
                    "observation_time": (ts_parsed or captured_dt).isoformat() if (ts_parsed or captured_dt) else "",
                }
            )
            continue

        # 2. Process line: explorer.exe | PID 4120 | User analyst
        m_proc = PROC_RE.match(line)
        if m_proc:
            proc = m_proc.group("proc")
            pid = m_proc.group("pid")
            user = m_proc.group("user").strip()
            et = "process_create" if any(k in proc.lower() for k in ("powershell", "updater", "cmd", "rundll")) else "process_list"

            events.append(
                {
                    "event_id": f"mem_proc_{pid}",
                    "timestamp": captured_dt,
                    "timestamp_utc": captured_iso,
                    "source": f"Memory Snapshot ({path.name})",
                    "source_type": SOURCE,
                    "artifact_type": "Memory Process List",
                    "event_type": et,
                    "user": user,
                    "actor": user,
                    "host": "",
                    "process": proc,
                    "pid": pid,
                    "action": f"Active Process ({proc})",
                    "object": proc,
                    "target": proc,
                    "path": proc,
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"Memory process snapshot | Process: {proc} | PID: {pid} | User: {user}",
                    "raw_data": json.dumps({"process": proc, "pid": pid, "user": user, "observation_time": captured_iso}),
                    "parser_name": "memory_proc",
                    "source_file": path.name,
                    "time_kind": "observation",
                    "observation_time": captured_iso,
                }
            )
            continue

        # 3. Simple Process line: Process: powershell.exe | PID: 4420
        m_alt = PROC_ALT_RE.match(line)
        if m_alt:
            proc = m_alt.group("proc")
            pid = m_alt.group("pid") or ""
            events.append(
                {
                    "event_id": f"mem_alt_{line_idx}",
                    "timestamp": captured_dt,
                    "timestamp_utc": captured_iso,
                    "source": f"Memory Snapshot ({path.name})",
                    "source_type": SOURCE,
                    "artifact_type": "Memory Process",
                    "event_type": "process_create" if "powershell" in proc.lower() else "process_list",
                    "user": "",
                    "actor": "",
                    "host": "",
                    "process": proc,
                    "pid": pid,
                    "action": f"Process in Memory ({proc})",
                    "object": proc,
                    "target": proc,
                    "path": proc,
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"Memory process observation | Process: {proc} {f'PID: {pid}' if pid else ''}",
                    "raw_data": json.dumps({"process": proc, "pid": pid}),
                    "parser_name": "memory_alt",
                    "source_file": path.name,
                    "time_kind": "observation",
                    "observation_time": captured_iso,
                }
            )
            continue

        # 4. Network connection line: 10.0.0.25:51520 -> 10.0.0.50:443
        m_net = NET_RE.search(line)
        if m_net:
            src = m_net.group("src")
            sport = m_net.group("sport")
            dst = m_net.group("dst")
            dport = m_net.group("dport")

            events.append(
                {
                    "event_id": f"mem_net_{line_idx}",
                    "timestamp": captured_dt,
                    "timestamp_utc": captured_iso,
                    "source": f"Memory Network ({path.name})",
                    "source_type": SOURCE,
                    "artifact_type": "Memory Network Connection",
                    "event_type": "network_flow",
                    "user": "",
                    "actor": src,
                    "host": "",
                    "process": "",
                    "pid": "",
                    "action": "Active Network Connection in Memory",
                    "object": f"{dst}:{dport}",
                    "target": f"{dst}:{dport}",
                    "path": "",
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": src,
                    "source_port": sport,
                    "destination_ip": dst,
                    "destination_port": dport,
                    "description": f"Memory network socket | {src}:{sport} → {dst}:{dport}",
                    "raw_data": json.dumps({"src": src, "sport": sport, "dst": dst, "dport": dport, "observation_time": captured_iso}),
                    "parser_name": "memory_net",
                    "source_file": path.name,
                    "time_kind": "observation",
                    "observation_time": captured_iso,
                }
            )

    return events
