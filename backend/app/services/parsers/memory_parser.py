import json
import re
from pathlib import Path

from .csv_util import parse_ts

SOURCE = "memory"

PROC_RE = re.compile(
    r"^[-*]\s*(?P<proc>[^\s|]+)\s*\|\s*PID\s*(?P<pid>\d+)\s*\|\s*User\s+(?P<user>.+)$",
    re.I,
)
NET_RE = re.compile(
    r"^(?:[-*]\s*)?(?P<src>\d+\.\d+\.\d+\.\d+):(?P<sport>\d+)\s*->\s*(?P<dst>\d+\.\d+\.\d+\.\d+):(?P<dport>\d+)"
)


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    parent = path.parent.name.lower()
    return "memory" in name or parent == "memory" or name.endswith(".raw.txt")


def parse(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    events = []
    captured = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "not a real memory" in line.lower() or line.lower().startswith("synthetic memory"):
            continue
        if line.lower().startswith("captured:"):
            captured = parse_ts(line.split(":", 1)[1].strip())
            continue
        if line.lower().startswith("case:") or line.lower().startswith("note:") or line.lower().rstrip(":") in {
            "processes",
            "network",
        }:
            continue
        m = PROC_RE.match(line)
        if m:
            proc = m.group("proc")
            et = "process_create" if "powershell" in proc.lower() or "updater" in proc.lower() else "process_list"
            events.append(
                {
                    "source_type": SOURCE,
                    "event_type": et,
                    "timestamp": captured,
                    "description": (
                        f"Synthetic memory process list | Process: {proc} | PID: {m.group('pid')} | "
                        f"User: {m.group('user')} | observation_time={captured} (snapshot, not start time)"
                    ),
                    "actor": m.group("user"),
                    "target": proc,
                    "process": proc,
                    "pid": m.group("pid"),
                    "raw_data": json.dumps({"line": line, "synthetic": True}),
                    "parser_name": "memory_text",
                    "source_file": path.name,
                    "time_kind": "observation",
                    "observation_time": captured.isoformat() if captured else "",
                }
            )
            continue
        n = NET_RE.search(line)
        if n:
            events.append(
                {
                    "source_type": SOURCE,
                    "event_type": "network_flow",
                    "timestamp": captured,
                    "description": (
                        f"Synthetic memory network | {n.group('src')}:{n.group('sport')} → "
                        f"{n.group('dst')}:{n.group('dport')} | observation_time={captured}"
                    ),
                    "actor": n.group("src"),
                    "target": f"{n.group('dst')}:{n.group('dport')}",
                    "source_ip": n.group("src"),
                    "source_port": n.group("sport"),
                    "destination_ip": n.group("dst"),
                    "destination_port": n.group("dport"),
                    "raw_data": json.dumps({"line": line, "synthetic": True, "time_kind": "observation"}),
                    "parser_name": "memory_text",
                    "source_file": path.name,
                    "time_kind": "observation",
                    "observation_time": captured.isoformat() if captured else "",
                }
            )
    return events
