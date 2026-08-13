import json
import re
from pathlib import Path

from .csv_util import parse_ts

SOURCE = "memory"


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    parent = path.parent.name.lower()
    return "memory" in name or parent == "memory" or suffix in {".mem.txt", ".raw.txt"} or name.endswith(".raw.txt")


def parse(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    events = []
    # Try "timestamp | type | detail" or "timestamp\tevent"
    line_re = re.compile(
        r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s*[,|;]\s*(?P<rest>.+)$"
    )
    kv_block: dict = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = line_re.match(line)
        if m:
            rest = m.group("rest")
            parts = re.split(r"\s*[|;]\s*", rest, maxsplit=1)
            et = parts[0].strip()
            desc = parts[-1].strip()
            events.append(_ev(parse_ts(m.group("ts")), et, desc, line))
            continue
        if ":" in line and not line.lower().startswith("http"):
            k, _, v = line.partition(":")
            key = k.strip().lower()
            kv_block[key] = v.strip()
            if key in {"process", "image", "pid", "cmd", "commandline"}:
                continue
        else:
            if kv_block:
                events.append(_from_kv(kv_block))
                kv_block = {}
            low = line.lower()
            et = "process_list"
            if "powershell" in low:
                et = "process_create"
            elif "usb" in low:
                et = "usb"
            events.append(_ev(None, et, line, line))
    if kv_block:
        events.append(_from_kv(kv_block))
    return events


def _from_kv(kv: dict) -> dict:
    proc = kv.get("process") or kv.get("image") or kv.get("name") or ""
    pid = kv.get("pid", "")
    ts = parse_ts(kv.get("timestamp") or kv.get("time"))
    desc = kv.get("description") or f"Memory artifact process={proc} pid={pid} {kv.get('cmd') or kv.get('commandline') or ''}".strip()
    et = "process_create" if "powershell" in desc.lower() else "process_list"
    return _ev(ts, et, desc, json.dumps(kv))


def _ev(ts, et, desc, raw):
    return {
        "source_type": SOURCE,
        "event_type": et.lower().replace(" ", "_") if et else "memory_artifact",
        "timestamp": ts,
        "description": desc,
        "actor": "",
        "target": "",
        "raw_data": str(raw)[:2000],
    }
