import csv
from datetime import datetime
from pathlib import Path
from dateutil import parser as dtp


TS_KEYS = (
    "timestamp",
    "time",
    "datetime",
    "date_time",
    "utc_time",
    "utc",
    "event_time",
    "timecreated",
    "time_created",
    "systemtime",
    "start_time",
    "creation_time",
    "created",
    "mtime",
    "accessed",
    "visit_time",
)


def read_rows(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except Exception:
            dialect = csv.excel
        reader = csv.DictReader(f, dialect=dialect)
        rows = []
        for row in reader:
            clean = {(k or "").strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
            if any(v for v in clean.values()):
                rows.append(clean)
        return rows


def norm_key(k: str) -> str:
    return (k or "").strip().lower().replace(" ", "_").replace("-", "_")


def get(row: dict, *names: str) -> str:
    mapped = {norm_key(k): v for k, v in row.items()}
    for n in names:
        v = mapped.get(norm_key(n))
        if v not in (None, ""):
            return str(v)
    return ""


def parse_ts(value) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    try:
        n = float(value)
        if n > 10**14:
            return datetime.utcfromtimestamp(n / 1_000_000 - 11644473600)
        if n > 10**11:
            return datetime.utcfromtimestamp(n / 1000)
        if n > 10**9:
            return datetime.utcfromtimestamp(n)
    except (TypeError, ValueError):
        pass
    try:
        dt = dtp.parse(str(value), fuzzy=True)
        return dt.replace(tzinfo=None) if dt.tzinfo else dt
    except Exception:
        return None


def row_ts(row: dict) -> datetime | None:
    mapped = {norm_key(k): v for k, v in row.items()}
    for k in TS_KEYS:
        if mapped.get(k):
            ts = parse_ts(mapped[k])
            if ts:
                return ts
    for k, v in mapped.items():
        if "time" in k or k.endswith("_at") or k == "date":
            ts = parse_ts(v)
            if ts:
                return ts
    return None


def classify_csv(path: Path) -> str:
    name = path.name.lower()
    parent = path.parent.name.lower()
    blob = f"{parent}/{name}"
    if "security" in blob:
        return "windows_security"
    if "system" in blob and "file" not in blob:
        return "windows_system"
    if "registry" in blob or blob.endswith("ntuser") or "runkey" in blob:
        return "registry"
    if "cookie" in blob:
        return "browser_cookie"
    if "history" in blob or "download" in blob or parent == "browser":
        return "browser"
    if "pcap" in blob or "packet" in blob or "network" in blob or "capture" in blob:
        return "network"
    if "memory" in blob or "process" in blob or parent == "memory":
        return "memory"
    if "file" in blob or "mft" in blob or parent in {"filesystem", "file_system", "fs"}:
        return "filesystem"
    if "metadata" in blob or parent == "metadata":
        return "metadata"
    return "structured"
