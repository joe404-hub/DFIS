import hashlib
from datetime import datetime, timezone
from dateutil import tz


def normalize_ts(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def fingerprint(ev: dict) -> str:
    key = "|".join(
        [
            str(ev.get("source_type") or ""),
            str(ev.get("event_type") or ""),
            str(ev.get("timestamp") or ""),
            str(ev.get("description") or "")[:200],
            str(ev.get("target") or ""),
        ]
    )
    return hashlib.sha256(key.encode()).hexdigest()


def correlate(events: list[dict]) -> list[dict]:
    """Attach simple correlation tags for USB/file/browser chains."""
    tags = []
    for ev in events:
        et = (ev.get("event_type") or "").lower()
        desc = (ev.get("description") or "").lower()
        tag = None
        if "usb" in et or "usb" in desc:
            tag = "usb_activity"
        elif "download" in et or ".zip" in desc or "archive" in et:
            tag = "staging"
        elif "url" in et or "drive.google" in desc or "dropbox" in desc:
            tag = "cloud_access"
        elif "logon" in et or "login" in et:
            tag = "access"
        ev["correlation"] = tag
        tags.append(ev)
    return tags


def build_timeline(raw_events: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for ev in raw_events:
        ev = dict(ev)
        ev["timestamp"] = normalize_ts(ev.get("timestamp"))
        fp = ev.get("fingerprint") or fingerprint(ev)
        ev["fingerprint"] = fp
        if fp in seen:
            continue
        seen.add(fp)
        out.append(ev)
    out.sort(key=lambda e: e["timestamp"] or datetime.min)
    return correlate(out)
