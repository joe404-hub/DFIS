import json
from pathlib import Path

from .csv_util import classify_csv, get, read_rows, row_ts

SOURCE = "structured"

EVENT_ID_MAP = {
    "4624": ("logon", "Successful Windows logon"),
    "4634": ("logoff", "Windows logoff"),
    "4647": ("logoff", "User initiated logoff"),
    "4625": ("failed_logon", "Failed logon attempt"),
    "4672": ("admin_logon", "Special privileges assigned (admin logon)"),
    "4688": ("process_create", "Process creation"),
    "7045": ("service_install", "Service installed"),
    "7036": ("service_state", "Service state change"),
    "6416": ("usb_connect", "New external device recognized"),
    "2100": ("usb_connect", "USB device connected"),
    "2102": ("usb_remove", "USB device removed"),
}


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    return suffix == ".csv"


def parse(path: Path) -> list[dict]:
    kind = classify_csv(path)
    rows = read_rows(path)
    if kind == "windows_security" or kind == "windows_system":
        return [_windows(row, kind) for row in rows]
    if kind == "registry":
        return [_registry(row) for row in rows]
    if kind == "browser_cookie":
        return [_cookie(row) for row in rows]
    if kind == "browser":
        return [_browser(row) for row in rows]
    if kind == "network":
        return [_network(row) for row in rows]
    if kind == "memory":
        return [_memory(row) for row in rows]
    if kind == "filesystem":
        return [_fs(row) for row in rows]
    if kind == "metadata":
        return [_meta(row) for row in rows]
    return [_generic(row, kind) for row in rows]


def normalize_declared_type(et: str) -> str | None:
    if not et:
        return None
    t = et.strip().lower().replace(" ", "_")
    aliases = {
        "file_open": "file_access",
        "open": "file_access",
        "accessed": "file_access",
        "file_accessed": "file_access",
        "copy": "file_copy",
        "copied": "file_copy",
        "usb": "usb_connect",
        "usb_inserted": "usb_connect",
        "usb_connected": "usb_connect",
        "usb_removed": "usb_remove",
        "login": "logon",
        "log_off": "logoff",
        "logout": "logoff",
    }
    return aliases.get(t, t)


def _etype_from_text(*parts: str) -> tuple[str, str]:
    text = " ".join(p for p in parts if p)
    low = text.lower()
    for token in text.replace(",", " ").split():
        if token.isdigit() and token in EVENT_ID_MAP:
            return EVENT_ID_MAP[token]
    if "4624" in low or (("logon" in low or "login" in low) and "file" not in low):
        if "fail" in low:
            return "failed_logon", text or "Failed logon"
        if "admin" in low or "special privilege" in low:
            return "admin_logon", text or "Administrative logon"
        return "logon", text or "User logon"
    if "4634" in low or "logoff" in low or "log off" in low or "logout" in low:
        return "logoff", text or "User logoff"
    if "powershell" in low:
        return "process_create", text or "PowerShell started"
    if "service" in low and ("install" in low or "7045" in low):
        return "service_install", text or "Service installed"
    if ("copy" in low or "copied" in low) and ("file" in low or "usb" in low or ".xlsx" in low or ".csv" in low or ".zip" in low):
        return "file_copy", text or "File copied"
    if "usb" in low and ("remov" in low or "disconnect" in low or "eject" in low):
        return "usb_remove", text or "USB removed"
    if "usb" in low or "mass storage" in low or "usbstor" in low:
        return "usb_connect", text or "USB connected"
    if "file" in low and ("open" in low or "access" in low):
        return "file_access", text or "File accessed"
    if "download" in low:
        return "download", text or "Download"
    if "dns" in low:
        return "dns_query", text or "DNS query"
    return "event", text


def _windows(row: dict, kind: str) -> dict:
    eid = get(row, "event_id", "eventid", "id", "eid")
    etype = get(row, "event_type", "type", "task_category", "task")
    msg = get(row, "description", "message", "msg", "details", "info")
    user = get(row, "user", "account", "account_name", "subject_username", "actor", "username")
    target = get(row, "target", "computer", "workstation", "process", "image", "service", "device")
    mapped = EVENT_ID_MAP.get(eid)
    if mapped:
        ev, label = mapped
    else:
        ev, label = _etype_from_text(etype, msg, eid)
    desc = msg or label
    if eid:
        desc = f"Windows Event {eid}: {desc}"
    if user and user.lower() not in desc.lower():
        desc += f" (user {user})"
    return _evt(
        "windows_event",
        ev,
        row_ts(row),
        desc,
        user,
        target or eid,
        row,
    )


def _registry(row: dict) -> dict:
    key = get(row, "key", "path", "registry_key", "reg_key")
    val = get(row, "value", "data", "reg_value", "name")
    desc = get(row, "description", "details", "info") or f"Registry {key} = {val}"
    ev, _ = _etype_from_text(desc, key, val, get(row, "event_type", "type"))
    if ev == "event":
        ev = "registry_value"
        if "usb" in (key + val + desc).lower():
            ev = "usb_history"
        elif "run" in (key + desc).lower():
            ev = "persistence_runkey"
    return _evt("registry", ev, row_ts(row), desc, get(row, "user", "actor"), key or val, row)


def _cookie(row: dict) -> dict:
    host = get(row, "host", "domain", "site")
    name = get(row, "name", "cookie", "key")
    return _evt(
        "browser",
        "cookie",
        row_ts(row),
        f"Cookie {name} for {host}",
        get(row, "user", "actor"),
        host or name,
        row,
    )


def _browser(row: dict) -> dict:
    url = get(row, "url", "uri", "href", "tab_url", "referrer")
    title = get(row, "title", "name")
    path = get(row, "target_path", "path", "filename")
    et = get(row, "event_type", "type")
    if path and ("download" in et.lower() or path):
        ev = "download" if "download" in (et + path).lower() or get(row, "target_path") else "url_visit"
        desc = get(row, "description") or (f"Download: {path}" if ev == "download" else f"Browser: {title} {url}")
        return _evt("browser", ev if ev != "event" else "url_visit", row_ts(row), desc, get(row, "user", "actor"), path or url, row)
    ev, desc = _etype_from_text(et, get(row, "description"), title, url)
    if ev == "event":
        ev = "url_visit"
        desc = get(row, "description") or f"Browser visit: {title} {url}".strip()
    return _evt("browser", ev, row_ts(row), desc, get(row, "user", "actor"), url or path, row)


def _network(row: dict) -> dict:
    src = get(row, "src", "source", "src_ip", "source_ip", "ip_src")
    dst = get(row, "dst", "dest", "dst_ip", "destination", "destination_ip", "ip_dst")
    proto = get(row, "protocol", "proto")
    info = get(row, "info", "description", "dns", "query", "host", "sni")
    sport = get(row, "src_port", "sport")
    dport = get(row, "dst_port", "dport", "port")
    declared = normalize_declared_type(get(row, "event_type", "type"))
    if declared:
        ev = declared
    else:
        ev, _ = _etype_from_text(info, proto)
        if ev == "event" or ev == "file_access":
            ev = "dns_query" if "dns" in (info + proto).lower() else "network_flow"
    desc = info or f"{proto} {src}:{sport} → {dst}:{dport}".strip(" :→")
    return _evt("network", ev, row_ts(row), desc, src, dst or info, row)


def _memory(row: dict) -> dict:
    proc = get(row, "process", "image", "name", "cmd", "commandline", "command_line")
    pid = get(row, "pid")
    desc = get(row, "description", "details") or f"Memory process {proc} pid={pid}".strip()
    ev, _ = _etype_from_text(get(row, "event_type", "type"), desc, proc)
    if ev == "event":
        ev = "process_list"
    return _evt("memory", ev, row_ts(row), desc, get(row, "user", "actor"), proc or pid, row)


def _fs(row: dict) -> dict:
    path = get(row, "path", "fullpath", "filename", "name", "destination", "dest", "target")
    src = get(row, "source", "src", "src_path")
    declared = normalize_declared_type(get(row, "event_type", "type", "action", "operation"))
    desc = get(row, "description", "details", "info")
    ev = declared or _etype_from_text(desc, path, src)[0]
    if ev == "event":
        ev = "file_meta"
    if ev == "file_copy" and src:
        desc = f"{desc + ': ' if desc else ''}{src} → {path}"
    elif path and path not in (desc or ""):
        desc = f"{desc} ({path})" if desc else f"File {ev} {path}"
    return _evt("filesystem", ev, row_ts(row), desc, get(row, "user", "actor", "owner"), path or src, row)


def _meta(row: dict) -> dict:
    name = get(row, "file", "filename", "path", "name")
    desc = get(row, "description") or f"Metadata {name} author={get(row, 'author')} created={get(row, 'created')}"
    return _evt("metadata", "file_metadata", row_ts(row), desc, get(row, "author", "actor"), name, row)


def _generic(row: dict, kind: str) -> dict:
    ev, desc = _etype_from_text(
        get(row, "event_type", "type"),
        get(row, "description", "message", "details", "info"),
    )
    return _evt(
        kind if kind != "structured" else "structured",
        ev if ev != "event" else get(row, "event_type", "type") or "event",
        row_ts(row),
        desc or json.dumps(row)[:400],
        get(row, "user", "actor"),
        get(row, "target", "path", "object"),
        row,
    )


def _evt(source, event_type, ts, description, actor, target, row):
    return {
        "source_type": source,
        "event_type": event_type,
        "timestamp": ts,
        "description": description,
        "actor": actor or "",
        "target": target or "",
        "raw_data": json.dumps(row, default=str)[:4000],
    }
