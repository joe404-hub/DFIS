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
    "4663": ("file_access", "Object access"),
    "2100": ("usb_connect", "USB device connected"),
    "2102": ("usb_remove", "USB device removed"),
}


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    return suffix == ".csv"


def parse(path: Path) -> list[dict]:
    kind = classify_csv(path)
    rows = read_rows(path)
    if kind == "windows_security" or kind == "windows_system":
        events = [_windows(row, kind) for row in rows]
    elif kind == "registry":
        events = [_registry(row) for row in rows]
    elif kind == "browser_cookie":
        events = [_cookie(row) for row in rows]
    elif kind == "browser":
        events = [_browser(row) for row in rows]
    elif kind == "network":
        events = [_network(row) for row in rows]
    elif kind == "memory":
        events = [_memory(row) for row in rows]
    elif kind == "filesystem":
        events = [_fs(row) for row in rows]
    elif kind == "metadata":
        events = [_meta(row) for row in rows]
    else:
        events = [_generic(row, kind) for row in rows]
    for ev in events:
        ev["source_file"] = path.name
        ev["parser_name"] = f"tabular:{kind}"
    return events


def normalize_declared_type(et: str) -> str | None:
    if not et:
        return None
    t = et.strip().lower().replace(" ", "_")
    aliases = {
        "file_open": "file_access",
        "file_access": "file_access",
        "open": "file_access",
        "accessed": "file_access",
        "file_accessed": "file_access",
        "file_copy": "file_copy",
        "copy": "file_copy",
        "copied": "file_copy",
        "usb": "usb_connect",
        "usb_inserted": "usb_connect",
        "usb_connected": "usb_connect",
        "usb_device_connected": "usb_connect",
        "usb_removed": "usb_remove",
        "usb_device_removed": "usb_remove",
        "successful_logon": "logon",
        "login": "logon",
        "log_off": "logoff",
        "logout": "logoff",
        "process_create": "process_create",
        "service_install": "service_install",
        "service_running": "service_state",
        "service_stopped": "service_state",
        "internal_drive_access": "url_visit",
    }
    return aliases.get(t, t)


def _etype_from_text(*parts: str) -> tuple[str, str]:
    text = " ".join(p for p in parts if p)
    low = text.lower()
    for token in text.replace(",", " ").split():
        if token.isdigit() and token in EVENT_ID_MAP:
            return EVENT_ID_MAP[token]
    if "removed" in low and "usb" in low:
        return "usb_remove", text or "USB removed"
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
    if ("copy" in low or "copied" in low) and (
        "file" in low or "usb" in low or ".xlsx" in low or ".csv" in low or ".zip" in low or "transfer" in low
    ):
        return "file_copy", text or "File copied"
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
    eid = get(row, "event_id", "eventid", "eid")
    declared = normalize_declared_type(get(row, "event_type", "type", "task_category", "task"))
    msg = get(row, "description", "message", "msg", "details", "info")
    user = get(row, "user", "account", "account_name", "subject_username", "actor", "username")
    host = get(row, "host", "computer", "workstation")
    if declared:
        ev = declared
        if ev == "logon" and ("admin" in (user + msg).lower() or "administrative" in msg.lower()):
            ev = "admin_logon"
    elif eid in EVENT_ID_MAP:
        ev = EVENT_ID_MAP[eid][0]
        if ev == "usb_connect" and "remov" in msg.lower():
            ev = "usb_remove"
        if ev == "file_access" and "cop" in msg.lower():
            ev = "file_copy"
    else:
        ev, _ = _etype_from_text(msg, eid)
    label = {
        "logon": "Successful logon",
        "admin_logon": "Administrative logon",
        "logoff": "Logoff",
        "process_create": "Process created",
        "service_install": "Service installed",
        "service_state": "Service state change",
        "usb_connect": "USB device connected",
        "usb_remove": "USB device removed",
        "file_access": "File accessed",
        "file_copy": "File copied",
    }.get(ev, ev)
    desc = f"Windows Event {eid}: {msg or label}" if eid else (msg or label)
    if user and user.lower() not in desc.lower():
        desc += f" (user {user})"
    extra = {
        "event_id": eid,
        "host": host,
        "user": user,
        "source_log": get(row, "source"),
    }
    src_path, dst_path = _paths_from_text(msg)
    return _evt("windows_event", ev, row_ts(row), desc, user, dst_path or host or eid, row, extra,
                process=_process_from_text(msg), source_path=src_path, destination_path=dst_path)


def _registry(row: dict) -> dict:
    hive = get(row, "hive", "registry_hive")
    artifact = get(row, "artifact", "artifact_type")
    key = get(row, "key_or_value", "key", "path", "registry_key", "reg_key")
    val = get(row, "value", "data", "reg_value", "interpretation", "name")
    interp = get(row, "interpretation", "description", "details", "info")
    ev = "registry_value"
    blob = f"{artifact} {key} {val} {interp}".lower()
    if "usb" in blob or "usbstor" in blob:
        ev = "usb_history" if "remov" not in blob else "usb_remove"
        if "connect" in blob or ev == "usb_history":
            ev = "usb_history"
    elif "run" in blob or "service" in blob:
        ev = "persistence"
    elif "recent" in blob or "mru" in blob:
        ev = "recent_docs"
    parts = [
        f"Registry artifact [{artifact or 'value'}]",
        f"Hive: {hive}" if hive else "",
        f"Key/value: {key}" if key else "",
        f"Interpretation: {interp or val}" if (interp or val) else "",
    ]
    desc = " | ".join(p for p in parts if p)
    target = key or val or artifact
    return _evt(
        "registry",
        ev,
        row_ts(row),
        desc,
        get(row, "user", "actor"),
        target,
        row,
        {"hive": hive, "artifact": artifact, "key_or_value": key, "interpretation": interp or val},
    )


def _cookie(row: dict) -> dict:
    host = get(row, "host", "domain", "site")
    name = get(row, "name", "cookie", "key")
    note = get(row, "note", "description")
    desc = f"Browser cookie '{name}' for {host}" + (f" — {note}" if note else "")
    return _evt("browser", "cookie", row_ts(row), desc, get(row, "user", "actor"), host or name, row,
                {"domain": host, "cookie": name})


def _browser(row: dict) -> dict:
    url = get(row, "url", "uri", "href", "tab_url", "referrer")
    title = get(row, "title", "name")
    path = get(row, "target_path", "path", "filename")
    et = get(row, "event_type", "type")
    if path:
        ev = "download" if "download" in (et + path).lower() or get(row, "target_path") else "url_visit"
        desc = get(row, "description") or (f"Download: {path}" if ev == "download" else f"Browser: {title} {url}")
        return _evt("browser", ev, row_ts(row), desc, get(row, "user", "actor"), path or url, row,
                    {"url": url, "path": path})
    ev, desc = _etype_from_text(et, get(row, "description"), title, url)
    if ev == "event":
        ev = "url_visit"
        desc = get(row, "description") or f"Browser visit: {title} {url}".strip()
    return _evt("browser", ev, row_ts(row), desc, get(row, "user", "actor"), url or path, row, {"url": url})


def _network(row: dict) -> dict:
    src = get(row, "src", "source", "src_ip", "source_ip", "ip_src")
    dst = get(row, "dst", "dest", "dst_ip", "destination", "destination_ip", "ip_dst")
    proto = get(row, "protocol", "proto") or "IP"
    info = get(row, "info", "description", "dns", "query", "details", "app")
    sport = get(row, "src_port", "sport", "source_port")
    dport = get(row, "dst_port", "dport", "port", "destination_port")
    app = get(row, "app", "application", "service")
    declared = normalize_declared_type(get(row, "event_type", "type"))
    ev = declared or ("dns_query" if "dns" in (info + proto).lower() else "network_flow")
    if ev in {"event", "file_access"}:
        ev = "network_flow"
    src_ep = f"{src}:{sport}" if sport else src
    dst_ep = f"{dst}:{dport}" if dport else dst
    desc = f"{proto} {src_ep} → {dst_ep}"
    if app:
        desc += f" ({app})"
    if info and info.lower() not in desc.lower():
        desc += f" — {info}"
    return _evt(
        "network",
        ev,
        row_ts(row),
        desc,
        src,
        dst_ep,
        row,
        {"application": app, "details": info},
        source_ip=src,
        source_port=sport,
        destination_ip=dst,
        destination_port=dport,
    )


def _memory(row: dict) -> dict:
    proc = get(row, "process", "image", "name", "cmd", "commandline", "command_line")
    pid = get(row, "pid")
    desc = get(row, "description", "details") or f"Memory process {proc} pid={pid}".strip()
    ev, _ = _etype_from_text(get(row, "event_type", "type"), desc, proc)
    if ev == "event":
        ev = "process_list"
    return _evt("memory", ev, row_ts(row), desc, get(row, "user", "actor"), proc or pid, row, {},
                process=proc, pid=pid)


def _fs(row: dict) -> dict:
    path = get(row, "path", "fullpath", "filename", "name", "destination", "dest", "target")
    src = get(row, "source", "src", "src_path")
    declared = normalize_declared_type(get(row, "event_type", "type", "action", "operation"))
    user = get(row, "user", "actor", "owner")
    ev = declared or _etype_from_text(get(row, "description"), path, src)[0]
    if ev == "event":
        ev = "file_meta"
    action = {"file_access": "OPEN", "file_copy": "COPY", "file_meta": "META"}.get(ev, ev.upper())
    if ev == "file_copy":
        dest = path
        # If only dest is present (E:/Transfer/file), infer copy to removable path
        src_path = src or ""
        desc = f"FILE_COPY | User: {user or 'unknown'} | Destination: {dest}"
        if src_path:
            desc = f"FILE_COPY | User: {user or 'unknown'} | {src_path} → {dest}"
        return _evt("filesystem", ev, row_ts(row), desc, user, dest, row, {"action": action},
                    source_path=src_path, destination_path=dest)
    desc = f"FILE_{action} | Path: {path} | User: {user or 'unknown'}"
    extra_note = get(row, "description", "details", "info")
    if extra_note and extra_note.lower() not in desc.lower():
        desc += f" | {extra_note}"
    return _evt("filesystem", ev, row_ts(row), desc, user, path or src, row, {"action": action},
                source_path=path, destination_path="")


def _meta(row: dict) -> dict:
    name = get(row, "file", "filename", "path", "name")
    desc = get(row, "description") or f"Metadata {name} author={get(row, 'author')} created={get(row, 'created')}"
    return _evt("metadata", "file_metadata", row_ts(row), desc, get(row, "author", "actor"), name, row, {})


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
        {},
    )


def _paths_from_text(text: str) -> tuple[str, str]:
    if not text:
        return "", ""
    dest = ""
    if "copied to" in text.lower():
        dest = text.split("copied to", 1)[-1].strip()
    name = ""
    for token in text.replace("\\", "/").split():
        if "." in token and not token.startswith("http"):
            name = token.strip(".,;")
            break
    return name, dest


def _process_from_text(text: str) -> str:
    if not text:
        return ""
    low = text.lower()
    for p in ("powershell.exe", "cmd.exe", "demoupdater.exe", "explorer.exe"):
        if p in low:
            return p
    return ""


def _evt(source, event_type, ts, description, actor, target, row, extra=None, **kwargs):
    payload = {
        "source_type": source,
        "event_type": event_type,
        "timestamp": ts,
        "description": description,
        "actor": actor or "",
        "target": str(target or "")[:512],
        "raw_data": json.dumps({**(extra or {}), **{k: v for k, v in row.items() if v}}, default=str)[:4000],
        "process": kwargs.get("process") or "",
        "pid": str(kwargs.get("pid") or ""),
        "source_path": kwargs.get("source_path") or "",
        "destination_path": kwargs.get("destination_path") or "",
        "source_ip": kwargs.get("source_ip") or "",
        "source_port": str(kwargs.get("source_port") or ""),
        "destination_ip": kwargs.get("destination_ip") or "",
        "destination_port": str(kwargs.get("destination_port") or ""),
    }
    return payload
