"""Tabular / CSV Forensic Parser for Synthetic & Exported Datasets.

Extracts events from CSV exports (Windows Security/System, Registry, Browser,
Network, FileSystem, Memory, etc.) into the Common Forensic Event Schema.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .csv_util import classify_csv, get, read_rows, row_ts

SOURCE = "structured"

EVENT_ID_MAP = {
    "4624": ("logon", "Logon", "Successful Windows logon"),
    "4634": ("logoff", "Logoff", "Windows logoff"),
    "4647": ("logoff", "Logoff", "User initiated logoff"),
    "4625": ("failed_logon", "Failed Logon", "Failed logon attempt"),
    "4672": ("admin_logon", "Privilege Assignment", "Special privileges assigned (admin logon)"),
    "4688": ("process_create", "Process Creation", "Process creation"),
    "7045": ("service_install", "Service Installation", "Service installed"),
    "7036": ("service_state", "Service State Change", "Service state change"),
    "6416": ("usb_connect", "USB / Device Connection", "New external device recognized"),
    "4663": ("file_access", "Object Access", "Object access"),
    "2100": ("usb_connect", "USB Connection", "USB device connected"),
    "2102": ("usb_remove", "USB Removal", "USB device removed"),
}


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    if suffix in {".csv", ".tsv"}:
        return True
    if hint in {"csv_tabular", "structured"}:
        return True
    return False


def parse(path: Path) -> list[dict]:
    kind = classify_csv(path)
    rows = read_rows(path)
    if kind in {"windows_security", "windows_system"}:
        events = [_windows(row, kind, path.name) for row in rows]
    elif kind == "registry":
        events = [_registry(row, path.name) for row in rows]
    elif kind == "browser_cookie":
        events = [_cookie(row, path.name) for row in rows]
    elif kind == "browser":
        events = [_browser(row, path.name) for row in rows]
    elif kind == "network":
        events = [_network(row, path.name) for row in rows]
    elif kind == "memory":
        events = [_memory(row, path.name) for row in rows]
    elif kind == "filesystem":
        events = [_fs(row, path.name) for row in rows]
    elif kind == "metadata":
        events = [_meta(row, path.name) for row in rows]
    else:
        events = [_generic(row, kind, path.name) for row in rows]

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
        "archive_created": "archive_created",
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


def _etype_from_text(*parts: str) -> tuple[str, str, str]:
    text = " ".join(p for p in parts if p)
    low = text.lower()
    for token in text.replace(",", " ").split():
        if token.isdigit() and token in EVENT_ID_MAP:
            return EVENT_ID_MAP[token]
    if "removed" in low and "usb" in low:
        return "usb_remove", "USB Removal", text or "USB removed"
    if "4624" in low or (("logon" in low or "login" in low) and "file" not in low):
        if "fail" in low:
            return "failed_logon", "Failed Logon", text or "Failed logon"
        if "admin" in low or "special privilege" in low:
            return "admin_logon", "Privilege Assignment", text or "Administrative logon"
        return "logon", "Logon", text or "User logon"
    if "4634" in low or "logoff" in low or "logout" in low:
        return "logoff", "Logoff", text or "User logoff"
    if "4688" in low or "powershell" in low or "process" in low:
        return "process_create", "Process Creation", text or "Process execution"
    if "7045" in low or "service install" in low:
        return "service_install", "Service Installation", text or "Service installed"
    if "7036" in low or "service" in low:
        return "service_state", "Service State Change", text or "Service state"
    if "6416" in low or "usb" in low:
        return "usb_connect", "USB Connection", text or "USB connected"
    if "copy" in low:
        return "file_copy", "File Copy", text or "File copied"
    if "file" in low or "open" in low or "access" in low:
        return "file_access", "File Access", text or "File accessed"
    return "event", "Forensic Event", text or "Event"


def _windows(row: dict, kind: str, filename: str) -> dict:
    eid = get(row, "event_id", "eventid", "id")
    msg = get(row, "message", "details", "description", "event_data", "info", "device", "service")
    user = get(row, "accountname", "targetusername", "user", "actor", "account", "subjectusername")
    host = get(row, "computer", "host", "workstation", "computername")
    dec_type = normalize_declared_type(get(row, "event_type", "type"))

    if eid in EVENT_ID_MAP:
        etype, art_type, label = EVENT_ID_MAP[eid]
    elif dec_type:
        etype = dec_type
        art_type = "Windows Event"
        label = dec_type.replace("_", " ").title()
    else:
        etype, art_type, label = _etype_from_text(eid, msg)

    desc = f"Windows Event {eid or etype}: {msg or label}".strip()
    if eid and not eid.isdigit():
        eid = ""
    ts = row_ts(row)

    src_p, dst_p = _paths_from_text(msg)
    proc = get(row, "process", "image", "newprocessname") or _process_from_text(msg)
    action = label

    return _evt(
        "windows_event",
        etype,
        art_type,
        ts,
        desc,
        user or ("admin" if etype == "admin_logon" else ""),
        get(row, "device", "service", "object", "target") or proc or eid or "workstation",
        row,
        filename,
        host=host,
        event_id=eid,
        process=proc,
        action=action,
        source_path=src_p,
        destination_path=dst_p,
    )


def _registry(row: dict, filename: str) -> dict:
    key = get(row, "key_or_value", "key", "path", "hive", "valuename", "name")
    val = get(row, "interpretation", "value", "data", "details", "description")
    desc_txt = get(row, "description", "details", "interpretation")
    dec_type = normalize_declared_type(get(row, "event_type", "type"))
    blob = f"{key} {val} {desc_txt}".lower()

    if dec_type:
        etype = dec_type
        art_type = "Registry Artifact"
    elif "usbstor" in blob or "sandisk" in blob:
        etype = "usb_history"
        art_type = "USB History (Registry)"
    elif "run" in blob or "persistence" in blob or "services" in blob:
        etype = "persistence"
        art_type = "Registry Persistence"
    elif "recentdocs" in blob:
        etype = "file_access"
        art_type = "Recent Documents"
    elif "userassist" in blob:
        etype = "process_create"
        art_type = "Program Execution (UserAssist)"
    else:
        etype = "registry_value"
        art_type = "Registry Value"

    desc = f"Registry artifact | Key: {key} | Value: {val or desc_txt}".strip()
    return _evt(
        "registry",
        etype,
        art_type,
        row_ts(row),
        desc,
        get(row, "user", "actor"),
        val or key,
        row,
        filename,
        action=f"Registry {etype.replace('_', ' ').title()}",
        path=key,
    )


def _cookie(row: dict, filename: str) -> dict:
    domain = get(row, "domain", "host", "site")
    name = get(row, "name", "cookie")
    desc = f"Browser cookie '{name}' for {domain}".strip()
    return _evt(
        "browser",
        "cookie",
        "Browser Cookie",
        row_ts(row),
        desc,
        get(row, "user", "actor") or "browser_user",
        domain or name,
        row,
        filename,
        host=domain,
        action="Cookie Created / Stored",
    )


def _browser(row: dict, filename: str) -> dict:
    url = get(row, "url", "target", "path", "site")
    title = get(row, "title", "name", "description")
    dec_type = normalize_declared_type(get(row, "event_type", "type"))
    blob = f"{url} {title}".lower()

    if dec_type:
        etype = dec_type
        art_type = "Browser Activity"
    elif "download" in blob or get(row, "target_path"):
        etype = "download"
        art_type = "Browser Download"
    else:
        etype = "url_visit"
        art_type = "Browser History"

    desc = f"Browser {etype}: {title} {url}".strip()
    return _evt(
        "browser",
        etype,
        art_type,
        row_ts(row),
        desc,
        get(row, "user", "actor") or "browser_user",
        url or title,
        row,
        filename,
        action="URL Visit" if etype == "url_visit" else "File Downloaded",
        path=url,
    )


def _network(row: dict, filename: str) -> dict:
    src = get(row, "src_ip", "source_ip", "src", "client")
    dst = get(row, "dst_ip", "dest_ip", "dst", "destination_ip", "server")
    proto = get(row, "protocol", "proto", "app") or "IP"
    info = get(row, "details", "info", "description", "query", "url")
    dport = get(row, "dst_port", "destination_port", "dport", "port")
    sport = get(row, "src_port", "source_port", "sport")
    dec_type = normalize_declared_type(get(row, "event_type", "type"))

    if dec_type:
        etype = dec_type
        art_type = "Network Flow"
    elif "dns" in proto.lower() or "dns" in info.lower():
        etype = "dns_query"
        art_type = "DNS Query"
    else:
        etype = "network_flow"
        art_type = "Network Flow"

    desc = f"{proto} {src} → {dst}{(':'+dport) if dport else ''} — {info}".strip(" —")
    return _evt(
        "network",
        etype,
        art_type,
        row_ts(row),
        desc,
        src or get(row, "user", "actor"),
        dst or info,
        row,
        filename,
        source_ip=src,
        source_port=sport,
        destination_ip=dst,
        destination_port=dport,
        action=f"{proto} {etype.replace('_', ' ').title()}",
    )


def _memory(row: dict, filename: str) -> dict:
    proc = get(row, "process", "name", "image", "cmdline")
    pid = get(row, "pid", "id")
    user = get(row, "user", "actor", "owner")
    desc = f"Memory process snapshot | {proc} (PID {pid})".strip()
    return _evt(
        "memory",
        "process_create" if "powershell" in proc.lower() else "process_list",
        "Memory Process Snapshot",
        row_ts(row),
        desc,
        user or "analyst",
        proc,
        row,
        filename,
        process=proc,
        pid=pid,
        time_kind="observation",
        action=f"Memory Process ({proc})",
    )


def _fs(row: dict, filename: str) -> dict:
    path_val = get(row, "path", "file", "target", "source")
    user = get(row, "user", "actor")
    dec_type = normalize_declared_type(get(row, "event_type", "action", "type"))
    blob = f"{path_val} {get(row, 'description')}".lower()

    if dec_type:
        etype = dec_type
        art_type = "Filesystem Activity"
    elif "copy" in blob or get(row, "destination") or "e:/" in blob or "e:\\" in blob:
        etype = "file_copy"
        art_type = "File Copy"
    elif "archive" in blob or ".zip" in blob:
        etype = "archive_created"
        art_type = "Archive Created"
    else:
        etype = "file_access"
        art_type = "File Access"

    src_p, dst_p = _paths_from_text(get(row, "description"))
    if not dst_p and get(row, "source"):
        src_p = get(row, "source")
        dst_p = path_val
    elif not dst_p and etype == "file_copy" and ("e:/" in path_val.lower() or "e:\\" in path_val.lower()):
        dst_p = path_val

    desc = f"{etype.upper()} | User: {user} | Path: {path_val} | {get(row, 'description')}".strip(" |")
    return _evt(
        "filesystem",
        etype,
        art_type,
        row_ts(row),
        desc,
        user,
        dst_p or path_val,
        row,
        filename,
        path=path_val,
        source_path=src_p,
        destination_path=dst_p,
        action=etype.replace("_", " ").title(),
    )


def _meta(row: dict, filename: str) -> dict:
    p = get(row, "path", "filename", "file", "target")
    return _evt(
        "metadata",
        "file_meta",
        "File Metadata",
        row_ts(row),
        f"Metadata for {p}",
        get(row, "user", "actor", "author"),
        p,
        row,
        filename,
        path=p,
        action="File Metadata Record",
    )


def _generic(row: dict, kind: str, filename: str) -> dict:
    et = normalize_declared_type(get(row, "event_type", "type", "action")) or "event"
    desc = get(row, "description", "details", "message", "info") or json.dumps(row)
    return _evt(
        "structured",
        et,
        "Structured Event",
        row_ts(row),
        desc,
        get(row, "user", "actor"),
        get(row, "target", "path", "object"),
        row,
        filename,
        action=et.replace("_", " ").title(),
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


def _evt(source, event_type, artifact_type, ts, description, actor, target, row, filename, extra=None, **kwargs):
    ts_utc = ts.isoformat() + "Z" if ts else ""
    return {
        "event_id": str(kwargs.get("event_id") or ""),
        "timestamp": ts,
        "timestamp_utc": ts_utc,
        "source": f"{source.replace('_', ' ').title()} ({filename})",
        "source_type": source,
        "artifact_type": artifact_type or source.title(),
        "event_type": event_type,
        "user": actor or "",
        "actor": actor or "",
        "host": str(kwargs.get("host") or ""),
        "process": str(kwargs.get("process") or ""),
        "pid": str(kwargs.get("pid") or ""),
        "action": str(kwargs.get("action") or event_type.replace("_", " ").title()),
        "object": str(target or "")[:512],
        "target": str(target or "")[:512],
        "path": str(kwargs.get("path") or ""),
        "source_path": str(kwargs.get("source_path") or ""),
        "destination_path": str(kwargs.get("destination_path") or ""),
        "source_ip": str(kwargs.get("source_ip") or ""),
        "source_port": str(kwargs.get("source_port") or ""),
        "destination_ip": str(kwargs.get("destination_ip") or ""),
        "destination_port": str(kwargs.get("destination_port") or ""),
        "description": description,
        "raw_data": json.dumps({**(extra or {}), **{k: v for k, v in row.items() if v}}, default=str)[:4000],
        "parser_name": f"tabular:{source}",
        "source_file": filename,
        "time_kind": kwargs.get("time_kind") or "event",
        "observation_time": str(ts_utc) if kwargs.get("time_kind") == "observation" else "",
    }
