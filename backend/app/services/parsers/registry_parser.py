"""Windows Registry Hive Forensic Parser.

Extracts persistence keys, USBSTOR device history, UserAssist execution history,
RecentDocs, Typed URLs/Paths, Services, and System/SAM metadata using python-registry.
"""

from __future__ import annotations

import codecs
import json
import struct
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

SOURCE = "registry"

CHROME_OR_WIN_EPOCH = datetime(1601, 1, 1)


def filetime_to_dt(ft: int) -> datetime | None:
    """Convert 64-bit Windows FILETIME (100ns intervals since 1601-01-01) to datetime."""
    if not ft or ft <= 0:
        return None
    try:
        us = ft // 10
        return CHROME_OR_WIN_EPOCH + timedelta(microseconds=us)
    except Exception:
        return None


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    if name.upper() in {"NTUSER.DAT", "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "USRCLASS.DAT"}:
        return True
    if suffix in {".dat", ".hiv", ".hive", ".reg"}:
        return True
    if hint in {"registry_hive", "registry"}:
        return True
    try:
        with open(path, "rb") as f:
            header = f.read(4)
            if header == b"regf":
                return True
    except Exception:
        pass
    return False


def parse(path: Path) -> list[dict]:
    """Parse registry hive binary file into normalized forensic events."""
    try:
        from Registry import Registry

        reg = Registry.Registry(str(path))
    except Exception:
        return _fallback_summary(path)

    events: list[dict] = []

    # 1. Parse UserAssist (Execution history & counts)
    events.extend(_parse_userassist(reg, path.name))

    # 2. Parse RecentDocs (Recently opened documents)
    events.extend(_parse_recentdocs(reg, path.name))

    # 3. Parse Run & RunOnce Keys (Persistence)
    events.extend(_parse_run_keys(reg, path.name))

    # 4. Parse RunMRU, TypedPaths, TypedURLs
    events.extend(_parse_mru_and_typed(reg, path.name))

    # 5. Parse USBSTOR & USB Devices (SYSTEM hive)
    events.extend(_parse_usbstor(reg, path.name))

    # 6. Parse Services (SYSTEM hive)
    events.extend(_parse_services(reg, path.name))

    # 7. Parse Mounted Devices (Drive letters)
    events.extend(_parse_mounted_devices(reg, path.name))

    # 8. Parse Computer Name & OS Metadata
    events.extend(_parse_system_info(reg, path.name))

    # 9. Parse SAM User Accounts
    events.extend(_parse_sam_accounts(reg, path.name))

    if not events:
        return _fallback_summary(path)

    return events


def _parse_userassist(reg: Any, filename: str) -> list[dict]:
    """Parse UserAssist keys to find executed applications and timestamps."""
    events: list[dict] = []
    ua_base = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
    try:
        base_key = reg.open(ua_base)
    except Exception:
        return events

    for guid_key in base_key.subkeys():
        try:
            count_key = guid_key.subkey("Count")
        except Exception:
            continue

        for val in count_key.values():
            val_name_raw = val.name()
            # ROT-13 decode the application name
            app_name = codecs.decode(val_name_raw, "rot_13")
            data = val.value()

            run_count = 0
            last_exec: datetime | None = None
            if isinstance(data, (bytes, bytearray)):
                # Windows 7+ UserAssist structure: 72 bytes. Offset 4: run count (DWORD), Offset 60: FILETIME
                if len(data) >= 68:
                    try:
                        run_count = struct.unpack_from("<I", data, 4)[0]
                        ft = struct.unpack_from("<Q", data, 60)[0]
                        last_exec = filetime_to_dt(ft)
                    except Exception:
                        pass
                # Windows XP UserAssist: 16 bytes. Offset 4: run count, Offset 8: FILETIME
                elif len(data) == 16:
                    try:
                        run_count = struct.unpack_from("<I", data, 4)[0]
                        ft = struct.unpack_from("<Q", data, 8)[0]
                        last_exec = filetime_to_dt(ft)
                    except Exception:
                        pass

            # Filter uninteresting guid headers
            clean_app = app_name.replace("UEME_RUNPATH:", "").replace("UEME_RUNPIDL:", "").replace("{", "").replace("}", "")
            proc_name = Path(clean_app).name if ("\\" in clean_app or "/" in clean_app) else clean_app

            events.append(
                {
                    "event_id": "userassist",
                    "timestamp": last_exec or count_key.timestamp(),
                    "timestamp_utc": (last_exec or count_key.timestamp()).isoformat() if (last_exec or count_key.timestamp()) else "",
                    "source": f"Registry UserAssist ({filename})",
                    "source_type": SOURCE,
                    "artifact_type": "Program Execution (UserAssist)",
                    "event_type": "process_create",
                    "user": "",
                    "actor": "",
                    "host": "",
                    "process": proc_name,
                    "pid": "",
                    "action": f"Executed program ({run_count} runs)",
                    "object": clean_app,
                    "target": clean_app,
                    "path": clean_app,
                    "source_path": clean_app,
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"UserAssist execution history | Program: {clean_app} | Run count: {run_count} | Last executed: {last_exec or 'N/A'}",
                    "raw_data": json.dumps({"raw_name": val_name_raw, "decoded": app_name, "run_count": run_count, "last_exec": str(last_exec)}),
                    "parser_name": "registry_userassist",
                    "source_file": filename,
                    "time_kind": "event",
                    "observation_time": "",
                }
            )
    return events


def _parse_recentdocs(reg: Any, filename: str) -> list[dict]:
    """Parse RecentDocs keys for recently accessed files."""
    events: list[dict] = []
    rd_base = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
    try:
        base_key = reg.open(rd_base)
    except Exception:
        return events

    # Check base key and all extension subkeys (.xlsx, .csv, .docx, etc.)
    target_keys = [base_key] + list(base_key.subkeys())
    for k in target_keys:
        k_ts = k.timestamp()
        ext = k.name() if k != base_key else "All"

        for val in k.values():
            if val.name() in {"MRUListEx", "MRUList"}:
                continue
            v = val.value()
            doc_str = ""
            if isinstance(v, (bytes, bytearray)):
                # UTF-16LE null-terminated string
                try:
                    doc_str = v.decode("utf-16le", errors="ignore").split("\x00")[0]
                except Exception:
                    doc_str = str(v)
            elif isinstance(v, str):
                doc_str = v

            if doc_str and len(doc_str) >= 2:
                events.append(
                    {
                        "event_id": "recentdocs",
                        "timestamp": k_ts,
                        "timestamp_utc": k_ts.isoformat() if k_ts else "",
                        "source": f"Registry RecentDocs ({filename})",
                        "source_type": SOURCE,
                        "artifact_type": "Recent Documents",
                        "event_type": "file_access",
                        "user": "",
                        "actor": "",
                        "host": "",
                        "process": "",
                        "pid": "",
                        "action": "File Accessed (RecentDocs)",
                        "object": doc_str,
                        "target": doc_str,
                        "path": doc_str,
                        "source_path": doc_str,
                        "destination_path": "",
                        "source_ip": "",
                        "source_port": "",
                        "destination_ip": "",
                        "destination_port": "",
                        "description": f"RecentDocs opened document | Category: {ext} | File: {doc_str}",
                        "raw_data": json.dumps({"key": k.path(), "value_name": val.name(), "doc": doc_str}),
                        "parser_name": "registry_recentdocs",
                        "source_file": filename,
                        "time_kind": "event",
                        "observation_time": "",
                    }
                )
    return events


def _parse_run_keys(reg: Any, filename: str) -> list[dict]:
    """Parse Run, RunOnce, and autorun keys for persistence mechanisms."""
    events: list[dict] = []
    run_paths = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]
    for rpath in run_paths:
        try:
            key = reg.open(rpath)
        except Exception:
            continue
        k_ts = key.timestamp()
        for val in key.values():
            cmd = str(val.value())
            name = val.name()
            proc = Path(cmd.split()[0].strip('"')).name if cmd else name
            events.append(
                {
                    "event_id": "run_key",
                    "timestamp": k_ts,
                    "timestamp_utc": k_ts.isoformat() if k_ts else "",
                    "source": f"Registry Persistence ({filename})",
                    "source_type": SOURCE,
                    "artifact_type": "Registry Persistence (Run Key)",
                    "event_type": "persistence",
                    "user": "",
                    "actor": "",
                    "host": "",
                    "process": proc,
                    "pid": "",
                    "action": "Autorun Persistence Established",
                    "object": name,
                    "target": cmd,
                    "path": cmd,
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"Registry autorun persistence | Key: {rpath}\\{name} = {cmd}",
                    "raw_data": json.dumps({"key": rpath, "value_name": name, "command": cmd}),
                    "parser_name": "registry_run_keys",
                    "source_file": filename,
                    "time_kind": "event",
                    "observation_time": "",
                }
            )
    return events


def _parse_mru_and_typed(reg: Any, filename: str) -> list[dict]:
    """Parse RunMRU, TypedPaths, and TypedURLs."""
    events: list[dict] = []
    mru_paths = [
        ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", "Run Dialog MRU", "process_create"),
        ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", "Explorer Typed Paths", "file_access"),
        ("Software\\Microsoft\\Internet Explorer\\TypedURLs", "Browser Typed URLs", "url_visit"),
    ]
    for mpath, label, etype in mru_paths:
        try:
            key = reg.open(mpath)
        except Exception:
            continue
        k_ts = key.timestamp()
        for val in key.values():
            if val.name() in {"MRUList", "MRUListEx"}:
                continue
            entry = str(val.value()).rstrip("\\1")
            events.append(
                {
                    "event_id": "mru_typed",
                    "timestamp": k_ts,
                    "timestamp_utc": k_ts.isoformat() if k_ts else "",
                    "source": f"Registry MRU ({filename})",
                    "source_type": SOURCE,
                    "artifact_type": label,
                    "event_type": etype,
                    "user": "",
                    "actor": "",
                    "host": "",
                    "process": Path(entry.split()[0]).name if etype == "process_create" else "",
                    "pid": "",
                    "action": f"User typed {label}",
                    "object": entry,
                    "target": entry,
                    "path": entry,
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"{label} | Entry: {entry}",
                    "raw_data": json.dumps({"key": mpath, "value_name": val.name(), "entry": entry}),
                    "parser_name": "registry_mru",
                    "source_file": filename,
                    "time_kind": "event",
                    "observation_time": "",
                }
            )
    return events


def _parse_usbstor(reg: Any, filename: str) -> list[dict]:
    """Parse SYSTEM USBSTOR key to identify connected USB storage devices and serial numbers."""
    events: list[dict] = []
    usbstor_paths = [
        "CurrentControlSet\\Enum\\USBSTOR",
        "ControlSet001\\Enum\\USBSTOR",
        "Enum\\USBSTOR",
        "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
    ]
    base_key = None
    for p in usbstor_paths:
        try:
            base_key = reg.open(p)
            break
        except Exception:
            continue

    if not base_key:
        return events

    for dev_type_key in base_key.subkeys():
        dev_type = dev_type_key.name()  # e.g., Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00
        for dev_instance_key in dev_type_key.subkeys():
            serial = dev_instance_key.name()
            k_ts = dev_instance_key.timestamp()

            friendly_name = ""
            try:
                friendly_name = str(dev_instance_key.value("FriendlyName").value())
            except Exception:
                try:
                    friendly_name = str(dev_instance_key.value("DeviceDesc").value())
                except Exception:
                    friendly_name = dev_type

            events.append(
                {
                    "event_id": "usbstor",
                    "timestamp": k_ts,
                    "timestamp_utc": k_ts.isoformat() if k_ts else "",
                    "source": f"Registry USBSTOR ({filename})",
                    "source_type": SOURCE,
                    "artifact_type": "USB Storage Device History",
                    "event_type": "usb_history",
                    "user": "",
                    "actor": "",
                    "host": "",
                    "process": "",
                    "pid": "",
                    "action": "USB Storage Device Connected / Recognized",
                    "object": friendly_name or dev_type,
                    "target": friendly_name or dev_type,
                    "path": f"USBSTOR\\{dev_type}\\{serial}",
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"USBSTOR device record | Device: {friendly_name} | Serial: {serial} | Type: {dev_type}",
                    "raw_data": json.dumps({"dev_type": dev_type, "serial": serial, "friendly_name": friendly_name}),
                    "parser_name": "registry_usbstor",
                    "source_file": filename,
                    "time_kind": "event",
                    "observation_time": "",
                }
            )
    return events


def _parse_services(reg: Any, filename: str) -> list[dict]:
    """Parse installed Windows services from SYSTEM hive."""
    events: list[dict] = []
    svc_paths = [
        "CurrentControlSet\\Services",
        "ControlSet001\\Services",
        "Services",
        "SYSTEM\\CurrentControlSet\\Services",
    ]
    base_key = None
    for p in svc_paths:
        try:
            base_key = reg.open(p)
            break
        except Exception:
            continue

    if not base_key:
        return events

    for svc_key in base_key.subkeys():
        svc_name = svc_key.name()
        k_ts = svc_key.timestamp()

        image_path = ""
        display_name = ""
        start_type = ""
        try:
            image_path = str(svc_key.value("ImagePath").value())
        except Exception:
            pass
        try:
            display_name = str(svc_key.value("DisplayName").value())
        except Exception:
            pass
        try:
            st_val = svc_key.value("Start").value()
            start_map = {2: "Auto", 3: "Manual", 4: "Disabled", 0: "Boot", 1: "System"}
            start_type = start_map.get(st_val, str(st_val))
        except Exception:
            pass

        # Only record services that have a binary image path or interesting names
        if image_path:
            proc = Path(image_path.split()[0].strip('"')).name
            events.append(
                {
                    "event_id": "service_entry",
                    "timestamp": k_ts,
                    "timestamp_utc": k_ts.isoformat() if k_ts else "",
                    "source": f"Registry Services ({filename})",
                    "source_type": SOURCE,
                    "artifact_type": "Installed Service",
                    "event_type": "service_install",
                    "user": "",
                    "actor": "",
                    "host": "",
                    "process": proc,
                    "pid": "",
                    "action": f"Service Configured ({start_type})",
                    "object": svc_name,
                    "target": image_path,
                    "path": image_path,
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"Installed Service | Name: {svc_name} ({display_name or svc_name}) | Path: {image_path} | Start: {start_type}",
                    "raw_data": json.dumps({"service": svc_name, "image_path": image_path, "start": start_type}),
                    "parser_name": "registry_services",
                    "source_file": filename,
                    "time_kind": "event",
                    "observation_time": "",
                }
            )
    return events


def _parse_mounted_devices(reg: Any, filename: str) -> list[dict]:
    """Parse MountedDevices mapping drive letters to disk signatures or volume GUIDs."""
    events: list[dict] = []
    md_paths = ["MountedDevices", "SYSTEM\\MountedDevices"]
    key = None
    for p in md_paths:
        try:
            key = reg.open(p)
            break
        except Exception:
            continue
    if not key:
        return events

    k_ts = key.timestamp()
    for val in key.values():
        val_name = val.name()
        if val_name.startswith("\\DosDevices\\"):
            drive_letter = val_name.replace("\\DosDevices\\", "")
            data = val.value()
            hex_data = data.hex() if isinstance(data, (bytes, bytearray)) else str(data)
            events.append(
                {
                    "event_id": "mounted_device",
                    "timestamp": k_ts,
                    "timestamp_utc": k_ts.isoformat() if k_ts else "",
                    "source": f"Registry MountedDevices ({filename})",
                    "source_type": SOURCE,
                    "artifact_type": "Mounted Storage Volume",
                    "event_type": "usb_history" if drive_letter not in {"C:", "D:"} else "file_meta",
                    "user": "",
                    "actor": "",
                    "host": "",
                    "process": "",
                    "pid": "",
                    "action": f"Volume Mounted ({drive_letter})",
                    "object": drive_letter,
                    "target": drive_letter,
                    "path": drive_letter,
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"Mounted volume mapping | Drive: {drive_letter} | Signature: {hex_data[:32]}",
                    "raw_data": json.dumps({"drive": drive_letter, "signature": hex_data}),
                    "parser_name": "registry_mounted_devices",
                    "source_file": filename,
                    "time_kind": "event",
                    "observation_time": "",
                }
            )
    return events


def _parse_system_info(reg: Any, filename: str) -> list[dict]:
    """Extract ComputerName, TimeZone, and OS build info."""
    events: list[dict] = []
    # Computer Name
    for p in ["CurrentControlSet\\Control\\ComputerName\\ComputerName", "Control\\ComputerName\\ComputerName"]:
        try:
            key = reg.open(p)
            cname = str(key.value("ComputerName").value())
            events.append(
                {
                    "event_id": "computer_name",
                    "timestamp": key.timestamp(),
                    "timestamp_utc": key.timestamp().isoformat() if key.timestamp() else "",
                    "source": f"Registry System ({filename})",
                    "source_type": SOURCE,
                    "artifact_type": "System Information",
                    "event_type": "system_info",
                    "user": "",
                    "actor": "",
                    "host": cname,
                    "process": "",
                    "pid": "",
                    "action": "Host System Identification",
                    "object": cname,
                    "target": cname,
                    "path": "",
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"System Hostname: {cname}",
                    "raw_data": json.dumps({"computer_name": cname}),
                    "parser_name": "registry_sysinfo",
                    "source_file": filename,
                    "time_kind": "observation",
                    "observation_time": key.timestamp().isoformat() if key.timestamp() else "",
                }
            )
            break
        except Exception:
            continue
    return events


def _parse_sam_accounts(reg: Any, filename: str) -> list[dict]:
    """Parse SAM user accounts and RIDs."""
    events: list[dict] = []
    sam_paths = ["SAM\\Domains\\Account\\Users\\Names", "Domains\\Account\\Users\\Names"]
    key = None
    for p in sam_paths:
        try:
            key = reg.open(p)
            break
        except Exception:
            continue
    if not key:
        return events

    for ukey in key.subkeys():
        uname = ukey.name()
        events.append(
            {
                "event_id": "sam_user",
                "timestamp": ukey.timestamp(),
                "timestamp_utc": ukey.timestamp().isoformat() if ukey.timestamp() else "",
                "source": f"Registry SAM ({filename})",
                "source_type": SOURCE,
                "artifact_type": "User Account (SAM)",
                "event_type": "account_info",
                "user": uname,
                "actor": uname,
                "host": "",
                "process": "",
                "pid": "",
                "action": "SAM User Account Record",
                "object": uname,
                "target": uname,
                "path": "",
                "source_path": "",
                "destination_path": "",
                "source_ip": "",
                "source_port": "",
                "destination_ip": "",
                "destination_port": "",
                "description": f"Local user account in SAM: {uname}",
                "raw_data": json.dumps({"user": uname, "timestamp": str(ukey.timestamp())}),
                "parser_name": "registry_sam",
                "source_file": filename,
                "time_kind": "observation",
                "observation_time": ukey.timestamp().isoformat() if ukey.timestamp() else "",
            }
        )
    return events


def _fallback_summary(path: Path) -> list[dict]:
    """Fallback when binary structure cannot be decoded."""
    st = path.stat()
    mtime = datetime.utcfromtimestamp(st.st_mtime)
    return [
        {
            "event_id": "registry_hive_ingested",
            "timestamp": mtime,
            "timestamp_utc": mtime.isoformat(),
            "source": f"Registry Hive ({path.name})",
            "source_type": SOURCE,
            "artifact_type": "Registry Hive",
            "event_type": "registry_hive",
            "user": "",
            "actor": "",
            "host": "",
            "process": "",
            "pid": "",
            "action": "Registry Hive Ingested",
            "object": path.name,
            "target": path.name,
            "path": str(path),
            "source_path": "",
            "destination_path": "",
            "source_ip": "",
            "source_port": "",
            "destination_ip": "",
            "destination_port": "",
            "description": f"Registry hive file ingested: {path.name} ({st.st_size} bytes)",
            "raw_data": f"size={st.st_size}",
            "parser_name": "registry_fallback",
            "source_file": path.name,
            "time_kind": "observation",
            "observation_time": mtime.isoformat(),
        }
    ]
