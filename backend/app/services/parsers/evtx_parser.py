"""Windows Event Log (.evtx & XML) Forensic Parser.

Extracts rich event attributes (EventID, timestamp, user, host, process,
command line, IP, status, service, USB device, etc.) into the Common Forensic Event Schema.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

SOURCE = "windows_event"

# Canonical Event ID definitions and mappings
EVENT_MAP = {
    # Account & Authentication
    "4624": ("logon", "Logon", "Successful Windows logon"),
    "4625": ("failed_logon", "Failed Logon", "Failed logon attempt"),
    "4634": ("logoff", "Logoff", "User logged off"),
    "4647": ("logoff", "Logoff", "User initiated logoff"),
    "4672": ("admin_logon", "Privilege Assignment", "Special privileges assigned (admin logon)"),
    "4778": ("session_reconnect", "Session Reconnect", "Session reconnected"),
    "4779": ("session_disconnect", "Session Disconnect", "Session disconnected"),
    "4800": ("workstation_lock", "Workstation Lock", "Workstation locked"),
    "4801": ("workstation_unlock", "Workstation Unlock", "Workstation unlocked"),
    # Process Execution
    "4688": ("process_create", "Process Creation", "Process creation"),
    "4689": ("process_terminate", "Process Termination", "Process exit / termination"),
    "1": ("process_create", "Sysmon Process Create", "Sysmon process creation"),
    "5": ("process_terminate", "Sysmon Process Terminate", "Sysmon process termination"),
    # Services & Persistence
    "7045": ("service_install", "Service Installation", "Service installed in the system"),
    "4697": ("service_install", "Service Installation", "Service installed in the system"),
    "7036": ("service_state", "Service State Change", "Service entered state"),
    "7040": ("service_change", "Service Start Type Change", "Service start type was changed"),
    "4698": ("scheduled_task", "Scheduled Task Created", "Scheduled task created"),
    "4699": ("scheduled_task", "Scheduled Task Deleted", "Scheduled task deleted"),
    "4702": ("scheduled_task", "Scheduled Task Updated", "Scheduled task updated"),
    # Removable Media & USB Devices
    "6416": ("usb_connect", "USB / Device Connection", "New external device recognized"),
    "20001": ("usb_connect", "USB Plug-and-Play", "PnP device driver installed / connected"),
    "20003": ("usb_connect", "USB Plug-and-Play", "PnP device connected"),
    "2100": ("usb_connect", "USB Device Connected", "USB device connected"),
    "2102": ("usb_remove", "USB Device Removed", "USB device removed"),
    # File & Object Access
    "4663": ("file_access", "Object Access", "Attempt made to access an object"),
    "4656": ("file_access", "Handle Request", "Handle to an object was requested"),
    "4660": ("file_delete", "Object Deleted", "Object was deleted"),
    "11": ("file_create", "Sysmon File Create", "Sysmon file creation detected"),
    "15": ("file_stream", "Sysmon Alternate Stream", "Sysmon alternate data stream created"),
    # PowerShell
    "4104": ("powershell_script", "PowerShell Script Block", "PowerShell script block executed"),
    "4103": ("powershell_module", "PowerShell Pipeline", "PowerShell pipeline execution"),
    "400": ("powershell_engine", "PowerShell Engine", "PowerShell engine lifecycle"),
    "600": ("powershell_provider", "PowerShell Provider", "PowerShell provider lifecycle"),
    # Network Activity
    "5156": ("network_flow", "WFP Connection", "Windows Filtering Platform allowed connection"),
    "5158": ("network_bind", "WFP Bind", "Windows Filtering Platform allowed bind"),
    "3": ("network_flow", "Sysmon Network Connection", "Sysmon network connection detected"),
    # Audit & Security Evasion
    "1102": ("log_cleared", "Security Log Cleared", "The audit log was cleared"),
    "104": ("log_cleared", "System Log Cleared", "The system event log was cleared"),
    "4719": ("policy_change", "Audit Policy Change", "System audit policy was changed"),
    # Account Management
    "4720": ("account_create", "User Account Created", "A user account was created"),
    "4722": ("account_enable", "User Account Enabled", "A user account was enabled"),
    "4724": ("password_reset", "Password Reset Attempt", "Attempt made to reset account password"),
    "4726": ("account_delete", "User Account Deleted", "A user account was deleted"),
    "4728": ("group_member_add", "Security Group Member Added", "Member added to security group"),
    "4732": ("group_member_add", "Local Group Member Added", "Member added to local group"),
}


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    if suffix == ".evtx":
        return True
    if suffix == ".xml" and ("event" in name.lower() or "security" in name.lower() or "system" in name.lower()):
        return True
    if hint in {"evtx", "windows_event"}:
        return True
    try:
        with open(path, "rb") as f:
            header = f.read(8)
            if header.startswith(b"ElfFile\x00"):
                return True
    except Exception:
        pass
    return False


def parse(path: Path) -> list[dict]:
    """Parse .evtx or XML event log into normalized forensic events."""
    # Check if binary EVTX or XML
    is_xml = False
    try:
        with open(path, "rb") as f:
            first_chunk = f.read(64)
            if first_chunk.startswith(b"ElfFile\x00"):
                is_xml = False
            elif b"<?xml" in first_chunk or b"<Event" in first_chunk:
                is_xml = True
            elif path.suffix.lower() == ".xml":
                is_xml = True
    except Exception:
        pass

    if is_xml:
        return _parse_xml(path)

    # Parse binary EVTX with python-evtx
    events: list[dict] = []
    try:
        from Evtx.Evtx import Evtx

        with Evtx(str(path)) as log:
            for rec in log.records():
                try:
                    xml_str = rec.xml()
                    ev = _from_xml_string(xml_str, path.name)
                    if ev:
                        events.append(ev)
                except Exception:
                    continue
    except Exception as exc:
        # Fallback if Evtx failed or unreadable
        events.append(
            {
                "source_type": SOURCE,
                "event_type": "evtx_error",
                "artifact_type": "Event Log",
                "timestamp": None,
                "timestamp_utc": "",
                "description": f"EVTX parser encountered error on {path.name}: {exc}",
                "actor": "",
                "target": path.name,
                "raw_data": str(exc),
                "source": f"Windows Event Log ({path.name})",
                "source_file": path.name,
                "parser_name": "evtx_binary",
            }
        )
    return events


def _parse_xml(path: Path) -> list[dict]:
    events: list[dict] = []
    try:
        root = ET.parse(path).getroot()
        for ev in root.iter():
            if ev.tag.endswith("Event") or ev.tag == "Event":
                parsed = _from_elem(ev, path.name)
                if parsed:
                    events.append(parsed)
    except Exception as exc:
        events.append(
            {
                "source_type": SOURCE,
                "event_type": "evtx_xml_error",
                "artifact_type": "Event Log XML",
                "timestamp": None,
                "timestamp_utc": "",
                "description": f"XML Event parser failed on {path.name}: {exc}",
                "actor": "",
                "target": path.name,
                "raw_data": str(exc),
                "source": f"Windows Event XML ({path.name})",
                "source_file": path.name,
                "parser_name": "evtx_xml",
            }
        )
    return events


def _from_xml_string(xml_str: str, filename: str) -> dict | None:
    try:
        root = ET.fromstring(xml_str)
        return _from_elem(root, filename)
    except Exception:
        return None


def _from_elem(elem: ET.Element, filename: str) -> dict | None:
    ns = ""
    if elem.tag.startswith("{"):
        ns = elem.tag.split("}")[0] + "}"

    def find(path: str) -> ET.Element | None:
        return elem.find(f".//{ns}{path}") if ns else elem.find(f".//{path}")

    def findall(path: str) -> list[ET.Element]:
        return elem.findall(f".//{ns}{path}") if ns else elem.findall(f".//{path}")

    # Extract System header elements
    system = find("System")
    eid = ""
    ts = None
    ts_utc_str = ""
    host = ""
    channel = ""
    provider = ""

    if system is not None:
        eid_el = system.find(f"{ns}EventID") if ns else system.find("EventID")
        time_el = system.find(f"{ns}TimeCreated") if ns else system.find("TimeCreated")
        comp_el = system.find(f"{ns}Computer") if ns else system.find("Computer")
        chan_el = system.find(f"{ns}Channel") if ns else system.find("Channel")
        prov_el = system.find(f"{ns}Provider") if ns else system.find("Provider")

        eid = (eid_el.text or "").strip() if eid_el is not None else ""
        if comp_el is not None and comp_el.text:
            host = comp_el.text.strip()
        if chan_el is not None and chan_el.text:
            channel = chan_el.text.strip()
        if prov_el is not None:
            provider = prov_el.attrib.get("Name") or ""

        if time_el is not None:
            raw_time = time_el.attrib.get("SystemTime")
            if raw_time:
                ts_utc_str = raw_time
                try:
                    ts = datetime.fromisoformat(raw_time.replace("Z", "+00:00")).replace(tzinfo=None)
                except Exception:
                    ts = None

    # Extract EventData & UserData dictionary
    data_dict: dict[str, str] = {}
    for d in findall("Data"):
        name_attr = d.attrib.get("Name")
        val = (d.text or "").strip()
        if name_attr:
            data_dict[name_attr] = val
        elif val:
            data_dict[f"Param_{len(data_dict)+1}"] = val

    # Common Windows field extractions
    user = (
        data_dict.get("TargetUserName")
        or data_dict.get("SubjectUserName")
        or data_dict.get("AccountName")
        or data_dict.get("User")
        or ""
    )
    if user in {"-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"} and data_dict.get("SubjectUserName"):
        alt_user = data_dict.get("SubjectUserName", "")
        if alt_user and alt_user != "-":
            user = alt_user

    process_path = (
        data_dict.get("NewProcessName")
        or data_dict.get("ProcessName")
        or data_dict.get("Image")
        or data_dict.get("Application")
        or ""
    )
    process_name = process_path.replace("\\", "/").split("/")[-1] if process_path else ""

    cmdline = data_dict.get("CommandLine") or ""
    pid = data_dict.get("NewProcessId") or data_dict.get("ProcessId") or data_dict.get("ProcessID") or ""
    src_ip = data_dict.get("IpAddress") or data_dict.get("SourceAddress") or data_dict.get("SourceIp") or ""
    src_port = data_dict.get("IpPort") or data_dict.get("SourcePort") or ""
    dst_ip = data_dict.get("DestAddress") or data_dict.get("DestinationIp") or ""
    dst_port = data_dict.get("DestPort") or data_dict.get("DestinationPort") or ""

    service_name = data_dict.get("ServiceName") or data_dict.get("Service") or ""
    service_file = data_dict.get("ImagePath") or data_dict.get("ServiceFileName") or ""
    service_proc = service_file.replace("\\", "/").split("/")[-1] if service_file else ""
    device_name = data_dict.get("DeviceDescription") or data_dict.get("DeviceName") or data_dict.get("DeviceInstanceId") or ""
    object_name = data_dict.get("ObjectName") or data_dict.get("TargetFilename") or ""
    script_text = data_dict.get("ScriptBlockText") or ""

    # Map Event ID to canonical event type, artifact type, and description label
    mapping = EVENT_MAP.get(eid)
    if mapping:
        etype, art_type, label = mapping
    else:
        etype = f"event_{eid or 'unknown'}"
        art_type = f"Windows Event {eid or 'unknown'}"
        label = f"Windows Event {eid or 'unknown'}"

    # Build clear, rich forensic description
    desc_parts = [f"Windows Event {eid}: {label}"]
    if user and user != "-":
        desc_parts.append(f"User: {user}")
    if process_name:
        desc_parts.append(f"Process: {process_name}")
    if cmdline and cmdline != process_path:
        desc_parts.append(f"Cmd: {cmdline[:200]}")
    if service_name:
        desc_parts.append(f"Service: {service_name}")
    if device_name:
        desc_parts.append(f"Device: {device_name}")
    if object_name:
        desc_parts.append(f"Object: {object_name}")
    if src_ip and src_ip not in {"-", "127.0.0.1", "::1"}:
        desc_parts.append(f"Src: {src_ip}:{src_port}".rstrip(":"))
    if dst_ip:
        desc_parts.append(f"Dst: {dst_ip}:{dst_port}".rstrip(":"))
    if script_text:
        desc_parts.append(f"Script: {script_text[:120]}...")

    description = " | ".join(desc_parts)

    target_val = object_name or process_name or service_name or device_name or cmdline or eid

    # Action description
    action_val = label
    if etype == "process_create" and process_name:
        action_val = f"Process Create ({process_name})"
    elif etype == "logon":
        logon_type = data_dict.get("LogonType", "")
        logon_map = {"2": "Interactive", "3": "Network", "7": "Unlock", "10": "RemoteInteractive (RDP)"}
        action_val = f"Logon ({logon_map.get(logon_type, f'Type {logon_type}')})" if logon_type else "Logon"
    elif etype == "service_install" and service_name:
        action_val = f"Service Install ({service_name})"
    elif etype == "usb_connect" and device_name:
        action_val = f"USB Connect ({device_name})"

    raw_blob = json.dumps(
        {
            "event_id": eid,
            "channel": channel,
            "provider": provider,
            "host": host,
            "data": data_dict,
        },
        default=str,
    )[:4000]

    return {
        "event_id": eid,
        "timestamp": ts,
        "timestamp_utc": ts_utc_str,
        "source": f"Windows {channel or 'Event'}.evtx",
        "source_type": SOURCE,
        "artifact_type": art_type,
        "event_type": etype,
        "user": user,
        "actor": user,
        "host": host,
        "process": process_name or service_proc,
        "pid": pid,
        "action": action_val,
        "object": target_val,
        "target": target_val,
        "path": object_name or process_path or service_file,
        "source_path": process_path,
        "destination_path": "",
        "source_ip": src_ip,
        "source_port": src_port,
        "destination_ip": dst_ip,
        "destination_port": dst_port,
        "description": description,
        "raw_data": raw_blob,
        "parser_name": "evtx_parser",
        "source_file": filename,
        "time_kind": "event",
        "observation_time": "",
    }
