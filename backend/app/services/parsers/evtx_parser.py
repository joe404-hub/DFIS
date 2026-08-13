from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

SOURCE = "windows_event"


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    return suffix == ".evtx" or "event" in name and suffix == ".xml"


def parse(path: Path) -> list[dict]:
    if path.suffix.lower() == ".xml":
        return _parse_xml(path)
    try:
        from Evtx.Evtx import Evtx
    except Exception:
        return []
    events = []
    with Evtx(str(path)) as log:
        for rec in log.records():
            try:
                xml = rec.xml()
                events.append(_from_xml_string(xml))
            except Exception:
                continue
    return [e for e in events if e]


def _parse_xml(path: Path) -> list[dict]:
    root = ET.parse(path).getroot()
    events = []
    for ev in root.iter():
        if ev.tag.endswith("Event") or ev.tag == "Event":
            events.append(_from_elem(ev))
    return [e for e in events if e]


def _from_xml_string(xml: str) -> dict | None:
    try:
        return _from_elem(ET.fromstring(xml))
    except Exception:
        return None


def _from_elem(elem: ET.Element) -> dict | None:
    ns = ""
    if elem.tag.startswith("{"):
        ns = elem.tag.split("}")[0] + "}"

    def find(path):
        return elem.find(f".//{ns}{path}") if ns else elem.find(f".//{path}")

    system = find("System")
    eid = ""
    ts = None
    if system is not None:
        eid_el = system.find(f"{ns}EventID") if ns else system.find("EventID")
        time_el = system.find(f"{ns}TimeCreated") if ns else system.find("TimeCreated")
        eid = (eid_el.text or "") if eid_el is not None else ""
        if time_el is not None:
            raw = time_el.attrib.get("SystemTime")
            if raw:
                try:
                    ts = datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None)
                except Exception:
                    ts = None
    text = " ".join((t or "").strip() for t in elem.itertext() if (t or "").strip())[:800]
    mapping = {
        "4624": ("logon", "Successful Windows logon"),
        "4634": ("logout", "Windows logoff"),
        "4625": ("failed_logon", "Failed logon attempt"),
        "4688": ("process_create", "Process creation"),
        "7045": ("service_install", "Service installed"),
        "6416": ("usb", "New external device recognized"),
    }
    etype, label = mapping.get(eid, (f"event_{eid or 'unknown'}", f"Windows event {eid or 'unknown'}"))
    return {
        "source_type": SOURCE,
        "event_type": etype,
        "timestamp": ts,
        "description": f"{label}. {text[:240]}",
        "actor": "",
        "target": eid,
        "raw_data": text[:2000],
    }
