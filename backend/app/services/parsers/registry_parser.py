from pathlib import Path

SOURCE = "registry"


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    return name.upper() in {"NTUSER.DAT", "SYSTEM", "SOFTWARE", "SAM"} or suffix in {".dat", ".hiv", ".hive"}


def parse(path: Path) -> list[dict]:
    try:
        from Registry import Registry
    except Exception:
        return _fallback(path)
    events = []
    try:
        reg = Registry.Registry(str(path))
    except Exception:
        return _fallback(path)
    interesting = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        "System\\CurrentControlSet\\Enum\\USBSTOR",
    ]
    for key_path in interesting:
        try:
            key = reg.open(key_path)
        except Exception:
            continue
        for val in key.values():
            events.append(
                {
                    "source_type": SOURCE,
                    "event_type": "registry_value",
                    "timestamp": getattr(key, "timestamp", lambda: None)(),
                    "description": f"Registry {key_path}\\{val.name()} = {str(val.value())[:200]}",
                    "actor": "",
                    "target": val.name(),
                    "raw_data": str(val.value())[:2000],
                }
            )
    return events or _fallback(path)


def _fallback(path: Path) -> list[dict]:
    return [
        {
            "source_type": SOURCE,
            "event_type": "registry_hive",
            "timestamp": None,
            "description": f"Registry hive ingested: {path.name}",
            "actor": "",
            "target": path.name,
            "raw_data": "",
        }
    ]
