from pathlib import Path
from . import evtx_parser, registry_parser, browser_parser, fs_parser, pcap_parser, meta_parser, json_parser

PARSERS = [
    evtx_parser,
    registry_parser,
    browser_parser,
    fs_parser,
    pcap_parser,
    meta_parser,
    json_parser,
]


def parse_file(path: Path, source_hint: str = "") -> list[dict]:
    events: list[dict] = []
    name = path.name.lower()
    suffix = path.suffix.lower()
    for mod in PARSERS:
        try:
            if mod.can_parse(path, name, suffix, source_hint):
                events.extend(mod.parse(path))
        except Exception as exc:  # noqa: BLE001
            events.append(
                {
                    "source_type": getattr(mod, "SOURCE", "unknown"),
                    "event_type": "parser_error",
                    "timestamp": None,
                    "description": f"{mod.__name__} failed on {path.name}: {exc}",
                    "actor": "",
                    "target": path.name,
                    "raw_data": str(exc),
                }
            )
    if not events:
        events.append(
            {
                "source_type": source_hint or "file",
                "event_type": "evidence_ingested",
                "timestamp": None,
                "description": f"Evidence file ingested without specialized parser: {path.name}",
                "actor": "",
                "target": path.name,
                "raw_data": "",
            }
        )
    return events
