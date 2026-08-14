"""Artifact Parser Manager.

Dispatches detected forensic artifact files to specialized parsers
and normalizes outputs into the Common Forensic Event Schema.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.services.detector import DetectionResult, detect_file_type

from . import (
    browser_parser,
    csv_util,
    evtx_parser,
    fs_parser,
    json_parser,
    memory_parser,
    meta_parser,
    pcap_parser,
    registry_parser,
    tabular_parser,
)

PARSER_MODULES = [
    evtx_parser,
    registry_parser,
    browser_parser,
    tabular_parser,
    pcap_parser,
    memory_parser,
    fs_parser,
    meta_parser,
    json_parser,
]

SKIP_EXACT = {
    "expected_timeline.csv",
    "readme.txt",
    "readme.md",
    "license",
    "license.txt",
    "case_manifest.json",
    ".ds_store",
    "thumbs.db",
}
SKIP_SUBSTRINGS = ("expected_timeline", "ground_truth", "groundtruth", "evaluation_timeline")


def is_evaluation_or_docs(path: Path) -> str | None:
    """Classify non-evidence documentation / evaluation files that should be excluded from forensic timeline."""
    name = path.name.lower()
    if name in SKIP_EXACT:
        if "expected" in name or "ground" in name:
            return "evaluation_ground_truth"
        if name.startswith("readme") or name.startswith("license"):
            return "documentation"
        if name == "case_manifest.json":
            return "case_inventory_not_timeline"
        return "system_metadata_excluded"
    if any(s in name for s in SKIP_SUBSTRINGS):
        return "evaluation_ground_truth"
    return None


def classify_skipped(path: Path) -> str | None:
    return is_evaluation_or_docs(path)


def parse_file(path: Path, source_hint: str = "", detection: DetectionResult | None = None) -> list[dict]:
    """Parse a forensic file using automatic detection or specific parser matching."""
    reason = is_evaluation_or_docs(path)
    if reason:
        return []

    if detection is None:
        detection = detect_file_type(path)

    events: list[dict] = []
    name = path.name.lower()
    suffix = path.suffix.lower()

    # Route based on detected artifact type first
    routed = False
    if detection.artifact_type == "evtx":
        events.extend(evtx_parser.parse(path))
        routed = True
    elif detection.artifact_type == "registry_hive":
        events.extend(registry_parser.parse(path))
        routed = True
    elif detection.artifact_type == "browser_sqlite":
        events.extend(browser_parser.parse(path))
        routed = True
    elif detection.artifact_type == "pcap":
        events.extend(pcap_parser.parse(path))
        routed = True
    elif detection.artifact_type == "memory":
        events.extend(memory_parser.parse(path))
        routed = True
    elif detection.artifact_type == "csv_tabular":
        events.extend(tabular_parser.parse(path))
        routed = True
    elif detection.artifact_type == "json":
        events.extend(json_parser.parse(path))
        routed = True
    elif detection.artifact_type == "document_metadata":
        events.extend(meta_parser.parse(path))
        routed = True

    # Fallback to scanning all parser modules if not handled or 0 events produced
    if not events and not routed:
        for mod in PARSER_MODULES:
            try:
                if mod.can_parse(path, name, suffix, source_hint or detection.artifact_type):
                    parsed_events = mod.parse(path)
                    if parsed_events:
                        events.extend(parsed_events)
                        break
            except Exception as exc:
                events.append(
                    {
                        "event_id": "parser_error",
                        "source_type": getattr(mod, "SOURCE", "unknown"),
                        "event_type": "parser_error",
                        "artifact_type": "Parser Error",
                        "timestamp": None,
                        "timestamp_utc": "",
                        "description": f"{mod.__name__} failed on {path.name}: {exc}",
                        "user": "",
                        "actor": "",
                        "host": "",
                        "process": "",
                        "pid": "",
                        "action": "Parser Exception",
                        "object": path.name,
                        "target": path.name,
                        "path": str(path),
                        "source_path": "",
                        "destination_path": "",
                        "source_ip": "",
                        "source_port": "",
                        "destination_ip": "",
                        "destination_port": "",
                        "raw_data": str(exc),
                        "parser_name": mod.__name__,
                        "source_file": path.name,
                        "time_kind": "event",
                        "observation_time": "",
                    }
                )

    return events
