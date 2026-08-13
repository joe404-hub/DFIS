from pathlib import Path
from . import (
    evtx_parser,
    registry_parser,
    browser_parser,
    fs_parser,
    pcap_parser,
    meta_parser,
    json_parser,
    tabular_parser,
    memory_parser,
)

PARSERS = [
    evtx_parser,
    registry_parser,
    browser_parser,
    tabular_parser,
    fs_parser,
    pcap_parser,
    memory_parser,
    meta_parser,
    json_parser,
]

SKIP_EXACT = {
    "expected_timeline.csv",
    "readme.txt",
    "readme.md",
    "license",
    "license.txt",
}
SKIP_SUBSTRINGS = ("expected_timeline", "ground_truth", "groundtruth")
SKIP_JSON = {"case_manifest.json"}


def is_evaluation_or_docs(path: Path) -> str | None:
    name = path.name.lower()
    if name in SKIP_EXACT or name in SKIP_JSON:
        if "expected" in name or "ground" in name:
            return "evaluation_ground_truth"
        if name.startswith("readme") or name.startswith("license"):
            return "documentation"
        if name == "case_manifest.json":
            return "case_inventory_not_timeline"
        return "excluded"
    if any(s in name for s in SKIP_SUBSTRINGS):
        return "evaluation_ground_truth"
    return None


def parse_file(path: Path, source_hint: str = "") -> list[dict]:
    reason = is_evaluation_or_docs(path)
    if reason:
        return []

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
    return events


def classify_skipped(path: Path) -> str | None:
    return is_evaluation_or_docs(path)
