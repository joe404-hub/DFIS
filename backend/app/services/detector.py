"""Automatic File Type & Forensic Artifact Detection Engine.

Inspects file magic bytes / signatures and structural content to accurately
determine artifact types without depending strictly on file names or extensions.
"""

from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DetectionResult:
    artifact_type: str  # evtx, registry_hive, browser_sqlite, pcap, memory, filesystem, document_metadata, csv_tabular, json, container, unknown
    canonical_source_type: str  # windows_event, registry, browser, network, memory, filesystem, metadata, structured
    subtype: str = ""  # chrome_history, firefox_places, system_hive, ntuser_hive, etc.
    magic_signature: str = ""  # ElfFile, regf, SQLite 3, PCAP, etc.
    mime_type: str = "application/octet-stream"
    confidence: float = 1.0  # 1.0 = magic bytes match, 0.8 = structural check, 0.5 = fallback heuristic
    description: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_type": self.artifact_type,
            "canonical_source_type": self.canonical_source_type,
            "subtype": self.subtype,
            "magic_signature": self.magic_signature,
            "mime_type": self.mime_type,
            "confidence": self.confidence,
            "description": self.description,
            "details": self.details,
        }


# Known binary file signatures (magic bytes)
MAGIC_SIGNATURES = [
    # Windows Event Log (EVTX): "ElfFile\x00"
    (b"ElfFile\x00", 0, "evtx", "windows_event", "windows_evtx", "ElfFile (Windows Event Log binary)", "application/x-ms-evtx"),
    # Windows Registry Hive: "regf"
    (b"regf", 0, "registry_hive", "registry", "registry_hive", "regf (Windows Registry Hive)", "application/x-ms-registry"),
    # SQLite 3 Database: "SQLite format 3\x00"
    (b"SQLite format 3\x00", 0, "browser_sqlite", "browser", "sqlite_database", "SQLite format 3 database", "application/x-sqlite3"),
    # PCAP Microsecond format (little-endian & big-endian)
    (b"\xd4\xc3\xb2\xa1", 0, "pcap", "network", "pcap_le", "PCAP network capture (LE)", "application/vnd.tcpdump.pcap"),
    (b"\xa1\xb2\xc3\xd4", 0, "pcap", "network", "pcap_be", "PCAP network capture (BE)", "application/vnd.tcpdump.pcap"),
    # PCAP Nanosecond format
    (b"\x4d\x3c\xb2\xa1", 0, "pcap", "network", "pcap_nano_le", "PCAP nanosecond capture (LE)", "application/vnd.tcpdump.pcap"),
    (b"\xa1\xb2\x3c\x4d", 0, "pcap", "network", "pcap_nano_be", "PCAP nanosecond capture (BE)", "application/vnd.tcpdump.pcap"),
    # PCAPNG Section Header Block: "\n\r\r\n"
    (b"\x0a\x0d\x0d\x0a", 0, "pcap", "network", "pcapng", "PCAPNG network capture", "application/x-pcapng"),
    # ZIP Container: "PK\x03\x04", "PK\x05\x06", "PK\x07\x08"
    (b"PK\x03\x04", 0, "container", "container", "zip_archive", "PK Zip Archive", "application/zip"),
    (b"PK\x05\x06", 0, "container", "container", "zip_empty", "PK Zip Archive (Empty/End)", "application/zip"),
    (b"PK\x07\x08", 0, "container", "container", "zip_spanned", "PK Zip Archive (Spanned)", "application/zip"),
    # 7-Zip Container: "7z\xbc\xaf\x27\x1c"
    (b"7z\xbc\xaf\x27\x1c", 0, "container", "container", "7z_archive", "7-Zip Archive", "application/x-7z-compressed"),
    # GZIP: "\x1f\x8b"
    (b"\x1f\x8b", 0, "container", "container", "gzip", "GZIP compressed archive", "application/gzip"),
    # BZIP2: "BZh"
    (b"BZh", 0, "container", "container", "bzip2", "BZIP2 compressed archive", "application/x-bzip2"),
    # XZ: "\xfd7zXZ\x00"
    (b"\xfd7zXZ\x00", 0, "container", "container", "xz", "XZ compressed archive", "application/x-xz"),
    # PDF: "%PDF-"
    (b"%PDF-", 0, "document_metadata", "metadata", "pdf_document", "PDF Document", "application/pdf"),
    # JPEG: "\xff\xd8\xff"
    (b"\xff\xd8\xff", 0, "document_metadata", "metadata", "jpeg_image", "JPEG Image", "image/jpeg"),
    # PNG: "\x89PNG\r\n\x1a\n"
    (b"\x89PNG\r\n\x1a\n", 0, "document_metadata", "metadata", "png_image", "PNG Image", "image/png"),
    # GIF: "GIF87a" / "GIF89a"
    (b"GIF87a", 0, "document_metadata", "metadata", "gif_image", "GIF Image", "image/gif"),
    (b"GIF89a", 0, "document_metadata", "metadata", "gif_image", "GIF Image", "image/gif"),
    # Windows Crash Dump / Memory: "PAGEDUMP", "DU64", "PAGE"
    (b"PAGEDUMP", 0, "memory", "memory", "windows_crash_dump", "Windows Crash Dump", "application/x-dmp"),
    (b"DU64", 0, "memory", "memory", "windows_dump_64", "Windows 64-bit Memory Dump", "application/x-dmp"),
    (b"PAGE", 0, "memory", "memory", "windows_page_dump", "Windows Page Memory Dump", "application/x-dmp"),
    (b"MDMP", 0, "memory", "memory", "minidump", "Windows Minidump", "application/x-dmp"),
    # NTFS MFT Record: "FILE" / "BAAD"
    (b"FILE", 0, "filesystem", "filesystem", "ntfs_mft", "NTFS MFT Record", "application/octet-stream"),
]


def detect_file_type(path: Path | str) -> DetectionResult:
    """Identify the forensic file type based on file magic bytes, content, and structure."""
    path = Path(path)
    if not path.is_file():
        return DetectionResult(
            artifact_type="unknown",
            canonical_source_type="unknown",
            description=f"File not found: {path}",
            confidence=0.0,
        )

    file_size = path.stat().st_size
    if file_size == 0:
        return DetectionResult(
            artifact_type="empty",
            canonical_source_type="unknown",
            description="Empty file (0 bytes)",
            confidence=1.0,
        )

    # 1. Read initial chunk for magic bytes inspection
    header_chunk = b""
    try:
        with open(path, "rb") as f:
            header_chunk = f.read(8192)
    except Exception as exc:
        return DetectionResult(
            artifact_type="error",
            canonical_source_type="unknown",
            description=f"Error reading file header: {exc}",
            confidence=0.0,
        )

    # 2. Check Magic Byte Signatures
    for sig, offset, art_type, can_src, sub, desc, mime in MAGIC_SIGNATURES:
        if len(header_chunk) >= offset + len(sig):
            if header_chunk[offset : offset + len(sig)] == sig:
                # Specialized sub-classification for SQLite databases
                if art_type == "browser_sqlite":
                    return _classify_sqlite_db(path, desc, mime)
                # Specialized sub-classification for Registry hives
                if art_type == "registry_hive":
                    return _classify_registry_hive(path, header_chunk, desc, mime)
                # Specialized check for Office documents packaged as ZIP (docx, xlsx)
                if art_type == "container" and (path.suffix.lower() in {".docx", ".xlsx", ".pptx"} or b"[Content_Types].xml" in header_chunk):
                    return DetectionResult(
                        artifact_type="document_metadata",
                        canonical_source_type="metadata",
                        subtype="office_document",
                        magic_signature="PK Zip Container (Office XML)",
                        mime_type="application/vnd.openxmlformats-officedocument",
                        confidence=1.0,
                        description="Office OpenXML Document",
                    )
                return DetectionResult(
                    artifact_type=art_type,
                    canonical_source_type=can_src,
                    subtype=sub,
                    magic_signature=desc,
                    mime_type=mime,
                    confidence=1.0,
                    description=desc,
                )

    # 3. Check for TAR container (magic "ustar" at offset 257)
    if len(header_chunk) >= 262 and header_chunk[257:262] == b"ustar":
        return DetectionResult(
            artifact_type="container",
            canonical_source_type="container",
            subtype="tar_archive",
            magic_signature="POSIX tar archive (ustar)",
            mime_type="application/x-tar",
            confidence=1.0,
            description="TAR Archive",
        )

    # 4. Text & Structured Data Inspection
    text_result = _inspect_text_content(path, header_chunk)
    if text_result:
        return text_result

    # 5. Extension-based fallback if magic bytes did not match
    return _extension_fallback(path)


def _classify_sqlite_db(path: Path, base_desc: str, mime: str) -> DetectionResult:
    """Inspect tables inside SQLite database to distinguish Chrome History, Firefox Places, Cookies, etc."""
    tables: set[str] = set()
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
        con.close()
    except Exception:
        pass

    details = {"tables": sorted(tables)}
    if "urls" in tables and "visits" in tables:
        return DetectionResult(
            artifact_type="browser_sqlite",
            canonical_source_type="browser",
            subtype="chrome_history",
            magic_signature="SQLite 3 (Chrome/Chromium History)",
            mime_type=mime,
            confidence=1.0,
            description="Chrome / Chromium / Edge Browser History & Downloads database",
            details=details,
        )
    if "moz_places" in tables or "moz_historyvisits" in tables:
        return DetectionResult(
            artifact_type="browser_sqlite",
            canonical_source_type="browser",
            subtype="firefox_places",
            magic_signature="SQLite 3 (Firefox Places)",
            mime_type=mime,
            confidence=1.0,
            description="Firefox Places / History SQLite database",
            details=details,
        )
    if "cookies" in tables or "moz_cookies" in tables:
        return DetectionResult(
            artifact_type="browser_sqlite",
            canonical_source_type="browser",
            subtype="browser_cookies",
            magic_signature="SQLite 3 (Browser Cookies)",
            mime_type=mime,
            confidence=1.0,
            description="Browser Cookies SQLite database",
            details=details,
        )
    if "downloads" in tables:
        return DetectionResult(
            artifact_type="browser_sqlite",
            canonical_source_type="browser",
            subtype="browser_downloads",
            magic_signature="SQLite 3 (Browser Downloads)",
            mime_type=mime,
            confidence=1.0,
            description="Browser Downloads SQLite database",
            details=details,
        )

    return DetectionResult(
        artifact_type="browser_sqlite",
        canonical_source_type="browser",
        subtype="generic_sqlite",
        magic_signature=base_desc,
        mime_type=mime,
        confidence=0.9,
        description=f"SQLite 3 Database (tables: {', '.join(sorted(tables)[:6]) or 'none'})",
        details=details,
    )


def _classify_registry_hive(path: Path, chunk: bytes, base_desc: str, mime: str) -> DetectionResult:
    """Inspect hive properties or strings to distinguish SYSTEM, SOFTWARE, SAM, NTUSER.DAT hives."""
    name_upper = path.name.upper()
    subtype = "windows_registry_hive"
    desc = "Windows Registry Hive"

    chunk_str = chunk.decode("latin1", errors="ignore").upper()
    if "CURRENTCONTROLSET" in chunk_str or "CONTROLSET001" in chunk_str or "SYSTEM" in name_upper:
        subtype = "system_hive"
        desc = "Windows SYSTEM Registry Hive (Services, USBSTOR, Mounted Devices)"
    elif "MICROSOFT\\WINDOWS NT" in chunk_str or "SOFTWARE" in name_upper:
        subtype = "software_hive"
        desc = "Windows SOFTWARE Registry Hive (Installed Apps, Run Keys, OS Info)"
    elif "USERASSIST" in chunk_str or "RECENTDOCS" in chunk_str or "NTUSER" in name_upper or name_upper.endswith(".DAT"):
        subtype = "ntuser_hive"
        desc = "Windows NTUSER.DAT User Registry Hive (UserAssist, RecentDocs, RunMRU)"
    elif "DOMAINS\\ACCOUNT\\USERS" in chunk_str or "SAM" in name_upper:
        subtype = "sam_hive"
        desc = "Windows SAM Registry Hive (User Accounts & RIDs)"
    elif "SECURITY" in name_upper:
        subtype = "security_hive"
        desc = "Windows SECURITY Registry Hive (LSA Secrets, Audit Policies)"

    return DetectionResult(
        artifact_type="registry_hive",
        canonical_source_type="registry",
        subtype=subtype,
        magic_signature="regf (Windows Registry Hive)",
        mime_type=mime,
        confidence=1.0,
        description=desc,
    )


def _inspect_text_content(path: Path, chunk: bytes) -> DetectionResult | None:
    """Inspect plain text files for XML events, CSV tables, JSON data, or Volatility memory outputs."""
    try:
        text = chunk.decode("utf-8-sig", errors="replace")
    except Exception:
        try:
            text = chunk.decode("latin1", errors="replace")
        except Exception:
            return None

    stripped = text.strip()
    if not stripped:
        return None

    # Check XML event log
    if stripped.startswith("<?xml") or "<Event " in text or "<Events>" in text or "<Event>" in text:
        return DetectionResult(
            artifact_type="evtx",
            canonical_source_type="windows_event",
            subtype="windows_event_xml",
            magic_signature="XML Windows Event Log",
            mime_type="application/xml",
            confidence=0.95,
            description="Windows Event Log (XML format)",
        )

    # Check JSON / NDJSON
    if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
        try:
            full_text = path.read_text(encoding="utf-8-sig", errors="replace")
            json.loads(full_text)
            return DetectionResult(
                artifact_type="json",
                canonical_source_type="structured",
                subtype="json_document",
                magic_signature="JSON data structure",
                mime_type="application/json",
                confidence=0.95,
                description="JSON Structured Data",
            )
        except Exception:
            pass

    # Check Memory text dumps / Volatility dumps
    text_lower = text.lower()
    if (
        "synthetic memory" in text_lower
        or "volatility" in text_lower
        or ("process:" in text_lower and "pid:" in text_lower)
        or ("pslist" in text_lower and "offset" in text_lower)
        or ("netscan" in text_lower and "foreignaddress" in text_lower)
    ):
        return DetectionResult(
            artifact_type="memory",
            canonical_source_type="memory",
            subtype="memory_text",
            magic_signature="Memory Process/Network Dump Text",
            mime_type="text/plain",
            confidence=0.9,
            description="Memory Snapshot / Volatility Output",
        )

    # Check CSV / TSV tabular data
    csv_subtype = _classify_csv_structure(path, text)
    if csv_subtype:
        source_map = {
            "windows_security_csv": ("windows_event", "Windows Security Events CSV"),
            "windows_system_csv": ("windows_event", "Windows System Events CSV"),
            "registry_csv": ("registry", "Registry Artifacts CSV"),
            "browser_csv": ("browser", "Browser Activity CSV"),
            "browser_cookie_csv": ("browser", "Browser Cookies CSV"),
            "network_csv": ("network", "Network Packets CSV"),
            "filesystem_csv": ("filesystem", "Filesystem Activity CSV"),
            "memory_csv": ("memory", "Memory Process List CSV"),
            "metadata_csv": ("metadata", "File Metadata CSV"),
            "generic_csv": ("structured", "Structured CSV Table"),
        }
        can_src, label = source_map.get(csv_subtype, ("structured", "Delimited Tabular Data"))
        return DetectionResult(
            artifact_type="csv_tabular",
            canonical_source_type=can_src,
            subtype=csv_subtype,
            magic_signature="Delimited Tabular Text (CSV/TSV)",
            mime_type="text/csv",
            confidence=0.85,
            description=label,
        )

    return None


def _classify_csv_structure(path: Path, sample_text: str) -> str | None:
    """Classify CSV structure by analyzing headers and rows."""
    lines = [line.strip() for line in sample_text.splitlines() if line.strip()]
    if not lines:
        return None

    first_line = lines[0]
    # Check if there is a delimiter (comma, semicolon, tab, pipe)
    delims = [",", ";", "\t", "|"]
    best_delim = max(delims, key=lambda d: first_line.count(d))
    if first_line.count(best_delim) < 1:
        if path.suffix.lower() == ".csv":
            return "generic_csv"
        return None

    header_cols = [c.strip().lower().replace(" ", "_").replace("-", "_") for c in first_line.split(best_delim)]
    header_blob = " ".join(header_cols)
    name_blob = f"{path.parent.name}/{path.name}".lower()

    if any(k in header_blob for k in ("eventid", "event_id", "timecreated", "accountname", "subjectusername")) or "security" in name_blob:
        return "windows_security_csv"
    if "system" in name_blob and "file" not in name_blob:
        return "windows_system_csv"
    if any(k in header_blob for k in ("key_or_value", "hive", "key", "valuename")) or "registry" in name_blob:
        return "registry_csv"
    if any(k in header_blob for k in ("domain", "cookie", "creation_time")) and ("cookie" in name_blob or "domain" in header_blob):
        return "browser_cookie_csv"
    if any(k in header_blob for k in ("visit_time", "url", "browser", "history", "download")) or "browser" in name_blob:
        return "browser_csv"
    if any(k in header_blob for k in ("src_ip", "dst_ip", "source_ip", "dest_ip", "protocol", "packet", "pcap")) or "network" in name_blob:
        return "network_csv"
    if any(k in header_blob for k in ("process", "pid", "ppid", "threads")) or "memory" in name_blob:
        return "memory_csv"
    if any(k in header_blob for k in ("path", "filename", "filepath", "mtime", "filesize")) or "file" in name_blob:
        return "filesystem_csv"
    if "metadata" in name_blob:
        return "metadata_csv"

    if path.suffix.lower() in {".csv", ".tsv"}:
        return "generic_csv"
    return None


def _extension_fallback(path: Path) -> DetectionResult:
    """Fallback classifier based on file extension and name."""
    suf = path.suffix.lower()
    name = path.name.lower()

    if suf == ".evtx":
        return DetectionResult("evtx", "windows_event", "windows_evtx", "Extension (.evtx)", "application/x-ms-evtx", 0.7, "Windows Event Log")
    if suf in {".hiv", ".hive", ".dat"} or name in {"ntuser.dat", "system", "software", "sam", "security"}:
        return DetectionResult("registry_hive", "registry", "registry_hive", "Extension/Name (Registry)", "application/x-ms-registry", 0.7, "Windows Registry Hive")
    if suf in {".sqlite", ".db"} or name in {"history", "places.sqlite", "cookies.sqlite", "web data"}:
        return DetectionResult("browser_sqlite", "browser", "sqlite_database", "Extension/Name (SQLite)", "application/x-sqlite3", 0.7, "SQLite Database")
    if suf in {".pcap", ".pcapng", ".cap"}:
        return DetectionResult("pcap", "network", "pcap_network", "Extension (.pcap)", "application/vnd.tcpdump.pcap", 0.7, "PCAP Network Capture")
    if suf == ".csv":
        return DetectionResult("csv_tabular", "structured", "generic_csv", "Extension (.csv)", "text/csv", 0.7, "CSV Data Table")
    if suf in {".json", ".ndjson"}:
        return DetectionResult("json", "structured", "json_document", "Extension (.json)", "application/json", 0.7, "JSON Data")
    if suf in {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".docx", ".xlsx"}:
        return DetectionResult("document_metadata", "metadata", "document", "Extension (Document/Image)", "application/octet-stream", 0.7, "Document / Image Metadata")
    if suf in {".zip", ".tar", ".gz", ".7z", ".bz2"}:
        return DetectionResult("container", "container", "archive", "Extension (Archive)", "application/zip", 0.7, "Compressed Archive")

    return DetectionResult(
        artifact_type="unknown",
        canonical_source_type="unknown",
        subtype="unidentified",
        magic_signature="Unknown",
        mime_type="application/octet-stream",
        confidence=0.2,
        description=f"Unrecognized file type: {path.name}",
    )
