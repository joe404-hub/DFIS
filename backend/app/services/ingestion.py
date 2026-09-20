"""Automated Evidence Ingestion Engine.

Orchestrates the complete evidence processing pipeline:
Archive Ingestion → SHA-256 Integrity → Content-Based File Type Detection →
Specialized Artifact Parsing → Common Forensic Schema Normalization →
Timestamp Normalization → Deduplication → Event Correlation → Database Persistence →
Case RAG Vector Indexing → AI Classification & Risk Analysis.

Provides auditable, first-class parser status tracking:
- parsed: Successfully extracted relevant forensic events
- empty: Recognized artifact structure inspected, but no relevant records present
- needs_review / unsupported: Recognized artifact type, but extraction needs examiner review
- error: Parser encountered an exception
- excluded: Intentionally excluded non-evidence documentation / ground truth
- skipped: Processing deliberately bypassed (e.g. zero-byte file)
"""

from __future__ import annotations

import os
import shutil
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.db import EVIDENCE_DIR
from app.models import Artifact, Case, CustodyEvent, Evidence
from app.services.detector import DetectionResult, detect_file_type
from app.services.integrity import sha256_file
from app.services.parsers import classify_skipped, parse_file
from app.services.parsers.browser_parser import parse_with_diagnostics
from app.services.timeline import build_timeline, fingerprint


@dataclass
class IngestedFileReport:
    filename: str
    relative_path: str
    sha256: str
    size_bytes: int
    detected_type: str
    canonical_source: str
    subtype: str
    magic_signature: str
    parser_name: str
    events_extracted: int
    status: str  # parsed, empty, needs_review, unsupported, error, excluded, skipped
    reason: str = ""
    recommended_action: str = ""
    notes: str = ""


@dataclass
class IngestionSummary:
    case_id: int
    evidence_id: int
    archive_name: str
    archive_sha256: str
    total_files_discovered: int
    total_documentation_excluded: int
    total_artifacts_identified: int
    total_successfully_parsed: int
    total_empty_artifacts: int
    total_parser_errors: int
    total_unsupported: int
    total_events_extracted: int
    total_events_deduplicated: int
    total_correlated_groups: int
    files: list[IngestedFileReport] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    skipped_reasons: list[str] = field(default_factory=list)

    @property
    def total_files_parsed(self) -> int:
        return self.total_successfully_parsed

    @property
    def total_files_skipped(self) -> int:
        return self.total_documentation_excluded + self.total_empty_artifacts + self.total_unsupported


class EvidenceIngestionEngine:
    """Automated Forensic Ingestion Pipeline Manager."""

    def __init__(self, db: Session, case: Case):
        self.db = db
        self.case = case

    def ingest_evidence(
        self,
        file_path: Path,
        original_filename: str,
        notes: str = "",
    ) -> tuple[Evidence, IngestionSummary]:
        """Process an uploaded evidence package with full content inspection and auditable status logging."""
        file_path = Path(file_path)
        archive_digest = sha256_file(file_path)
        archive_size = file_path.stat().st_size

        # Detect the uploaded container/file
        top_detection = detect_file_type(file_path)

        ev = Evidence(
            case_id=self.case.id,
            filename=original_filename,
            stored_path=str(file_path),
            sha256=archive_digest,
            source_type=top_detection.canonical_source_type,
            detected_type=top_detection.artifact_type,
            magic_signature=top_detection.magic_signature,
            mime_type=top_detection.mime_type,
            size_bytes=archive_size,
            notes=notes or top_detection.description,
            integrity_ok=True,
        )
        self.db.add(ev)
        self.db.flush()

        # Record initial ingestion custody event
        self.db.add(
            CustodyEvent(
                case_id=self.case.id,
                evidence_id=ev.id,
                action="evidence_ingested",
                actor="Evidence Ingestion Engine",
                detail=f"Ingested {original_filename} ({archive_size} bytes) | SHA-256: {archive_digest} | Type: {top_detection.description}",
            )
        )

        # Extract archive if container
        work_files: list[tuple[Path, str]] = []  # (absolute_path, relative_display_name)
        if zipfile.is_zipfile(file_path) or top_detection.artifact_type == "container":
            extract_dir = file_path.parent / f"extracted_{ev.id}"
            extract_dir.mkdir(exist_ok=True)
            try:
                with zipfile.ZipFile(file_path) as zf:
                    for member in zf.infolist():
                        target_p = extract_dir / member.filename
                        if not target_p.resolve().is_relative_to(extract_dir.resolve()):
                            continue
                        zf.extract(member, extract_dir)
                for p in extract_dir.rglob("*"):
                    if p.is_file():
                        rel = str(p.relative_to(extract_dir))
                        work_files.append((p, rel))
            except Exception as exc:
                self.db.add(
                    CustodyEvent(
                        case_id=self.case.id,
                        evidence_id=ev.id,
                        action="extraction_warning",
                        actor="Evidence Ingestion Engine",
                        detail=f"Zip extraction warning on {original_filename}: {exc}",
                    )
                )
                work_files = [(file_path, original_filename)]
        else:
            work_files = [(file_path, original_filename)]

        raw_events: list[dict[str, Any]] = []
        file_reports: list[IngestedFileReport] = []
        skipped_details: list[str] = []
        warnings: list[str] = []

        # Process each discovered file
        for fp, rel_name in work_files:
            file_digest = sha256_file(fp)
            fsize = fp.stat().st_size

            # Check zero-byte file
            if fsize == 0:
                file_reports.append(
                    IngestedFileReport(
                        filename=fp.name,
                        relative_path=rel_name,
                        sha256=file_digest,
                        size_bytes=0,
                        detected_type="empty_file",
                        canonical_source="unknown",
                        subtype="zero_byte",
                        magic_signature="Empty (0 bytes)",
                        parser_name="None",
                        events_extracted=0,
                        status="skipped",
                        reason="Zero-byte file",
                        recommended_action="Verify if file was acquired correctly",
                        notes="File is 0 bytes",
                    )
                )
                skipped_details.append(f"{rel_name} (zero bytes)")
                continue

            # Check if file should be excluded from forensic timeline (documentation, evaluation ground truth)
            skip_reason = classify_skipped(fp)
            if skip_reason:
                skipped_details.append(f"{rel_name} ({skip_reason})")
                file_reports.append(
                    IngestedFileReport(
                        filename=fp.name,
                        relative_path=rel_name,
                        sha256=file_digest,
                        size_bytes=fsize,
                        detected_type="excluded_document",
                        canonical_source="metadata",
                        subtype=skip_reason,
                        magic_signature="Filtered Documentation / Ground Truth",
                        parser_name="None",
                        events_extracted=0,
                        status="excluded",
                        reason=f"Excluded from timeline: {skip_reason}",
                        recommended_action="None (Non-evidence file)",
                        notes="Intentionally excluded documentation or evaluation baseline",
                    )
                )
                continue

            # Automatic File Type Detection by magic bytes and structure
            detection = detect_file_type(fp)

            # Specialized execution and diagnostics for SQLite browser databases
            if detection.artifact_type == "browser_sqlite":
                parsed, diag = parse_with_diagnostics(fp)
                parser_name = "SQLite Browser Parser"
                if parsed:
                    status = "parsed"
                    reason = f"Successfully parsed {len(parsed)} browser events from tables: {', '.join(diag.get('tables', []))}"
                    rec_action = "Review extracted URL visits and downloads"
                else:
                    status = "empty" if diag.get("tables") else "needs_review"
                    reason = f"SQLite database inspected (tables: {', '.join(diag.get('tables', [])) or 'none'}). Expected browser history/download queries returned 0 records."
                    rec_action = "Inspect database schema and table rows"
                    warnings.append(
                        f"⚠️ Browser History database identified ({rel_name}) but no events were extracted. "
                        f"Reason: {reason} Recommended action: {rec_action}."
                    )
            else:
                # Other specialized parsers
                parser_name = self._parser_display_name(detection.artifact_type)
                try:
                    parsed = parse_file(fp, detection=detection)
                    if parsed:
                        status = "parsed"
                        reason = f"Extracted {len(parsed)} forensic events"
                        rec_action = "Correlate with timeline"
                    elif detection.artifact_type in {"evtx", "registry_hive", "pcap", "memory", "csv_tabular"}:
                        status = "empty"
                        reason = f"Recognized {detection.description} artifact, but 0 relevant forensic records found"
                        rec_action = "Inspect artifact structure"
                        warnings.append(f"⚠️ Artifact {rel_name} ({detection.description}) inspected but 0 events were extracted.")
                    else:
                        status = "unsupported"
                        reason = f"Unrecognized or unsupported artifact format ({detection.description})"
                        rec_action = "Check if custom parser is required"
                except Exception as exc:
                    parsed = []
                    status = "error"
                    reason = f"Parser exception: {exc}"
                    rec_action = "Inspect error logs and file corruption"
                    warnings.append(f"❌ Error parsing {rel_name}: {exc}")

            # Populate Common Forensic Schema fields
            if parsed:
                for rec in parsed:
                    rec["evidence_id"] = ev.id
                    rec["evidence_hash"] = file_digest
                    rec["source_file"] = rel_name
                    rec["fingerprint"] = fingerprint(rec)
                    raw_events.append(rec)

            file_reports.append(
                IngestedFileReport(
                    filename=fp.name,
                    relative_path=rel_name,
                    sha256=file_digest,
                    size_bytes=fsize,
                    detected_type=detection.artifact_type,
                    canonical_source=detection.canonical_source_type,
                    subtype=detection.subtype,
                    magic_signature=detection.magic_signature,
                    parser_name=parser_name,
                    events_extracted=len(parsed),
                    status=status,
                    reason=reason,
                    recommended_action=rec_action,
                    notes=f"Detected: {detection.description}",
                )
            )

        # Log custody event for excluded/warning items
        if warnings:
            self.db.add(
                CustodyEvent(
                    case_id=self.case.id,
                    evidence_id=ev.id,
                    action="ingestion_warnings",
                    actor="Evidence Ingestion Engine",
                    detail="; ".join(warnings[:10]),
                )
            )
        if skipped_details:
            self.db.add(
                CustodyEvent(
                    case_id=self.case.id,
                    evidence_id=ev.id,
                    action="artifact_classification",
                    actor="Evidence Ingestion Engine",
                    detail="Excluded non-evidence/empty items: " + "; ".join(skipped_details[:20]),
                )
            )

        # Execute Timeline Normalization, Deduplication, and Correlation
        timeline_events = build_timeline(raw_events)

        # Persist normalized artifacts to database
        for rec in timeline_events:
            art_row = self._create_artifact_row(ev.id, rec)
            self.db.add(art_row)

        ev.artifact_count = len(timeline_events)
        self.db.commit()
        self.db.refresh(ev)

        # Count metrics
        corr_count = sum(1 for e in timeline_events if e.get("source_type") == "correlated")
        doc_excluded_count = sum(1 for f in file_reports if f.status == "excluded")
        identified_count = sum(1 for f in file_reports if f.status not in {"excluded", "skipped"})
        parsed_count = sum(1 for f in file_reports if f.status == "parsed")
        empty_count = sum(1 for f in file_reports if f.status == "empty")
        error_count = sum(1 for f in file_reports if f.status == "error")
        unsupported_count = sum(1 for f in file_reports if f.status in {"unsupported", "needs_review"})

        summary = IngestionSummary(
            case_id=self.case.id,
            evidence_id=ev.id,
            archive_name=original_filename,
            archive_sha256=archive_digest,
            total_files_discovered=len(work_files),
            total_documentation_excluded=doc_excluded_count,
            total_artifacts_identified=identified_count,
            total_successfully_parsed=parsed_count,
            total_empty_artifacts=empty_count,
            total_parser_errors=error_count,
            total_unsupported=unsupported_count,
            total_events_extracted=len(raw_events),
            total_events_deduplicated=len(timeline_events),
            total_correlated_groups=corr_count,
            files=file_reports,
            warnings=warnings,
            skipped_reasons=skipped_details,
        )

        return ev, summary

    def _parser_display_name(self, art_type: str) -> str:
        names = {
            "evtx": "Windows EVTX Parser",
            "registry_hive": "Registry Hive Parser",
            "browser_sqlite": "SQLite Browser Parser",
            "pcap": "Scapy PCAP Network Parser",
            "memory": "Memory Process/Network Parser",
            "csv_tabular": "Delimited Tabular CSV Parser",
            "filesystem": "Filesystem MFT/Stat Parser",
            "document_metadata": "Document Metadata Parser",
            "json": "JSON Structured Parser",
        }
        return names.get(art_type, "Forensic Parser")

    def _create_artifact_row(self, evidence_id: int, rec: dict[str, Any]) -> Artifact:
        """Instantiate an Artifact model row populated with Common Forensic Event Schema fields."""
        source_type = rec.get("source_type") or "unknown"
        time_kind = rec.get("time_kind") or ("observation" if source_type == "memory" else "event")
        obs_time = (
            rec.get("observation_time")
            or (str(rec.get("timestamp") or "") if source_type == "memory" else "")
        )

        return Artifact(
            case_id=self.case.id,
            evidence_id=evidence_id,
            event_id=str(rec.get("event_id") or ""),
            timestamp=rec.get("timestamp"),
            timestamp_utc=str(rec.get("timestamp_utc") or ""),
            source=str(rec.get("source") or f"{source_type.title()} Artifact"),
            source_type=source_type,
            artifact_type=str(rec.get("artifact_type") or source_type.replace("_", " ").title()),
            event_type=str(rec.get("event_type") or "event"),
            user=str(rec.get("user") or rec.get("actor") or ""),
            actor=str(rec.get("actor") or rec.get("user") or ""),
            host=str(rec.get("host") or ""),
            process=str(rec.get("process") or ""),
            pid=str(rec.get("pid") or ""),
            action=str(rec.get("action") or rec.get("event_type") or "Event"),
            object=str(rec.get("object") or rec.get("target") or "")[:512],
            target=str(rec.get("target") or rec.get("object") or "")[:512],
            path=str(rec.get("path") or "")[:512],
            source_path=str(rec.get("source_path") or "")[:512],
            destination_path=str(rec.get("destination_path") or "")[:512],
            source_ip=str(rec.get("source_ip") or ""),
            source_port=str(rec.get("source_port") or ""),
            destination_ip=str(rec.get("destination_ip") or ""),
            destination_port=str(rec.get("destination_port") or ""),
            description=str(rec.get("description") or ""),
            evidence_hash=str(rec.get("evidence_hash") or ""),
            fingerprint=str(rec.get("fingerprint") or ""),
            correlation_id=str(rec.get("correlation_id") or ""),
            raw_data=str(rec.get("raw_data") or "")[:4000],
            parser_name=str(rec.get("parser_name") or ""),
            source_file=str(rec.get("source_file") or ""),
            time_kind=time_kind,
            observation_time=obs_time,
        )
