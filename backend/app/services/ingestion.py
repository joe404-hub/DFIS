"""Automated Evidence Ingestion Engine.

Orchestrates the complete evidence processing pipeline:
Archive Ingestion → SHA-256 Integrity → Content-Based File Type Detection →
Specialized Artifact Parsing → Common Forensic Schema Normalization →
Timestamp Normalization → Deduplication → Event Correlation → Database Persistence →
Case RAG Vector Indexing → AI Classification & Risk Analysis.
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
    events_extracted: int
    status: str  # parsed, skipped, error
    notes: str = ""


@dataclass
class IngestionSummary:
    case_id: int
    evidence_id: int
    archive_name: str
    archive_sha256: str
    total_files_discovered: int
    total_files_parsed: int
    total_files_skipped: int
    total_events_extracted: int
    total_events_deduplicated: int
    total_correlated_groups: int
    files: list[IngestedFileReport] = field(default_factory=list)
    skipped_reasons: list[str] = field(default_factory=list)


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
        """Process an uploaded evidence file (container ZIP/archive or raw artifact)."""
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
                    # Guard against zip slip
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

        # Process each discovered file
        for fp, rel_name in work_files:
            file_digest = sha256_file(fp)
            fsize = fp.stat().st_size

            # Check if file should be excluded from forensic timeline (documentation, evaluation truth)
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
                        events_extracted=0,
                        status="skipped",
                        notes=f"Excluded from timeline: {skip_reason}",
                    )
                )
                continue

            # Automatic File Type Detection by magic bytes and structure
            detection = detect_file_type(fp)

            # Parse with specialized artifact parser
            parsed = parse_file(fp, detection=detection)

            if not parsed:
                skipped_details.append(f"{rel_name} (no forensic events extracted)")
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
                        events_extracted=0,
                        status="skipped",
                        notes="No forensic events extracted",
                    )
                )
                continue

            # Populate Common Forensic Schema fields
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
                    events_extracted=len(parsed),
                    status="parsed",
                    notes=f"Detected: {detection.description}",
                )
            )

        # Log custody for skipped files if any
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

        # Count correlated groups
        corr_count = sum(1 for e in timeline_events if e.get("source_type") == "correlated")

        summary = IngestionSummary(
            case_id=self.case.id,
            evidence_id=ev.id,
            archive_name=original_filename,
            archive_sha256=archive_digest,
            total_files_discovered=len(work_files),
            total_files_parsed=sum(1 for f in file_reports if f.status == "parsed"),
            total_files_skipped=sum(1 for f in file_reports if f.status == "skipped"),
            total_events_extracted=len(raw_events),
            total_events_deduplicated=len(timeline_events),
            total_correlated_groups=corr_count,
            files=file_reports,
            skipped_reasons=skipped_details,
        )

        return ev, summary

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
