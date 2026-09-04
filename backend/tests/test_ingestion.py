"""End-to-End Tests for Evidence Ingestion Engine."""

import csv
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from zipfile import ZipFile
import pytest

from app.db import Base, SessionLocal, engine, migrate
from app.models import Artifact, Case, CustodyEvent, Evidence
from app.services.ingestion import EvidenceIngestionEngine
from app.services.integrity import sha256_file
from app.services.analyzer import analyze_timeline
from app.services.rag import index_case_events, retrieve


import uuid

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    migrate()
    yield


def test_full_pipeline_ingestion(tmp_path, db_session):
    db = db_session
    try:
        case_num = f"CASE-TEST-{uuid.uuid4().hex[:8]}"
        # Create Case
        case = Case(
            case_number=case_num,
            title="Automated Evidence Ingestion Test Case",
            description="Testing ZIP ingestion with EVTX, SQLite, CSV, Memory, Network",
            investigator="Forensic Examiner",
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        # Build mixed case directory
        evidence_dir = tmp_path / "case_evidence"
        evidence_dir.mkdir(parents=True)

        # 1. Windows Event XML (representing EVTX export)
        (evidence_dir / "Security.xml").write_text("""<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2026-08-14T09:00:00.000000Z" />
      <Computer>WORKSTATION-14</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">analyst</Data>
      <Data Name="LogonType">2</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-08-14T09:04:12.000000Z" />
      <Computer>WORKSTATION-14</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>6416</EventID>
      <TimeCreated SystemTime="2026-08-14T09:14:00.000000Z" />
      <Computer>WORKSTATION-14</Computer>
    </System>
    <EventData>
      <Data Name="DeviceDescription">SanDisk Ultra USB Device</Data>
    </EventData>
  </Event>
</Events>
""")

        # 2. Chrome History SQLite (no extension to test content-based detection!)
        chrome_db = evidence_dir / "History"
        con = sqlite3.connect(chrome_db)
        con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
        con.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
        chrome_epoch = datetime(1601, 1, 1)
        t_visit = datetime(2026, 8, 14, 9, 8, 43)
        vtime = int((t_visit - chrome_epoch).total_seconds() * 1_000_000)
        con.execute("INSERT INTO urls VALUES (1, 'https://example.internal/documents', 'Internal Documents')")
        con.execute("INSERT INTO visits VALUES (1, 1, ?)", (vtime,))
        con.commit()
        con.close()

        # 3. File System CSV
        (evidence_dir / "filesystem_events.csv").write_text(
            "timestamp,path,event_type,user,description\n"
            "2026-08-14T09:15:22,C:/Projects/Sensitive_ProjectX.xlsx,FILE_OPEN,analyst,Sensitive project file accessed\n"
            "2026-08-14T09:23:00,E:/Transfer/Sensitive_ProjectX.xlsx,FILE_COPY,analyst,Copied to USB\n"
        )

        # 4. Filtered evaluation truth & doc
        (evidence_dir / "expected_timeline.csv").write_text("timestamp,expected\n2026-08-14T09:00:00,logon\n")
        (evidence_dir / "README.txt").write_text("Documentation file.")

        # Zip into case package
        zip_path = tmp_path / "CASE003_evidence.zip"
        with ZipFile(zip_path, "w") as zf:
            for p in evidence_dir.iterdir():
                zf.write(p, arcname=p.name)

        # Execute Evidence Ingestion Engine
        engine_inst = EvidenceIngestionEngine(db, case)
        ev, summary = engine_inst.ingest_evidence(zip_path, "CASE003_evidence.zip", notes="Automated test ZIP")

        # Verify Evidence metadata and SHA-256
        assert ev.id is not None
        assert ev.sha256 == sha256_file(zip_path)
        assert ev.integrity_ok is True
        assert ev.size_bytes > 0

        # Verify Ingestion Summary
        assert summary.total_files_discovered == 5
        assert summary.total_files_parsed == 3  # Security.xml, History, filesystem_events.csv
        assert summary.total_files_skipped == 2  # expected_timeline.csv, README.txt
        assert summary.total_events_extracted >= 6

        # Verify Artifacts stored in database
        artifacts = db.query(Artifact).filter(Artifact.case_id == case.id).order_by(Artifact.timestamp.asc()).all()
        assert len(artifacts) >= 6

        # Check Common Forensic Event Schema fields
        for a in artifacts:
            assert a.case_id == case.id
            assert a.evidence_id == ev.id
            assert a.source_type != ""
            assert a.event_type != ""
            assert a.description != ""
            assert a.fingerprint != ""

        # Check specific events extracted by the specialized parsers
        types = [a.event_type for a in artifacts]
        assert "logon" in types
        assert "process_create" in types
        assert "usb_connect" in types
        assert "url_visit" in types
        assert "file_access" in types
        assert "file_copy" in types

        # Check correlation
        corr_arts = [a for a in artifacts if a.source_type == "correlated"]
        assert len(corr_arts) >= 1  # Correlated USB / File copy activity

        # Check RAG & Analysis
        events_dicts = [
            {
                "id": a.id,
                "case_id": a.case_id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "source_type": a.source_type,
                "event_type": a.event_type,
                "description": a.description,
                "actor": a.actor,
                "target": a.target,
                "correlation_id": a.correlation_id,
            }
            for a in artifacts
        ]
        index_case_events(case.id, events_dicts)
        rag_res = retrieve(case.id, "powershell execution")
        assert len(rag_res["knowledge"]) > 0

        analysis = analyze_timeline(events_dicts, case_id=case.id)
        assert analysis["risk_score"] > 0
        assert len(analysis["findings"]) > 0

    finally:
        db.close()
