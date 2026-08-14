"""Comprehensive End-to-End Tests for Forensic Ingestion, Correlation, RAG, and AI Analysis."""

import csv
import json
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from zipfile import ZipFile
import pytest
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR

from app.db import Base, SessionLocal, engine, migrate
from app.models import Artifact, Case, Evidence, Finding, Recommendation
from app.services.analyzer import analyze_timeline, answer_question
from app.services.ingestion import EvidenceIngestionEngine
from app.services.integrity import sha256_file
from app.services.rag import index_case_events, retrieve
from app.services.report import generate_report


@pytest.fixture(autouse=True)
def init_db():
    Base.metadata.create_all(bind=engine)
    migrate()
    yield


def test_complete_investigation_workflow(tmp_path):
    db = SessionLocal()
    try:
        case_id_str = f"CASE-{uuid.uuid4().hex[:6].upper()}"
        case = Case(
            case_number=case_id_str,
            title="Suspected Exfiltration of Confidential IP",
            description="End-to-end multi-artifact forensic evidence ingestion test",
            investigator="Lead Examiner",
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        # Create folder structure for evidence
        src_dir = tmp_path / "raw_evidence"
        src_dir.mkdir()

        # 1. EVTX-like XML Event Log
        t0 = datetime(2026, 8, 14, 9, 0, 0)
        (src_dir / "Security_Log.xml").write_text(f"""<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event>
    <System>
      <EventID>4624</EventID>
      <TimeCreated SystemTime="{(t0).isoformat()}Z" />
      <Computer>WORKSTATION-14</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">analyst</Data>
      <Data Name="LogonType">2</Data>
    </EventData>
  </Event>
  <Event>
    <System>
      <EventID>4688</EventID>
      <TimeCreated SystemTime="{(t0 + timedelta(minutes=4)).isoformat()}Z" />
      <Computer>WORKSTATION-14</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass -Command "Get-Process"</Data>
    </EventData>
  </Event>
  <Event>
    <System>
      <EventID>6416</EventID>
      <TimeCreated SystemTime="{(t0 + timedelta(minutes=14)).isoformat()}Z" />
      <Computer>WORKSTATION-14</Computer>
    </System>
    <EventData>
      <Data Name="DeviceDescription">SanDisk Ultra USB Device</Data>
      <Data Name="DeviceInstanceId">USB\\VID_0781&amp;PID_5581\\4C530001</Data>
    </EventData>
  </Event>
</Events>""")

        # 2. Browser SQLite database (History)
        hist_db = src_dir / "History"
        con = sqlite3.connect(hist_db)
        con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)")
        con.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
        con.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, start_time INTEGER, tab_url TEXT, total_bytes INTEGER)")
        epoch = datetime(1601, 1, 1)

        def to_ct(dt):
            return int((dt - epoch).total_seconds() * 1_000_000)

        con.execute("INSERT INTO urls VALUES (1, 'https://github.com/corp/secret-repo', 'Corporate Repo', 5)")
        con.execute("INSERT INTO urls VALUES (2, 'https://drive.google.com/drive/my-drive', 'Google Drive', 2)")
        con.execute("INSERT INTO visits VALUES (1, 1, ?)", (to_ct(t0 + timedelta(minutes=8)),))
        con.execute("INSERT INTO visits VALUES (2, 2, ?)", (to_ct(t0 + timedelta(minutes=30)),))
        con.execute(
            "INSERT INTO downloads VALUES (1, 'C:\\\\Users\\\\analyst\\\\Downloads\\\\api_keys.env', ?, 'https://github.com/corp/secret-repo', 1024)",
            (to_ct(t0 + timedelta(minutes=10)),),
        )
        con.commit()
        con.close()

        # 3. PCAP Network Capture
        pcap_file = src_dir / "traffic.pcap"
        pkts = [
            IP(src="10.0.0.14", dst="10.0.0.53") / UDP(sport=54321, dport=53) / DNS(rd=1, qd=DNSQR(qname="drive.google.com")),
            IP(src="10.0.0.14", dst="142.250.190.46") / TCP(sport=54322, dport=443, flags="S"),
        ]
        scapy.wrpcap(str(pcap_file), pkts)

        # 4. Filesystem Activity CSV
        (src_dir / "fs_log.csv").write_text(
            "timestamp,path,event_type,user,description\n"
            f"{(t0 + timedelta(minutes=16)).isoformat()},C:/Users/analyst/Documents/api_keys.env,FILE_OPEN,analyst,API keys accessed\n"
            f"{(t0 + timedelta(minutes=22)).isoformat()},E:/Transfer/api_keys.env,FILE_COPY,analyst,Copied to USB removable drive\n"
        )

        # 5. Memory snapshot
        (src_dir / "memory.txt").write_text(
            f"SYNTHETIC MEMORY SNAPSHOT\n"
            f"Captured: {(t0 + timedelta(minutes=35)).isoformat()}\n\n"
            f"Processes:\n"
            f"- explorer.exe | PID 3100 | User analyst\n"
            f"- powershell.exe | PID 4200 | User analyst\n\n"
            f"Network:\n"
            f"- 10.0.0.14:54322 -> 142.250.190.46:443\n"
        )

        # Package into Evidence ZIP
        zip_file = tmp_path / f"{case_id_str}_Forensic_Package.zip"
        with ZipFile(zip_file, "w") as zf:
            for p in src_dir.iterdir():
                zf.write(p, arcname=p.name)

        # Run Evidence Ingestion Engine
        engine_inst = EvidenceIngestionEngine(db, case)
        ev, summary = engine_inst.ingest_evidence(zip_file, zip_file.name, notes="E2E test package")

        # Assertions
        assert ev.id is not None
        assert ev.integrity_ok is True
        assert ev.sha256 == sha256_file(zip_file)
        assert summary.total_files_parsed >= 5

        # Query artifacts
        arts = db.query(Artifact).filter(Artifact.case_id == case.id).order_by(Artifact.timestamp.asc()).all()
        assert len(arts) >= 8

        # Verify Common Forensic Event Schema consistency
        for a in arts:
            assert isinstance(a.source_type, str)
            assert isinstance(a.event_type, str)
            assert isinstance(a.description, str)
            assert a.fingerprint != ""

        # Verify Analysis
        events_dicts = [
            {
                "id": a.id,
                "case_id": a.case_id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "source_type": a.source_type,
                "event_type": a.event_type,
                "description": a.description,
                "actor": a.actor,
                "user": a.user,
                "target": a.target,
                "object": a.object,
                "correlation_id": a.correlation_id,
            }
            for a in arts
        ]
        index_case_events(case.id, events_dicts)

        analysis = analyze_timeline(events_dicts, case_id=case.id)
        assert analysis["category"] in {"Insider Threat", "Data Theft"}
        assert analysis["risk_score"] >= 40
        assert len(analysis["findings"]) > 0

        # Test Q&A with RAG
        rag_data = retrieve(case.id, "Was any file copied to USB?")
        assert len(rag_data["knowledge"]) > 0
        answer = answer_question("Was any file copied to USB?", rag_data, events_dicts, analysis)
        assert "USB" in answer or "transfer" in answer or "api_keys" in answer

        # Test PDF Report Generation
        findings = [
            Finding(
                case_id=case.id,
                category=analysis["category"],
                title=f"Possible {analysis['category']}",
                body="Test finding body",
                risk_score=float(analysis["risk_score"]),
                confidence=0.85,
            )
        ]
        pdf_path = generate_report(case, [ev], arts, findings, analysis)
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 1000

    finally:
        db.close()
