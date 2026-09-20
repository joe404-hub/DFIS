"""Tests for Automated Evidence Acquisition Engine, Policy Agent, Prefetch & Amcache Parsers."""

import json
import uuid
from pathlib import Path
import pytest

from app.db import Base, SessionLocal, engine, migrate
from app.models import Artifact, Case, CustodyEvent, Evidence
from app.services.acquisition import AutomatedEvidenceCollector, AcquisitionPolicy
from app.services.parsers import prefetch_parser, amcache_parser


@pytest.fixture(autouse=True)
def init_db():
    Base.metadata.create_all(bind=engine)
    migrate()
    yield


def test_prefetch_parser(tmp_path):
    pf_file = tmp_path / "POWERSHELL.EXE-A4B3C2D1.pf.csv"
    pf_file.write_text("executable,timestamp,run_count\nPOWERSHELL.EXE,2026-08-14T09:04:12,14\n")

    events = prefetch_parser.parse(pf_file)
    assert len(events) == 1
    ev = events[0]
    assert ev["process"] == "POWERSHELL.EXE"
    assert ev["event_type"] == "process_create"
    assert "Prefetch" in ev["artifact_type"]


def test_amcache_parser(tmp_path):
    am_file = tmp_path / "Amcache_Applications.csv"
    am_file.write_text("path,sha1,timestamp\nC:\\ProgramData\\DemoUpdater.exe,3a4f6c8e9b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f,2026-08-14T09:10:00\n")

    events = amcache_parser.parse(am_file)
    assert len(events) == 1
    ev = events[0]
    assert ev["process"] == "DemoUpdater.exe"
    assert ev["event_type"] == "process_create"
    assert "Amcache" in ev["artifact_type"]


def test_policy_driven_automated_collection(tmp_path, db_session):
    db = db_session
    case = Case(
        case_number=f"CASE-ACQ-{uuid.uuid4().hex[:6].upper()}",
        title="Automated Policy-Driven Collection Test",
        description="Testing policy checklist and acquisition agent",
        investigator="Forensic Examiner",
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    # Define custom investigator policy
    policy = AcquisitionPolicy(
        collect_security_logs=True,
        collect_system_logs=True,
        collect_powershell_logs=True,
        collect_registry=True,
        collect_browser_history=True,
        collect_browser_downloads=True,
        collect_filesystem=True,
        collect_prefetch=True,
        collect_amcache=True,
        collect_network=True,
        collect_memory=False,  # Policy test: disable memory
    )

    collector = AutomatedEvidenceCollector(db, case)
    ev, report = collector.run_authorized_collection(policy, mode="automated_collection", notes="Test policy run")

    assert ev.id is not None
    assert report.total_files_collected >= 8
    assert report.package_sha256 != ""
    assert report.mode == "automated_collection"

    # Verify categories
    cat_map = {c.category: c for c in report.categories}
    assert cat_map["Windows Security Logs"].status == "collected"
    assert cat_map["Prefetch Execution Traces"].status == "collected"
    assert cat_map["Amcache Application Evidence"].status == "collected"
    assert cat_map["Memory Image"].status == "skipped_by_policy"

    # Verify artifacts extracted from acquired package
    artifacts = db.query(Artifact).filter(Artifact.case_id == case.id).all()
    assert len(artifacts) >= 8

    # Verify Common Forensic Event Schema fields
    for a in artifacts:
        assert a.case_id == case.id
        assert a.evidence_id == ev.id
        assert a.source_type != ""
        assert a.event_type != ""
        assert a.description != ""
