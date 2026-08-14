"""Tests for Ingestion Engine Auditable Parser Status Taxonomy & SQLite Diagnostic Reporting."""

import sqlite3
import uuid
from pathlib import Path
from zipfile import ZipFile
import pytest

from app.db import Base, SessionLocal, engine, migrate
from app.models import Artifact, Case, Evidence
from app.services.ingestion import EvidenceIngestionEngine
from app.services.parsers.browser_parser import parse_with_diagnostics


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    migrate()
    yield


def test_sqlite_diagnostics_and_empty_status(tmp_path):
    # Create empty SQLite history database
    db_path = tmp_path / "History.sqlite"
    con = sqlite3.connect(db_path)
    con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
    con.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
    con.commit()
    con.close()

    events, diag = parse_with_diagnostics(db_path)
    assert len(events) == 0
    assert "urls" in diag["tables"]
    assert "visits" in diag["tables"]
    assert diag["row_counts"]["urls"] == 0

    # Test full Ingestion Engine handling of empty SQLite database
    db = SessionLocal()
    try:
        case = Case(
            case_number=f"CASE-AUDIT-{uuid.uuid4().hex[:6].upper()}",
            title="Audit Status Taxonomy Test",
            description="Verifying first-class parser status tracking",
            investigator="Examiner",
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        # Build ZIP with:
        # 1. empty History.sqlite
        # 2. README.txt (excluded)
        # 3. Security.xml (parsed)
        case_dir = tmp_path / "case_src"
        case_dir.mkdir()
        
        # Copy empty History.sqlite
        import shutil
        shutil.copy2(db_path, case_dir / "History.sqlite")
        
        # Excluded doc
        (case_dir / "README.txt").write_text("Documentation file.")
        
        # Valid XML event
        (case_dir / "Security.xml").write_text("""<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event>
    <System><EventID>4624</EventID><TimeCreated SystemTime="2026-08-14T09:00:00Z"/></System>
    <EventData><Data Name="TargetUserName">analyst</Data></EventData>
  </Event>
</Events>""")

        zip_p = tmp_path / "case_audit.zip"
        with ZipFile(zip_p, "w") as zf:
            for p in case_dir.iterdir():
                zf.write(p, arcname=p.name)

        engine_inst = EvidenceIngestionEngine(db, case)
        ev, summary = engine_inst.ingest_evidence(zip_p, "case_audit.zip")

        # Verify first-class status metrics
        assert summary.total_files_discovered == 3
        assert summary.total_documentation_excluded == 1  # README.txt -> excluded
        assert summary.total_artifacts_identified == 2    # History.sqlite, Security.xml
        assert summary.total_successfully_parsed == 1     # Security.xml -> parsed
        assert summary.total_empty_artifacts == 1         # History.sqlite -> empty

        # Check individual file statuses
        file_map = {f.filename: f for f in summary.files}
        assert file_map["README.txt"].status == "excluded"
        assert file_map["Security.xml"].status == "parsed"
        assert file_map["Security.xml"].events_extracted == 1

        hist_report = file_map["History.sqlite"]
        assert hist_report.status == "empty"
        assert hist_report.events_extracted == 0
        assert "SQLite database inspected" in hist_report.reason
        assert "Inspect database schema" in hist_report.recommended_action

        # Check that warning was produced for empty browser history
        assert len(summary.warnings) >= 1
        assert any("Browser History database identified" in w for w in summary.warnings)

    finally:
        db.close()
