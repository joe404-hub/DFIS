"""Tests for Content-Based File Type & Forensic Artifact Detection Engine."""

import tempfile
from pathlib import Path
import pytest

from app.services.detector import detect_file_type, DetectionResult


def test_detect_evtx_magic():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        # EVTX header: "ElfFile\x00"
        f.write(b"ElfFile\x00" + b"\x00" * 500)
        f.flush()
        res = detect_file_type(Path(f.name))
        assert res.artifact_type == "evtx"
        assert res.canonical_source_type == "windows_event"
        assert res.confidence == 1.0
        assert "ElfFile" in res.magic_signature


def test_detect_registry_hive_magic():
    with tempfile.NamedTemporaryFile(suffix=".tmp", delete=False) as f:
        # Registry hive header: "regf" + SYSTEM string inside
        f.write(b"regf" + b"\x00" * 200 + b"CurrentControlSet" + b"\x00" * 200)
        f.flush()
        res = detect_file_type(Path(f.name))
        assert res.artifact_type == "registry_hive"
        assert res.canonical_source_type == "registry"
        assert res.subtype == "system_hive"
        assert res.confidence == 1.0


def test_detect_sqlite_magic(tmp_path):
    import sqlite3
    db_file = tmp_path / "arbitrary_name_no_ext"
    con = sqlite3.connect(db_file)
    con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
    con.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
    con.commit()
    con.close()

    res = detect_file_type(db_file)
    assert res.artifact_type == "browser_sqlite"
    assert res.canonical_source_type == "browser"
    assert res.subtype == "chrome_history"
    assert res.confidence == 1.0


def test_detect_pcap_magic(tmp_path):
    pcap_file = tmp_path / "network_data.dump"
    # Microsecond PCAP magic LE: 0xd4c3b2a1
    pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 100)

    res = detect_file_type(pcap_file)
    assert res.artifact_type == "pcap"
    assert res.canonical_source_type == "network"
    assert res.confidence == 1.0


def test_detect_csv_security(tmp_path):
    csv_file = tmp_path / "audit_log.data"
    csv_file.write_text("TimeCreated,EventID,AccountName,Message\n2026-08-14T10:00:00,4624,analyst,Logon\n")

    res = detect_file_type(csv_file)
    assert res.artifact_type == "csv_tabular"
    assert res.canonical_source_type == "windows_event"
    assert res.subtype == "windows_security_csv"


def test_detect_memory_text(tmp_path):
    mem_file = tmp_path / "memory_snapshot.txt"
    mem_file.write_text("SYNTHETIC MEMORY SNAPSHOT\nProcesses:\n- explorer.exe | PID 4120 | User analyst\n")

    res = detect_file_type(mem_file)
    assert res.artifact_type == "memory"
    assert res.canonical_source_type == "memory"
    assert res.subtype == "memory_text"
