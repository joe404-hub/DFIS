"""Tests for Specialized Forensic Artifact Parsers."""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import pytest
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR

from app.services.parsers import (
    evtx_parser,
    registry_parser,
    browser_parser,
    pcap_parser,
    memory_parser,
    tabular_parser,
)


def test_evtx_xml_parser(tmp_path):
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-08-14T09:04:12.000000Z" />
      <Computer>WORKSTATION-14</Computer>
      <Channel>Security</Channel>
    </System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass</Data>
      <Data Name="NewProcessId">0x1144</Data>
    </EventData>
  </Event>
</Events>
"""
    xml_file = tmp_path / "Security_test.xml"
    xml_file.write_text(xml_content)

    events = evtx_parser.parse(xml_file)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_id"] == "4688"
    assert ev["event_type"] == "process_create"
    assert ev["user"] == "analyst"
    assert ev["host"] == "WORKSTATION-14"
    assert ev["process"] == "powershell.exe"
    assert "powershell.exe" in ev["description"]
    assert ev["timestamp"] == datetime(2026, 8, 14, 9, 4, 12)
    assert ev["timestamp_utc"] == "2026-08-14T09:04:12.000000Z"


def test_browser_sqlite_parser(tmp_path):
    hist_file = tmp_path / "History"
    con = sqlite3.connect(hist_file)
    con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)")
    con.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
    con.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, start_time INTEGER, tab_url TEXT, total_bytes INTEGER)")

    chrome_epoch = datetime(1601, 1, 1)
    t1 = datetime(2026, 8, 14, 9, 8, 43)
    t2 = datetime(2026, 8, 14, 9, 10, 0)
    vtime1 = int((t1 - chrome_epoch).total_seconds() * 1_000_000)
    vtime2 = int((t2 - chrome_epoch).total_seconds() * 1_000_000)

    con.execute("INSERT INTO urls VALUES (1, 'https://example.internal/documents', 'Internal Documents', 3)")
    con.execute("INSERT INTO visits VALUES (1, 1, ?)", (vtime1,))
    con.execute(
        "INSERT INTO downloads VALUES (1, 'C:\\\\Downloads\\\\ProjectX.zip', ?, 'https://example.internal/files', 4500000)",
        (vtime2,),
    )
    con.commit()
    con.close()

    events = browser_parser.parse(hist_file)
    assert len(events) == 2
    
    url_ev = next(e for e in events if e["event_type"] == "url_visit")
    assert url_ev["object"] == "https://example.internal/documents"
    assert url_ev["action"] == "URL Visit"
    assert url_ev["timestamp"] == t1

    dl_ev = next(e for e in events if e["event_type"] == "download")
    assert "ProjectX.zip" in dl_ev["object"]
    assert dl_ev["action"] == "File Downloaded"
    assert dl_ev["timestamp"] == t2


def test_pcap_parser(tmp_path):
    pcap_file = tmp_path / "capture.pcap"
    pkts = [
        IP(src="10.0.0.14", dst="10.0.0.53") / UDP(sport=51234, dport=53) / DNS(rd=1, qd=DNSQR(qname="drive.google.com")),
        IP(src="10.0.0.14", dst="142.250.190.46") / TCP(sport=51235, dport=443, flags="S"),
    ]
    scapy.wrpcap(str(pcap_file), pkts)

    events = pcap_parser.parse(pcap_file)
    assert len(events) >= 2
    dns_ev = next(e for e in events if e["event_type"] == "dns_query")
    assert "drive.google.com" in dns_ev["object"]
    assert dns_ev["source_ip"] == "10.0.0.14"


def test_memory_parser(tmp_path):
    mem_file = tmp_path / "Memory.raw.txt"
    mem_file.write_text(
        "SYNTHETIC MEMORY SNAPSHOT\n"
        "Captured: 2026-08-14T09:40:00\n\n"
        "Processes:\n"
        "- explorer.exe | PID 4120 | User analyst\n"
        "- powershell.exe | PID 5288 | User analyst\n\n"
        "Network:\n"
        "- 10.0.0.25:51520 -> 10.0.0.50:443\n"
    )

    events = memory_parser.parse(mem_file)
    assert len(events) == 3
    procs = [e["process"] for e in events if e["process"]]
    assert "explorer.exe" in procs
    assert "powershell.exe" in procs
    net_ev = next(e for e in events if e["event_type"] == "network_flow")
    assert net_ev["source_ip"] == "10.0.0.25"
    assert net_ev["destination_port"] == "443"
    assert net_ev["time_kind"] == "observation"
