"""Tests for Forensic Classification, Evidentiary States & Grounded Q&A Consistency."""

from datetime import datetime, timedelta
import pytest

from app.services.investigation import (
    classify_and_score,
    get_evidentiary_states,
    attack_chain,
    answer_question,
    run_investigation,
)


def test_benign_case_consistency():
    t0 = datetime(2026, 8, 14, 9, 0, 0)
    # Case with only logon + internal web traffic (no USB, no file copies)
    events = [
        {
            "id": 1,
            "timestamp": t0,
            "event_type": "logon",
            "source_type": "windows_event",
            "actor": "analyst",
            "target": "WORKSTATION-14",
            "description": "Windows Event 4624 Successful logon for user analyst",
        },
        {
            "id": 2,
            "timestamp": t0 + timedelta(minutes=5),
            "event_type": "url_visit",
            "source_type": "browser",
            "actor": "analyst",
            "target": "https://intranet.corp/internal-drive",
            "description": "Browser visit to internal intranet drive",
        },
        {
            "id": 3,
            "timestamp": t0 + timedelta(minutes=6),
            "event_type": "network_flow",
            "source_type": "network",
            "actor": "10.0.0.14",
            "target": "10.0.0.20:443",
            "source_ip": "10.0.0.14",
            "destination_ip": "10.0.0.20",
            "destination_port": "443",
            "description": "TCP connection 10.0.0.14:52100 -> 10.0.0.20:443 (internal server)",
        },
        {
            "id": 4,
            "timestamp": t0 + timedelta(minutes=30),
            "observation_time": (t0 + timedelta(minutes=30)).isoformat(),
            "event_type": "process_list",
            "source_type": "memory",
            "time_kind": "observation",
            "actor": "analyst",
            "target": "chrome.exe",
            "process": "chrome.exe",
            "description": "Memory snapshot: chrome.exe active at 09:30:00",
        },
    ]

    inv = run_investigation(case_id=999, events=events)

    # 1. Classification & Secondary status consistency
    assert "Unauthorized Access" not in inv["category"] or "Possible Unauthorized Use" in inv["category"]
    assert "Insufficient Evidence for Exfiltration" in inv["secondary"] or "Insufficient" in inv["secondary"]

    # 2. 4-Tier Evidentiary States
    ev_states = {s["finding"]: s["state"] for s in inv["evidentiary_states"]}
    assert ev_states["User authentication"] == "OBSERVED"
    assert ev_states["Network/browser activity"] == "OBSERVED"
    assert ev_states["Unauthorized account use"] == "NOT ESTABLISHED"
    assert ev_states["USB connection"] == "NOT ESTABLISHED"
    assert ev_states["Confidential-file copying"] == "NOT ESTABLISHED"
    assert ev_states["Exfiltration"] == "NOT ESTABLISHED"

    # 3. Attack Chain Technique & Evidence Observations Mapping
    chain = inv["attack_chain"]
    # Check T1078 has status observed and high confidence
    t1078_step = next((s for s in chain if s["mitre"] == "T1078"), None)
    assert t1078_step is not None
    assert t1078_step["status"] == "observed"

    # Check Memory snapshot is in separate observations section, NOT in attack chain
    assert not any("Memory snapshot" in s["title"] for s in chain)
    assert len(inv["observations"]) > 0
    mem_obs = inv["observations"][0]
    assert mem_obs["title"] == "Memory snapshot"
    assert mem_obs["status"] == "OBSERVED"
    assert "observation time" in mem_obs["note"]

    # 4. Grounded Q&A Consistency
    answer = answer_question("Was confidential data copied to USB?", {}, events, inv)
    assert "not establish that confidential data was copied to USB" in answer
    assert "NOT ESTABLISHED" in answer
    assert "General forensic knowledge is interpretive only and cannot be used as case evidence" in answer
