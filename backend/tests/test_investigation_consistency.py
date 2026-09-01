"""Tests for Forensic Classification, Evidentiary States, Query Routing & Grounded Q&A Consistency."""

from datetime import datetime, timedelta
import pytest

from app.services.investigation import (
    classify_and_score,
    classify_query_intent,
    classify_user_query,
    get_evidentiary_states,
    attack_chain,
    answer_question,
    run_investigation,
    INTENT_GREETING,
    INTENT_GENERAL,
    INTENT_TECHNICAL_FORENSIC,
    INTENT_FORENSIC_KNOWLEDGE,
    INTENT_CASE_ANALYSIS,
    INTENT_CASE_TIMELINE,
    INTENT_CASE_SUMMARY,
    INTENT_CASE_GUIDANCE,
    INTENT_CASE_QUERY,
)


def test_query_classifier():
    # 1. Greetings
    assert classify_query_intent("hi") == INTENT_GREETING
    assert classify_query_intent("hello") == INTENT_GREETING
    assert classify_query_intent("hey there") == INTENT_GREETING
    assert classify_query_intent("who are you") == INTENT_GREETING
    assert classify_query_intent("help") == INTENT_GREETING

    # 2. General Concept queries
    assert classify_query_intent("What is HTTP?") == INTENT_GENERAL
    assert classify_query_intent("https means") == INTENT_GENERAL
    assert classify_query_intent("What does HTTPS mean?") == INTENT_GENERAL
    assert classify_query_intent("Explain cryptography") == INTENT_GENERAL
    assert classify_query_intent("What is AI?") == INTENT_GENERAL
    assert classify_query_intent("Explain Python") == INTENT_GENERAL

    # 3. Technical Forensic Knowledge & Methodology queries
    assert classify_query_intent("What is a Windows Event ID 4624?") == INTENT_TECHNICAL_FORENSIC
    assert classify_query_intent("What is USBSTOR?") == INTENT_TECHNICAL_FORENSIC
    assert classify_query_intent("What is MITRE ATT&CK?") == INTENT_TECHNICAL_FORENSIC
    assert classify_query_intent("What is T1078?") == INTENT_TECHNICAL_FORENSIC
    assert classify_query_intent("how could we find the suspicious activity taken place?") == INTENT_TECHNICAL_FORENSIC

    # 4. Case Investigation, Timeline, Summary & Guidance queries
    assert classify_query_intent("generate the timeline of events occured") == INTENT_CASE_TIMELINE
    assert classify_query_intent("show sequence of events") == INTENT_CASE_TIMELINE
    assert classify_query_intent("summarize the case") == INTENT_CASE_SUMMARY
    assert classify_query_intent("What are the recommended next steps?") == INTENT_CASE_GUIDANCE
    assert classify_query_intent("Was confidential data copied to USB?") == INTENT_CASE_QUERY
    assert classify_query_intent("Does the HTTPS activity in this case indicate exfiltration?") == INTENT_CASE_QUERY
    assert classify_query_intent("What was chrome.exe accessing in this case?") == INTENT_CASE_QUERY


def test_case_timeline_generation():
    """Verify deterministic timeline table generation with chronological ordering and evidence IDs."""
    t0 = datetime(2026, 8, 14, 9, 0, 0)
    events = [
        {"id": 1, "timestamp": t0, "event_type": "logon", "source_type": "windows_event", "target": "WORKSTATION-14", "process": "lsass.exe", "description": "Windows logon"},
        {"id": 2, "timestamp": t0 + timedelta(minutes=5), "event_type": "url_visit", "source_type": "browser", "target": "https://github.com/acme/ProjectX", "process": "chrome.exe", "description": "Browser visit"},
        {"id": 3, "timestamp": t0 + timedelta(minutes=10), "event_type": "usb_connect", "source_type": "windows_event", "target": "SanDisk Ultra", "description": "USB device connected"},
    ]
    inv = run_investigation(case_id=1, events=events)
    ans = answer_question("generate the timeline of events occured", {}, events, inv)

    assert "Chronological Investigation Event Timeline" in ans
    assert "2026-08-14 09:00:00" in ans
    assert "2026-08-14 09:05:00" in ans
    assert "2026-08-14 09:10:00" in ans
    assert "Evidence [#1]" in ans
    assert "Evidence [#2]" in ans
    assert "Evidence [#3]" in ans
    assert "AI Investigation Summary" in ans


def test_general_https_response():
    events = [
        {"id": 26, "timestamp": "2026-08-13T09:05:00", "source_type": "browser", "target": "chrome.exe", "description": "Browser visit"},
        {"id": 41, "timestamp": "2026-08-13T11:00:00", "source_type": "network", "target": "10.0.0.20:443", "description": "TCP flow"},
    ]
    inv = {
        "category": "Possible Unauthorized Use of Valid Account",
        "secondary": "Insufficient Evidence for Exfiltration",
        "risk_score": 20,
        "priority": "LOW PRIORITY",
        "evidentiary_states": [],
        "observations": [],
        "correlations": [],
    }

    ans = answer_question("What does HTTPS mean?", {}, events, inv)
    assert "Hypertext Transfer Protocol Secure" in ans
    assert "Working classification:" not in ans  # Does not dump classification template for concept question
    assert "OBSERVED CASE EVIDENCE" not in ans
    assert "FORENSIC ASSESSMENT" not in ans


def test_greeting_does_not_inject_case_classification():
    inv = {
        "category": "Possible Unauthorized Use of Valid Account",
        "secondary": "Insufficient Evidence for Exfiltration",
        "risk_score": 20,
        "priority": "LOW PRIORITY",
        "evidentiary_states": [],
        "observations": [],
        "correlations": [],
    }
    ans = answer_question("hi", {}, [], inv)
    assert "forensic investigation assistant for this case" in ans
    assert "Working classification:" not in ans
    assert "Investigation Priority:" not in ans
    assert "USB-based" not in ans
    assert "CASE-SPECIFIC EVIDENCE" not in ans


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

    # 5. Dynamic Suggested Queries
    assert len(inv["suggested_queries"]) > 0
    assert any("valid account" in q.lower() for q in inv["suggested_queries"])
    assert any("usb" in q.lower() for q in inv["suggested_queries"])
