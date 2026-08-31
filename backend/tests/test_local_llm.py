"""Tests for Local LLM (llama3.2:3b) Integration, Prompt Construction & Forensic Grounding."""

import json
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from app.db import Base, engine, get_db, migrate
from app.models import Case
from app.main import app
from app.services.llm import (
    DEFAULT_MODEL,
    FORENSIC_SYSTEM_PROMPT,
    build_forensic_prompt,
    check_local_llm_health,
    generate_chat_response,
    post_process_llm_answer,
    query_ollama,
)


@pytest.fixture(autouse=True)
def init_db():
    Base.metadata.create_all(bind=engine)
    migrate()
    yield


@pytest.fixture
def test_case_state():
    return {
        "category": "Possible Unauthorized Use of Valid Account",
        "secondary": "Insufficient Evidence for Exfiltration",
        "risk_score": 25,
        "priority": "LOW PRIORITY",
        "evidentiary_states": [
            {"finding": "User authentication", "state": "OBSERVED", "detail": "Event 4624"},
            {"finding": "USB connection", "state": "NOT ESTABLISHED", "detail": "No USB device recorded"},
            {"finding": "Exfiltration", "state": "NOT ESTABLISHED", "detail": "No transmission of confidential files"},
        ],
        "correlations": [
            {
                "timestamp": "2026-08-14T09:05:00",
                "family": "network",
                "entity": "10.0.0.20:443",
                "source_event_ids": [26, 29],
            }
        ],
    }


@pytest.fixture
def test_events():
    return [
        {
            "id": 1,
            "timestamp": "2026-08-14T09:00:00",
            "source_type": "windows_event",
            "event_type": "logon",
            "actor": "analyst",
            "target": "WORKSTATION-14",
            "process": "lsass.exe",
            "description": "Windows Event 4624 Successful logon for user analyst",
        },
        {
            "id": 26,
            "timestamp": "2026-08-14T09:05:00",
            "source_type": "browser",
            "event_type": "url_visit",
            "actor": "analyst",
            "target": "https://intranet.corp/internal-drive",
            "process": "chrome.exe",
            "description": "Browser visit to internal intranet drive",
        },
    ]


def test_build_forensic_prompt(test_case_state, test_events):
    messages = build_forensic_prompt(
        question="Was confidential data copied to USB?",
        query_type="case_investigation",
        events=test_events,
        inv=test_case_state,
        rag={"knowledge": ["USB storage artifacts are in SYSTEM hive."]},
    )

    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert "llama3.2:3b" in messages[0]["content"]
    assert "MANDATORY FORENSIC GROUNDING RULES" in messages[0]["content"]

    user_msg = messages[1]["content"]
    assert "Was confidential data copied to USB?" in user_msg
    assert "Possible Unauthorized Use of Valid Account" in user_msg
    assert "USB connection: NOT ESTABLISHED" in user_msg
    assert "Evidence IDs: [26, 29]" in user_msg


def test_health_check_offline():
    status = check_local_llm_health(base_url="http://127.0.0.1:59999", model="llama3.2:3b")
    assert status["connected"] is False
    assert status["model"] == "llama3.2:3b"
    assert "100% Local" in status["privacy"]
    assert "ollama run llama3.2:3b" in status["recommended_command"]


def test_health_check_online_mocked():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"models": [{"name": "llama3.2:3b"}, {"name": "nomic-embed-text:latest"}]}

    with patch("httpx.Client.get", return_value=mock_resp):
        status = check_local_llm_health(base_url="http://localhost:11434", model="llama3.2:3b")
        assert status["connected"] is True
        assert status["mode"] == "local_inference_ready"
        assert "llama3.2:3b" in status["available_models"]


def test_query_ollama_mocked():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {
            "role": "assistant",
            "content": "Assessment: Valid logon observed [Evidence ID: 1]. USB activity is NOT ESTABLISHED.",
        }
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        ans = query_ollama(
            messages=[{"role": "user", "content": "hello"}],
            model="llama3.2:3b",
        )
        assert ans is not None
        assert "[Evidence ID: 1]" in ans
        assert "NOT ESTABLISHED" in ans


def test_generate_chat_response_greeting(test_case_state, test_events):
    res = generate_chat_response(
        question="hi",
        events=test_events,
        inv=test_case_state,
        rag={},
    )
    assert res["is_local"] is True
    assert res["query_type"] == "greeting"
    assert "forensic investigation assistant for this case" in res["answer"]
    # Never dump classification template on greeting
    assert "Working classification:" not in res["answer"]


def test_generate_chat_response_offline_fallback(test_case_state, test_events):
    # Ensure offline fallback is seamless, grounded, and never crashes
    res = generate_chat_response(
        question="Was confidential data copied to USB?",
        events=test_events,
        inv=test_case_state,
        rag={},
        base_url="http://127.0.0.1:59999",  # unreachable port
    )
    assert res["is_local"] is True
    assert "llama3.2:3b" in res["model"]
    assert "NOT ESTABLISHED" in res["answer"]
    assert "AI is an investigative assistant, not an evidence source." in res["answer"]


def test_generate_chat_response_with_mocked_ollama(test_case_state, test_events):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {
            "role": "assistant",
            "content": "Grounded assessment: USB connection is NOT ESTABLISHED. User authentication is OBSERVED at 09:00 (Evidence ID: 1).",
        }
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        res = generate_chat_response(
            question="Was confidential data copied to USB?",
            events=test_events,
            inv=test_case_state,
            rag={},
            model="llama3.2:3b",
        )
        assert res["is_local"] is True
        assert res["llm_mode"] == "local_neural_inference"
        assert res["model"] == "llama3.2:3b"
        assert res["provider"].lower() == "ollama"
        assert "USB connection is NOT ESTABLISHED" in res["answer"]
        assert "AI is an investigative assistant, not an evidence source." in res["answer"]
        assert res["generator"]["fallback"] is False
        assert res["generator"]["verified"] is True
        assert res["generator"]["type"] == "llm"
        assert res["generator"]["provider"] == "ollama"


def test_api_chat_endpoint_returns_local_llm_metadata(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        client = TestClient(app)
        # Create test case
        case = Case(case_number="CASE-TEST-LLM", title="Test Local LLM", investigator="Lead Examiner")
        db_session.add(case)
        db_session.commit()
        db_session.refresh(case)

        # Call chat
        chat_resp = client.post(
            f"/api/cases/{case.id}/chat",
            json={"question": "What does HTTPS mean?", "model": "llama3.2:3b"},
        )
        assert chat_resp.status_code == 200
        data = chat_resp.json()
        assert "answer" in data
        assert "llama3.2:3b" in data["model"]
        assert data["is_local"] is True
        assert "generator" in data
        assert isinstance(data["generator"]["fallback"], bool)
        assert "Hypertext Transfer Protocol Secure" in data["answer"]
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_api_llm_status_endpoint():
    client = TestClient(app)
    resp = client.get("/api/llm/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["model"] == "llama3.2:3b"
    assert "100% Local" in data["privacy"]


def test_canonical_forensic_state_engine_consistency(test_case_state, test_events):
    """Verify Rule 1 & Rule 2: LLM and Fallback produce the exact same canonical forensic_state."""
    # 1. Fallback execution
    fallback_res = generate_chat_response(
        question="Was confidential data copied to USB?",
        events=test_events,
        inv=test_case_state,
        rag={},
        base_url="http://127.0.0.1:59999",
    )

    # 2. Mocked Ollama neural execution
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {
            "role": "assistant",
            "content": "ATT&CK Hypothesis: T1567 · Exfiltration Over Web Service\nStatus: Hypothesis\nConfidence: Medium\nAssessment: Neural interpretation text.\n\nExaminer Verification Checklist:\n1. Step one.\n2. Step two.",
        }
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        llm_res = generate_chat_response(
            question="Was confidential data copied to USB?",
            events=test_events,
            inv=test_case_state,
            rag={},
            model="llama3.2:3b",
        )

    assert fallback_res["forensic_state"] is not None
    assert llm_res["forensic_state"] is not None

    # Verify IDENTICAL forensic_state across both engines
    assert fallback_res["forensic_state"] == llm_res["forensic_state"]
    assert fallback_res["forensic_state"]["assessment"]["status"] == "NOT_ESTABLISHED"
    assert len(fallback_res["forensic_state"]["observed_evidence"]) == len(llm_res["forensic_state"]["observed_evidence"])
    assert len(fallback_res["forensic_state"]["unproven_findings"]) == len(llm_res["forensic_state"]["unproven_findings"])
    assert len(fallback_res["forensic_state"]["evidence_gaps"]) == len(llm_res["forensic_state"]["evidence_gaps"])


def test_canonical_state_deduplication_usb(test_case_state):
    """Verify Rule 3: Multiple USB artifacts are deduplicated into ONE single observed finding with separated chips."""
    from app.services.investigation import build_canonical_forensic_state

    # 4 distinct USB artifacts from different sources
    usb_events = [
        {"id": 4, "source_type": "windows_event", "event_type": "usb", "description": "USB mass storage inserted VID_0781", "event_id": "json_2"},
        {"id": 12, "source_type": "windows_event", "event_type": "usb", "description": "USB device removed SanDisk Ultra", "event_id": "json_6"},
        {"id": 27, "source_type": "windows_event", "event_type": "usb_connect", "description": "Windows Event 6416: New external device recognized", "event_id": "6416"},
        {"id": 28, "source_type": "registry", "event_type": "usb_history", "description": "Registry artifact Key: USBSTOR VID_0781", "target": "SanDisk"},
    ]

    state = build_canonical_forensic_state(usb_events, test_case_state, "Was USB connected?")
    observed = state["observed_evidence"]

    # Must be deduplicated into EXACTLY ONE USB item
    usb_items = [item for item in observed if item["id"] == "usb_connection"]
    assert len(usb_items) == 1

    usb_finding = usb_items[0]
    assert usb_finding["title"] == "USB Device Connection"
    # Evidence IDs gathered from all artifacts: [4, 12, 27, 28]
    assert usb_finding["evidence_ids"] == [4, 12, 27, 28]
    # Event ID separated: [6416] (NOT inside evidence_ids)
    assert usb_finding["event_ids"] == [6416]
    # Artifact tags separated: ['USBSTOR']
    assert "USBSTOR" in usb_finding["artifacts"]


def test_api_chat_endpoint_returns_canonical_forensic_state(db_session):
    """Verify API chat endpoint returns structured canonical forensic_state and generated_analysis."""
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        client = TestClient(app)
        case = Case(case_number="CASE-STATE-TEST", title="Test Canonical State", investigator="Lead Examiner")
        db_session.add(case)
        db_session.commit()
        db_session.refresh(case)

        chat_resp = client.post(
            f"/api/cases/{case.id}/chat",
            json={"question": "Was confidential data copied to USB?", "model": "llama3.2:3b"},
        )
        assert chat_resp.status_code == 200
        data = chat_resp.json()
        assert "forensic_state" in data
        assert "generated_analysis" in data
        assert data["forensic_state"]["assessment"]["status"] == "NOT_ESTABLISHED"
        assert len(data["forensic_state"]["evidence_gaps"]) >= 3
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_generate_chat_response_general_educational(test_case_state, test_events):
    """Verify general educational queries return clean normal LLM responses without forensic templates."""
    # 1. Cryptography query
    res_crypto = generate_chat_response(
        question="Explain cryptography",
        events=test_events,
        inv=test_case_state,
        rag={},
    )
    assert res_crypto["intent"] == "GENERAL"
    assert "Confidentiality" in res_crypto["answer"] or "cryptography" in res_crypto["answer"].lower()
    assert res_crypto["forensic_state"] is None
    assert "FORENSIC ASSESSMENT" not in res_crypto["answer"]
    assert "OBSERVED CASE EVIDENCE" not in res_crypto["answer"]
    assert "USB-based" not in res_crypto["answer"]

    # 2. AI query
    res_ai = generate_chat_response(
        question="What is AI?",
        events=test_events,
        inv=test_case_state,
        rag={},
    )
    assert res_ai["intent"] == "GENERAL"
    assert "Artificial Intelligence" in res_ai["answer"]
    assert res_ai["forensic_state"] is None


def test_generate_chat_response_technical_forensic_methodology(test_case_state, test_events):
    """Verify forensic methodology questions return structured knowledge without case verdict dumps."""
    res = generate_chat_response(
        question="how could we find the suspicious activity taken place?",
        events=test_events,
        inv=test_case_state,
        rag={},
    )
    assert res["intent"] in {"FORENSIC_KNOWLEDGE", "TECHNICAL_FORENSIC"}
    assert "Authentication" in res["answer"] or "Event ID 4624" in res["answer"]
    assert "Process Execution" in res["answer"] or "Prefetch" in res["answer"]
    assert "General forensic knowledge" in res["answer"]
    # Does not dump the USB false verdict
    assert "The available evidence does not establish that any confidential file was copied to a USB device" not in res["answer"]

