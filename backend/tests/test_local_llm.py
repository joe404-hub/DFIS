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
