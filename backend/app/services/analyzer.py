"""Forensic Timeline Analyzer & Grounded AI Classification."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from typing import Any

from app.services.investigation import answer_from_investigation, run_investigation

CATEGORIES = [
    "Data Theft",
    "Insider Threat",
    "Malware Infection",
    "Possible Unauthorized Use of Valid Account",
    "Possible Suspicious Network Activity",
    "Ransomware",
    "Credential Abuse",
    "Normal Activity",
]


def analyze_timeline(events: list[dict], case_id: int | None = None) -> dict[str, Any]:
    """Execute complete forensic investigation analysis across the timeline."""
    return run_investigation(case_id or 0, events)


def answer_question(question: str, rag: dict, events: list[dict], analysis: dict) -> str:
    """Produce grounded examiner Q&A answers citing case evidence and uncertainty bounds."""
    return answer_from_investigation(question, events, {**analysis, "rag": rag or analysis.get("rag") or {}})
