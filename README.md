# DFIS — AI-Assisted Digital Forensics Investigation Platform

Extension of ForensicLLM into a case-oriented investigation workflow:
evidence import → SHA-256 integrity → artifact extraction → unified timeline →
case-specific RAG → incident classification / risk / ATT&CK mapping →
traceable reports and visualizations.

## Quick start

```bash
# Backend
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Frontend
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```

Or from the repo root:

```bash
bash scripts/dev.sh
```

The API seeds a synthetic **CASE-DEMO** package (Windows-like events, browser SQLite,
USB/file activity, network summary) so the dashboard works immediately.

## Stack

| Layer | Technology |
| --- | --- |
| API | FastAPI, SQLAlchemy, SQLite (PostgreSQL-ready) |
| Integrity | SHA-256 (`hashlib`) |
| Parsers | EVTX, Registry, SQLite browser, filesystem, PCAP (best-effort), metadata |
| Timeline | Normalize → dedupe → correlate → sort |
| RAG | ChromaDB + sentence-transformers (UAE_Large-V1–compatible interface) |
| Analysis | Rule engine + optional local/OpenAI LLM |
| Reports | ReportLab |
| UI | React, Vite, MUI, vis-timeline, vis-network |

## Notes

- AI output is an **investigative aid**, not evidence.
- Every finding is linked to supporting artifact IDs and hashes.
- QLoRA/RAFT belong to model training (ForensicLLM paper), not per-case inference.
