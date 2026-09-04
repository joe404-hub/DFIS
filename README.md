# DFIS — AI-Assisted Digital Forensics Investigation Platform

DFIS extends ForensicLLM into an automated, case-oriented digital forensic investigation workflow:
**Evidence Archive Ingestion → SHA-256 Cryptographic Integrity → Automatic Content-Based Detection → Specialized Artifact Parsing → Common Forensic Schema Normalization → Timestamp Normalization → Deduplication → Multi-Source Correlation → Unified Chronological Timeline → Case RAG Vector Retrieval → Incident Classification / Risk Prioritization / ATT&CK Mapping → Evidence-Linked Reports**.

---

## Automated Forensic Pipeline

```
                 CASE ZIP / EVIDENCE FOLDER
                           │
                           ▼
                  SHA-256 Integrity Check
                           │
                           ▼
             Content-Based File Type Detection
         (Inspects magic bytes & file structure)
                           │
    ┌──────────────────────┼──────────────────────┐
    ▼                      ▼                      ▼
 Windows EVTX        Registry Hives        Browser SQLite
(ElfFile magic)       (regf magic)        (SQLite 3 magic)
    │                      │                      │
    ▼                      ▼                      ▼
EVTX Parser         Registry Parser        SQLite Parser
(4624, 4688,        (UserAssist,           (Chrome, Edge,
 6416, 7045)        RecentDocs, USBSTOR)   Firefox, Brave)
    │                      │                      │
    └──────────────────────┼──────────────────────┘
                           ▼
               Extract Forensic Events
                           │
                           ▼
             Common Forensic Event Schema
 (event_id, timestamp_utc, source, artifact_type,
  event_type, user, host, process, action, object,
  path, source_ip, destination_ip, evidence_hash,
  correlation_id, fingerprint)
                           │
                           ▼
                 Timestamp Normalization
                           │
                           ▼
                    Deduplication
                           │
                           ▼
                  Event Correlation
                           │
                           ▼
               PostgreSQL / SQLite Database
                           │
                           ▼
                 Unified Timeline
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
          Case-Specific RAG       AI Analysis
          (ChromaDB Vector)       (Risk & ATT&CK)
                │                     │
                └──────────┬──────────┘
                           ▼
         Incident Classification / Risk Score /
          ATT&CK Mapping / Q&A / PDF Report
```

---

## What Is Automated?

| Input Type | Magic Signature / Detection | Automated Extractions | Tool / Library |
| :--- | :--- | :--- | :--- |
| **Windows Event Logs (`.evtx`)** | `ElfFile\x00` | EventID, System Time, User, Computer, Process, CommandLine, Parent, IP, Status, Service, USB Device | `python-evtx`, `xml.etree` |
| **Registry Hives (NTUSER.DAT, SYSTEM, SOFTWARE, SAM)** | `regf` | UserAssist execution history (ROT13 decoded, run count, FILETIME), RecentDocs, Run/RunOnce persistence, USBSTOR devices, Services, Mounted Devices, SAM accounts | `python-registry` |
| **Browser Databases (Chrome, Edge, Firefox, Brave)** | `SQLite format 3\x00` | URL history, visit timestamps (WebKit / PRTime normalized), omnibox search queries, downloads, cookies | `sqlite3` |
| **Network Captures (`.pcap`, `.pcapng`)** | `\xd4\xc3\xb2\xa1`, `\x0a\x0d\x0d\x0a` | DNS queries/responses, HTTP requests, TLS Client Hello SNI hostnames, TCP/UDP connection sessions | `scapy` |
| **Memory Snapshots / Volatility** | `PAGEDUMP`, `PAGE`, text | Running process list (`pslist`), command lines (`cmdline`), active network sockets (`netscan`), observation times | `re`, `json` |
| **File System Metadata / Documents** | `FILE`, `%PDF-`, `\xff\xd8\xff`, `\x89PNG` | Timestamps (`mtime`, `ctime`), file size, paths, user actions, document metadata | `pathlib`, `os` |
| **Delimited Tabular Data (`.csv`, `.tsv`)** | Header analysis | Windows Security/System, Registry, Browser, Network, FileSystem CSV records | `csv` |
| **Any Uploaded File** | Byte stream | Cryptographic SHA-256 digest computed at ingestion and verified on demand | `hashlib` |

---

## Content-Aware Detection: No Reliance on Strict File Names

Rather than requiring files to be named `Windows/Security_events.csv` or `Browser/History.sqlite`, the **File Type Identification Engine** (`detector.py`) inspects file headers, byte magic, and internal structures:

```
CASE003.zip
   ├── Security.bin           ──▶ Magic 'ElfFile\x00'    ──▶ Windows EVTX Parser
   ├── SYSTEM.hiv             ──▶ Magic 'regf'           ──▶ Registry SYSTEM Parser
   ├── raw_history            ──▶ Magic 'SQLite 3'       ──▶ Chrome/Firefox Browser Parser
   ├── 2026-08-14_dump        ──▶ Magic '0xd4c3b2a1'     ──▶ PCAP Network Parser
   └── memory_snapshot.txt    ──▶ Process/Net Heuristic  ──▶ Memory Parser
```

---

## Common Forensic Event Schema

All parsers emit standardized event structures containing:
- `event_id`: Canonical event identifier (e.g., `4688`, `4624`, `url_visit`, `usbstor`)
- `timestamp`: Normalized local / wall-clock datetime
- `timestamp_utc`: ISO-8601 UTC timestamp string
- `source`: Authoritative evidence source name (e.g., `Windows Security.evtx`, `Chrome History`)
- `source_type`: Canonical category (`windows_event`, `registry`, `browser`, `network`, `filesystem`, `memory`, `correlated`)
- `artifact_type`: Forensic artifact category (`Process Creation`, `Browser History`, `USB Storage History`, `Registry Persistence`, `Network Flow`, `File Access`, `Logon`)
- `event_type`: Normalized event type (`process_create`, `logon`, `failed_logon`, `logoff`, `url_visit`, `download`, `cookie`, `usb_connect`, `usb_remove`, `file_access`, `file_copy`, `network_flow`, `dns_query`, `service_install`, etc.)
- `user` / `actor`: Account or user identity
- `host`: Hostname / Computer name
- `process`: Binary name (e.g., `powershell.exe`)
- `pid`: Process identifier
- `action`: Human-readable action description
- `object` / `target`: Targeted file, URL, registry key, or entity
- `path` / `source_path` / `destination_path`: Source and destination paths (e.g., file copy destination)
- `source_ip` / `source_port`: Network source endpoint
- `destination_ip` / `destination_port`: Network destination endpoint
- `description`: Structured forensic event narrative
- `evidence_hash`: Cryptographic SHA-256 hash of the evidence file
- `fingerprint`: Deterministic SHA-256 hash for deduplication
- `correlation_id`: Analytical cross-source grouping identifier
- `time_kind`: `event` (historical timestamp) or `observation` (snapshot time, e.g., memory)
- `raw_data`: Full original JSON / XML payload for verification

---

## Operating Modes

1. **Real Investigation Mode**:
   Upload a raw case evidence ZIP or folder containing `.evtx` logs, Registry hives, browser SQLite databases, `.pcap` files, and memory snapshots. The system automatically detects file types, parses artifacts, extracts common schema fields, verifies SHA-256 hashes, deduplicates events, and generates a unified chronological timeline.

2. **Development / Synthetic Evaluation Mode**:
   Seamless backward compatibility for synthetic benchmark datasets (e.g., `CASE001`, `CASE002`, `CASE-DEMO`).

---

## Quick Start

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```

Or run both via:

```bash
bash scripts/dev.sh
```

---

## Running Tests

```bash
cd backend
source .venv/bin/activate
pytest tests/
```

---

## Core Principles

## Core Principles

- **Local LLM Inference (`llama3.2:3b`)**: 100% local, air-gapped forensic AI assistance via Ollama or local inference engine. Zero case data is transmitted to external or online chatbots.
- **AI is an investigative aid, not evidence**: The system assists examiners in identifying patterns and forming hypotheses, but cannot manufacture evidence.
- **Cryptographic Provenance**: Every finding, attack-chain stage, and correlation link traces directly to original SHA-256 verified evidence IDs.
- **General forensic knowledge is strictly separated from case-specific facts via RAG**: General concepts provide interpretive context only and cannot be cited as case evidence.

---

## Local LLM Setup (`llama3.2:3b`)

DFIS is configured out of the box to use the local **`llama3.2:3b`** model for investigator chat, timeline interpretation, and grounded Q&A.

### 1. Launch Ollama with `llama3.2:3b`

To enable live local neural inference on your forensic workstation:

```bash
# Pull and start llama3.2:3b locally
ollama run llama3.2:3b
```

Ollama listens on `http://localhost:11434` by default. DFIS automatically detects the running daemon and routes investigator queries through the local model with low temperature (`0.1`) and strict forensic grounding system prompts.

### 2. Air-Gapped & Offline Fallback

If Ollama is not installed or running, DFIS automatically activates its **Offline Grounded Reasoning Engine**, ensuring 100% test reliability, instant responses, and zero downtime without external network access.

### 3. Forensic Grounding Invariants

Every completion generated by `llama3.2:3b` adheres to mandatory forensic rules:
1. Valid-account logons (Event 4624) do not imply unauthorized access or compromise.
2. Network and browser traffic over HTTPS/443 do not establish data exfiltration without corroborated staging.
3. Missing evidence is explicitly stated as `NOT ESTABLISHED` or `INSUFFICIENT EVIDENCE`.
4. Correlation IDs are analytical relationships, not original evidence files.
5. All case assertions cite exact Evidence IDs.
