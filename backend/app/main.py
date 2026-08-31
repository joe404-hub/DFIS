"""DFIS Backend API Service.

Integrates the Automated Evidence Ingestion Engine with case management,
unified timeline generation, case-specific RAG vector retrieval,
incident classification, risk scoring, ATT&CK mapping, and automated reporting.
"""

from __future__ import annotations

import shutil
import zipfile
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import Base, EVIDENCE_DIR, engine, get_db, migrate
from app.models import Artifact, Case, CustodyEvent, Evidence, Finding, Recommendation
from app.services.analyzer import analyze_timeline, answer_question
from app.services.detector import detect_file_type
from app.services.ingestion import EvidenceIngestionEngine, IngestionSummary
from app.services.integrity import sha256_file
from app.services.llm import check_local_llm_health, generate_chat_response
from app.services.parsers import classify_skipped, parse_file
from app.services.rag import index_case_events, knowledge_collection, retrieve
from app.services.report import generate_report
from app.services.seed import write_demo_package
from app.services.timeline import build_timeline, fingerprint

app = FastAPI(title="DFIS — Forensic Investigation Platform", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)
migrate()


class CaseIn(BaseModel):
    case_number: str
    title: str
    description: str = ""
    investigator: str = "Investigator"


class ChatIn(BaseModel):
    question: str
    model: str = "llama3.2:3b"
    temperature: float = 0.1


class GeneratorMetadata(BaseModel):
    type: str
    provider: str
    model: Optional[str] = None
    mode: Optional[str] = None
    fallback: bool
    verified: bool = False
    reason: Optional[str] = None
    provenance_id: Optional[str] = None
    request_id: Optional[str] = None
    generated_at: Optional[str] = None


class LLMConfigIn(BaseModel):
    model: str = "llama3.2:3b"
    base_url: str = "http://localhost:11434"
    temperature: float = 0.1
    timeout: float = 20.0


class RecStatusIn(BaseModel):
    status: str


class AcquireIn(BaseModel):
    mode: str = "automated_collection"  # manual_import, automated_collection, hybrid_collection
    policy: dict[str, bool] = {
        "collect_security_logs": True,
        "collect_system_logs": True,
        "collect_powershell_logs": True,
        "collect_registry": True,
        "collect_browser_history": True,
        "collect_browser_downloads": True,
        "collect_filesystem": True,
        "collect_prefetch": True,
        "collect_amcache": True,
        "collect_network": True,
        "collect_memory": False,
    }
    notes: str = ""


def _case_or_404(db: Session, case_id: int) -> Case:
    c = db.get(Case, case_id)
    if not c:
        raise HTTPException(404, "Case not found")
    return c


def _art_to_dict(a: Artifact) -> dict[str, Any]:
    """Serialize an Artifact to the Common Forensic Event Schema dictionary."""
    return {
        "id": a.id,
        "case_id": a.case_id,
        "evidence_id": a.evidence_id,
        "event_id": getattr(a, "event_id", "") or "",
        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        "timestamp_utc": getattr(a, "timestamp_utc", "") or (a.timestamp.isoformat() + "Z" if a.timestamp else ""),
        "source": getattr(a, "source", "") or f"{a.source_type.title()} Artifact",
        "source_type": a.source_type,
        "artifact_type": getattr(a, "artifact_type", "") or a.source_type.replace("_", " ").title(),
        "event_type": a.event_type,
        "user": getattr(a, "user", "") or a.actor or "",
        "actor": a.actor or getattr(a, "user", "") or "",
        "host": getattr(a, "host", "") or "",
        "process": a.process or "",
        "pid": a.pid or "",
        "action": getattr(a, "action", "") or a.event_type.replace("_", " ").title(),
        "object": getattr(a, "object", "") or a.target or "",
        "target": a.target or getattr(a, "object", "") or "",
        "path": getattr(a, "path", "") or a.source_path or "",
        "source_path": a.source_path or "",
        "destination_path": a.destination_path or "",
        "source_ip": a.source_ip or "",
        "source_port": a.source_port or "",
        "destination_ip": a.destination_ip or "",
        "destination_port": a.destination_port or "",
        "description": a.description or "",
        "evidence_hash": getattr(a, "evidence_hash", "") or "",
        "fingerprint": a.fingerprint or "",
        "correlation_id": a.correlation_id or "",
        "parser_name": a.parser_name or "",
        "source_file": a.source_file or "",
        "time_kind": getattr(a, "time_kind", None) or ("observation" if a.source_type == "memory" else "event"),
        "observation_time": getattr(a, "observation_time", None) or "",
        "raw_data": a.raw_data or "",
    }


def process_evidence_file(db: Session, case: Case, dest: Path, original_name: str, notes: str = "") -> tuple[Evidence, IngestionSummary]:
    """Execute the automated Evidence Ingestion Engine pipeline."""
    engine_inst = EvidenceIngestionEngine(db, case)
    ev, summary = engine_inst.ingest_evidence(dest, original_name, notes=notes)
    return ev, summary


def rebuild_analysis(db: Session, case: Case) -> dict[str, Any]:
    """Index artifacts into RAG vector collection and execute AI classification / risk scoring."""
    arts = db.query(Artifact).filter(Artifact.case_id == case.id).order_by(Artifact.timestamp.asc()).all()
    events = [_art_to_dict(a) for a in arts]
    index_case_events(case.id, events)
    result = analyze_timeline(events, case_id=case.id)

    db.query(Finding).filter(Finding.case_id == case.id).delete()
    prev = {
        r.action: r.status
        for r in db.query(Recommendation).filter(Recommendation.case_id == case.id).all()
    }
    db.query(Recommendation).filter(Recommendation.case_id == case.id).delete()

    for a in result.get("next_actions") or []:
        db.add(
            Recommendation(
                case_id=case.id,
                priority=int(a.get("priority") or 0),
                question=a.get("question") or "",
                action=a.get("action") or "",
                reason=a.get("reason") or "",
                evidence_ids=",".join(str(i) for i in (a.get("evidence_ids") or [])),
                status=prev.get(a.get("action") or "", a.get("status") or "pending_examiner_verification"),
                layer=a.get("layer") or "verify",
            )
        )

    for f in result.get("findings") or []:
        db.add(
            Finding(
                case_id=case.id,
                category=f["category"],
                title=f["title"],
                body=f["body"],
                risk_score=f["risk_score"],
                confidence=f["confidence"],
                attack_stage=f["attack_stage"],
                mitre_ids=f["mitre_ids"],
                artifact_ids=f["artifact_ids"],
            )
        )
    db.commit()
    return result


@app.on_event("startup")
def startup():
    knowledge_collection()
    db = next(get_db())
    try:
        if db.query(Case).count() == 0:
            demo = Case(
                case_number="CASE-DEMO",
                title="Suspected source-code exfiltration — WORKSTATION-14",
                description="Demonstration case: login, GitHub, USB, archive, Google Drive exfiltration.",
                investigator="A. Rao",
                status="open",
            )
            db.add(demo)
            db.commit()
            db.refresh(demo)
            zpath = write_demo_package()
            dest = EVIDENCE_DIR / f"case{demo.id}_{zpath.name}"
            shutil.copy(zpath, dest)
            process_evidence_file(db, demo, dest, zpath.name, notes="Seeded demo package")
            rebuild_analysis(db, demo)
    finally:
        db.close()


@app.get("/api/health")
def health():
    return {"ok": True, "service": "DFIS", "pipeline": "automated_evidence_ingestion_engine"}


@app.get("/api/cases")
def list_cases(db: Session = Depends(get_db)):
    cases = db.query(Case).order_by(Case.id.desc()).all()
    out = []
    for c in cases:
        finding = db.query(Finding).filter(Finding.case_id == c.id).first()
        out.append(
            {
                "id": c.id,
                "case_number": c.case_number,
                "title": c.title,
                "description": c.description,
                "investigator": c.investigator,
                "status": c.status,
                "created_at": c.created_at.isoformat(),
                "evidence_count": len(c.evidence),
                "artifact_count": len(c.artifacts),
                "risk_score": finding.risk_score if finding else 0,
                "category": finding.category if finding else None,
            }
        )
    return out


@app.post("/api/cases")
def create_case(body: CaseIn, db: Session = Depends(get_db)):
    if db.query(Case).filter(Case.case_number == body.case_number).first():
        raise HTTPException(400, "Case number exists")
    c = Case(**body.model_dump())
    db.add(c)
    db.commit()
    db.refresh(c)
    db.add(CustodyEvent(case_id=c.id, action="case_created", actor=c.investigator, detail=c.title))
    db.commit()
    return {"id": c.id, "case_number": c.case_number}


@app.get("/api/cases/{case_id}")
def get_case(case_id: int, db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    finding = db.query(Finding).filter(Finding.case_id == c.id).all()
    evidence = [
        {
            "id": e.id,
            "filename": e.filename,
            "sha256": e.sha256,
            "source_type": e.source_type,
            "detected_type": getattr(e, "detected_type", "") or e.source_type,
            "magic_signature": getattr(e, "magic_signature", "") or "",
            "size_bytes": e.size_bytes,
            "artifact_count": getattr(e, "artifact_count", 0) or len(e.artifacts),
            "uploaded_at": e.uploaded_at.isoformat(),
            "integrity_ok": e.integrity_ok,
        }
        for e in c.evidence
    ]
    custody = (
        db.query(CustodyEvent)
        .filter(CustodyEvent.case_id == c.id)
        .order_by(CustodyEvent.created_at.asc())
        .all()
    )
    return {
        "id": c.id,
        "case_number": c.case_number,
        "title": c.title,
        "description": c.description,
        "investigator": c.investigator,
        "status": c.status,
        "created_at": c.created_at.isoformat(),
        "evidence": evidence,
        "findings": [
            {
                "id": f.id,
                "category": f.category,
                "title": f.title,
                "body": f.body,
                "risk_score": f.risk_score,
                "confidence": f.confidence,
                "attack_stage": f.attack_stage,
                "mitre_ids": f.mitre_ids,
                "artifact_ids": [int(x) for x in f.artifact_ids.split(",") if x],
            }
            for f in finding
        ],
        "custody": [
            {
                "action": x.action,
                "actor": x.actor,
                "detail": x.detail,
                "created_at": x.created_at.isoformat(),
            }
            for x in custody
        ],
    }


@app.get("/api/cases/{case_id}/evidence")
def list_case_evidence(case_id: int, db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    return [
        {
            "id": e.id,
            "filename": e.filename,
            "sha256": e.sha256,
            "source_type": e.source_type,
            "detected_type": getattr(e, "detected_type", "") or e.source_type,
            "magic_signature": getattr(e, "magic_signature", "") or "",
            "mime_type": getattr(e, "mime_type", "") or "",
            "size_bytes": e.size_bytes,
            "artifact_count": getattr(e, "artifact_count", 0) or len(e.artifacts),
            "uploaded_at": e.uploaded_at.isoformat(),
            "integrity_ok": e.integrity_ok,
            "notes": e.notes,
        }
        for e in c.evidence
    ]


@app.post("/api/cases/{case_id}/evidence")
async def upload_evidence(case_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload and automatically ingest an evidence package (ZIP, EVTX, Registry, SQLite, PCAP, CSV)."""
    c = _case_or_404(db, case_id)
    dest = EVIDENCE_DIR / f"case{c.id}_{datetime.utcnow().strftime('%H%M%S')}_{file.filename}"
    with dest.open("wb") as out:
        shutil.copyfileobj(file.file, out)

    ev, summary = process_evidence_file(db, c, dest, file.filename)
    analysis = rebuild_analysis(db, c)

    return {
        "evidence_id": ev.id,
        "filename": ev.filename,
        "sha256": ev.sha256,
        "detected_type": ev.detected_type,
        "magic_signature": ev.magic_signature,
        "artifact_count": ev.artifact_count,
        "summary": asdict(summary),
        "analysis": analysis,
    }


@app.post("/api/cases/{case_id}/acquire")
def acquire_evidence(case_id: int, body: AcquireIn, db: Session = Depends(get_db)):
    """Execute authorized policy-driven automated endpoint acquisition, compute SHA-256, and ingest."""
    c = _case_or_404(db, case_id)
    from app.services.acquisition import AutomatedEvidenceCollector, AcquisitionPolicy
    pol = AcquisitionPolicy(**body.policy)
    collector = AutomatedEvidenceCollector(db, c)
    ev, report = collector.run_authorized_collection(pol, mode=body.mode, notes=body.notes)
    analysis = rebuild_analysis(db, c)

    return {
        "evidence_id": ev.id,
        "package_filename": report.package_filename,
        "package_sha256": report.package_sha256,
        "report": asdict(report),
        "analysis": analysis,
    }


@app.post("/api/cases/{case_id}/verify/{evidence_id}")
def verify_hash(case_id: int, evidence_id: int, db: Session = Depends(get_db)):
    _case_or_404(db, case_id)
    ev = db.get(Evidence, evidence_id)
    if not ev or ev.case_id != case_id:
        raise HTTPException(404, "Evidence not found")
    current = sha256_file(ev.stored_path)
    ev.integrity_ok = current == ev.sha256
    db.commit()
    return {"stored": ev.sha256, "current": current, "ok": ev.integrity_ok}


@app.get("/api/cases/{case_id}/timeline")
def timeline(case_id: int, db: Session = Depends(get_db)):
    _case_or_404(db, case_id)
    arts = db.query(Artifact).filter(Artifact.case_id == case_id).order_by(Artifact.timestamp.asc()).all()
    return [_art_to_dict(a) for a in arts]


@app.get("/api/cases/{case_id}/artifacts")
def get_artifacts(
    case_id: int,
    source_type: Optional[str] = None,
    artifact_type: Optional[str] = None,
    user: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Retrieve filterable forensic artifacts adhering to Common Forensic Event Schema."""
    _case_or_404(db, case_id)
    query = db.query(Artifact).filter(Artifact.case_id == case_id)
    if source_type:
        query = query.filter(Artifact.source_type == source_type)
    if artifact_type:
        query = query.filter(Artifact.artifact_type.ilike(f"%{artifact_type}%"))
    if user:
        query = query.filter((Artifact.actor.ilike(f"%{user}%")) | (Artifact.user.ilike(f"%{user}%")))
    if search:
        s_pat = f"%{search}%"
        query = query.filter(
            (Artifact.description.ilike(s_pat))
            | (Artifact.target.ilike(s_pat))
            | (Artifact.process.ilike(s_pat))
            | (Artifact.path.ilike(s_pat))
        )

    arts = query.order_by(Artifact.timestamp.asc()).all()
    return [_art_to_dict(a) for a in arts]


@app.get("/api/cases/{case_id}/graph")
def graph(case_id: int, db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    arts = db.query(Artifact).filter(Artifact.case_id == case_id).all()
    events = [_art_to_dict(a) for a in arts]
    inv = analyze_timeline(events, case_id=c.id)
    nodes = {}
    edges = []

    def node(nid, label, group):
        nodes[nid] = {"id": nid, "label": str(label)[:56], "group": group}

    for g in inv.get("correlations") or []:
        cid = f"c:{g['correlation_id']}"
        node(cid, f"{g['family']}\n{g['entity']}", "correlated")
        for s in g.get("sources") or []:
            eid = f"e{s.get('event_id')}"
            node(eid, f"#{s.get('event_id')} {s.get('source_type')}", s.get("source_type") or "evidence")
            edges.append({"from": eid, "to": cid, "label": "supports"})
        if g.get("actor"):
            an = "a:" + g["actor"]
            node(an, g["actor"], "actor")
            edges.append({"from": an, "to": cid, "label": "involved"})
        if g.get("destination"):
            dn = "d:" + g["destination"]
            node(dn, g["destination"], "destination")
            edges.append({"from": cid, "to": dn, "label": "to"})
    if not nodes:
        for a in arts:
            evn = f"e{a.id}"
            node(evn, a.event_type, a.source_type)
            if a.actor:
                an = "a:" + a.actor
                node(an, a.actor, "actor")
                edges.append({"from": an, "to": evn, "label": "performed"})
            if a.target:
                tn = "t:" + a.target
                node(tn, a.target[:40], "target")
                edges.append({"from": evn, "to": tn, "label": "involves"})
    return {"nodes": list(nodes.values()), "edges": edges}


@app.post("/api/cases/{case_id}/reprocess")
def reprocess(case_id: int, db: Session = Depends(get_db)):
    """Re-run the Evidence Ingestion Engine on stored evidence files."""
    c = _case_or_404(db, case_id)
    db.query(Artifact).filter(Artifact.case_id == case_id).delete()
    db.query(Finding).filter(Finding.case_id == case_id).delete()
    db.commit()

    db.add(
        CustodyEvent(
            case_id=c.id,
            action="reprocessed",
            actor="Evidence Ingestion Engine",
            detail="Artifacts cleared and automated parsers re-run on stored working copies",
        )
    )
    db.commit()

    raw_events: list[dict[str, Any]] = []
    for ev in db.query(Evidence).filter(Evidence.case_id == case_id).all():
        path = Path(ev.stored_path)
        if not path.exists():
            continue

        work_files: list[tuple[Path, str]] = []
        if zipfile.is_zipfile(path):
            extract_dir = path.parent / f"extracted_{ev.id}"
            extract_dir.mkdir(exist_ok=True)
            with zipfile.ZipFile(path) as zf:
                zf.extractall(extract_dir)
            work_files = [(p, str(p.relative_to(extract_dir))) for p in extract_dir.rglob("*") if p.is_file()]
        else:
            work_files = [(path, ev.filename)]

        for fp, rel in work_files:
            if classify_skipped(fp):
                continue
            detection = detect_file_type(fp)
            parsed = parse_file(fp, detection=detection)
            for rec in parsed:
                rec["evidence_id"] = ev.id
                rec["evidence_hash"] = ev.sha256
                rec["source_file"] = rel
                rec["fingerprint"] = fingerprint(rec)
                raw_events.append(rec)

    timeline_events = build_timeline(raw_events)
    engine_inst = EvidenceIngestionEngine(db, c)
    for rec in timeline_events:
        db.add(engine_inst._create_artifact_row(rec.get("evidence_id") or 1, rec))

    db.commit()
    return rebuild_analysis(db, c)


@app.post("/api/cases/{case_id}/analyze")
def analyze(case_id: int, db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    return rebuild_analysis(db, c)


@app.get("/api/cases/{case_id}/recommendations")
def list_recommendations(case_id: int, db: Session = Depends(get_db)):
    _case_or_404(db, case_id)
    rows = (
        db.query(Recommendation)
        .filter(Recommendation.case_id == case_id)
        .order_by(Recommendation.priority.asc())
        .all()
    )
    if not rows:
        rebuild_analysis(db, db.get(Case, case_id))
        rows = (
            db.query(Recommendation)
            .filter(Recommendation.case_id == case_id)
            .order_by(Recommendation.priority.asc())
            .all()
        )
    return [
        {
            "id": r.id,
            "priority": r.priority,
            "question": getattr(r, "question", "") or "",
            "action": r.action,
            "reason": r.reason,
            "evidence_ids": [int(x) for x in r.evidence_ids.split(",") if x],
            "status": r.status,
            "layer": r.layer,
        }
        for r in rows
    ]


@app.patch("/api/cases/{case_id}/recommendations/{rec_id}")
def update_recommendation(case_id: int, rec_id: int, body: RecStatusIn, db: Session = Depends(get_db)):
    _case_or_404(db, case_id)
    rec = db.get(Recommendation, rec_id)
    if not rec or rec.case_id != case_id:
        raise HTTPException(404, "Recommendation not found")
    allowed = {"pending_examiner_verification", "in_progress", "verified", "not_applicable"}
    if body.status not in allowed:
        raise HTTPException(400, f"status must be one of {sorted(allowed)}")
    rec.status = body.status
    db.add(
        CustodyEvent(
            case_id=case_id,
            action="recommendation_status",
            actor="examiner",
            detail=f"{rec.action} → {body.status}",
        )
    )
    db.commit()
    return {"id": rec.id, "status": rec.status}


@app.get("/api/cases/{case_id}/investigation")
def investigation(case_id: int, db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    arts = db.query(Artifact).filter(Artifact.case_id == case_id).order_by(Artifact.timestamp.asc()).all()
    return analyze_timeline([_art_to_dict(a) for a in arts], case_id=c.id)


@app.get("/api/llm/status")
def llm_status():
    """Return status and configuration for the local LLM (llama3.2:3b)."""
    return check_local_llm_health()


@app.post("/api/llm/config")
def set_llm_config(body: LLMConfigIn):
    """Test and update configuration for the local LLM instance."""
    return check_local_llm_health(base_url=body.base_url, model=body.model)


@app.post("/api/cases/{case_id}/chat")
def chat(case_id: int, body: ChatIn, db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    arts = db.query(Artifact).filter(Artifact.case_id == case_id).all()
    events = [_art_to_dict(a) for a in arts]
    rag = retrieve(case_id, body.question)
    analysis = analyze_timeline(events, case_id=case_id)
    chat_res = generate_chat_response(
        question=body.question,
        events=events,
        inv=analysis,
        rag=rag,
        model=body.model or "llama3.2:3b",
        temperature=body.temperature if body.temperature is not None else 0.1,
    )
    return {
        "answer": chat_res.get("answer"),
        "intent": chat_res.get("intent", "FORENSIC_CASE_ANALYSIS"),
        "model": chat_res.get("model", "llama3.2:3b"),
        "provider": chat_res.get("provider", "ollama"),
        "llm_mode": chat_res.get("llm_mode"),
        "is_local": True,
        "query_type": chat_res.get("query_type"),
        "generator": chat_res.get("generator", {
            "type": "fallback",
            "provider": "dfis_grounded_engine",
            "model": None,
            "fallback": True,
            "verified": False,
        }),
        "forensic_state": chat_res.get("forensic_state"),
        "generated_analysis": chat_res.get("generated_analysis"),
        "concept_data": chat_res.get("concept_data"),
        "rag": analysis.get("rag") or rag,
        "category": analysis.get("category"),
        "investigation": {
            "risk_score": analysis.get("risk_score"),
            "attack_chain": analysis.get("attack_chain"),
            "correlations": [
                {
                    "correlation_id": g.get("correlation_id"),
                    "timestamp": g.get("timestamp"),
                    "family": g.get("family"),
                    "entity": g.get("entity"),
                    "source_event_ids": g.get("source_event_ids"),
                }
                for g in (analysis.get("correlations") or [])
            ],
        },
    }


@app.get("/api/cases/{case_id}/report.json")
def report_json(case_id: int, db: Session = Depends(get_db)):
    """Structured evidence-linked report for the UI preview (same payload as the PDF)."""
    c = _case_or_404(db, case_id)
    arts = db.query(Artifact).filter(Artifact.case_id == case_id).order_by(Artifact.timestamp.asc()).all()
    analysis = analyze_timeline([_art_to_dict(a) for a in arts], case_id=c.id)
    from app.services.investigation import _usb_transfer_answer, format_classification_label

    formatted_label = format_classification_label(analysis.get("category"), analysis.get("secondary"))

    return {
        "case": {
            "case_number": c.case_number,
            "title": c.title,
            "investigator": c.investigator,
            "principle": (
                "The LLM does not treat general forensic knowledge as evidence. "
                "It retrieves case-specific events and uses general knowledge only to interpret them. "
                "Every important conclusion is linked to original evidence IDs."
            ),
        },
        "integrity": [
            {"id": e.id, "filename": e.filename, "sha256": e.sha256, "ok": e.integrity_ok}
            for e in c.evidence
        ],
        "classification": {
            "label": formatted_label,
            "priority": analysis.get("priority"),
            "risk_score": analysis.get("risk_score"),
            "disclaimer": (analysis.get("risk") or {}).get("disclaimer"),
        },
        "risk": analysis.get("risk"),
        "attack_chain": analysis.get("attack_chain"),
        "correlations": analysis.get("correlations"),
        "evidentiary_states": analysis.get("evidentiary_states") or [],
        "observations": analysis.get("observations") or [],
        "usb_qa": _usb_transfer_answer(analysis, [_art_to_dict(a) for a in arts]),
        "next_actions": analysis.get("next_actions") or [],
        "timeline": [_art_to_dict(a) for a in arts if a.source_type != "correlated"][:80],
    }


@app.get("/api/cases/{case_id}/report")
def report(case_id: int, db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    arts = db.query(Artifact).filter(Artifact.case_id == case_id).order_by(Artifact.timestamp.asc()).all()
    findings = db.query(Finding).filter(Finding.case_id == case_id).all()
    analysis = analyze_timeline([_art_to_dict(a) for a in arts], case_id=c.id)
    path = generate_report(c, c.evidence, arts, findings, analysis)
    return FileResponse(path, filename=path.name, media_type="application/pdf")
