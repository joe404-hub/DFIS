import shutil
import zipfile
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import Base, EVIDENCE_DIR, engine, get_db, migrate
from app.models import Artifact, Case, CustodyEvent, Evidence, Finding
from app.services.analyzer import analyze_timeline, answer_question
from app.services.integrity import sha256_file
from app.services.parsers import classify_skipped, parse_file
from app.services.rag import index_case_events, knowledge_collection, retrieve
from app.services.report import generate_report
from app.services.seed import write_demo_package
from app.services.timeline import build_timeline, fingerprint

app = FastAPI(title="DFIS", version="1.0.0")
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


def _case_or_404(db: Session, case_id: int) -> Case:
    c = db.get(Case, case_id)
    if not c:
        raise HTTPException(404, "Case not found")
    return c


def _art_to_dict(a: Artifact) -> dict:
    return {
        "id": a.id,
        "case_id": a.case_id,
        "evidence_id": a.evidence_id,
        "source_type": a.source_type,
        "event_type": a.event_type,
        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        "description": a.description,
        "actor": a.actor,
        "target": a.target,
        "raw_data": a.raw_data,
        "fingerprint": a.fingerprint,
        "parser_name": a.parser_name,
        "source_file": a.source_file,
        "correlation_id": a.correlation_id,
        "process": a.process,
        "pid": a.pid,
        "source_path": a.source_path,
        "destination_path": a.destination_path,
        "source_ip": a.source_ip,
        "source_port": a.source_port,
        "destination_ip": a.destination_ip,
        "destination_port": a.destination_port,
    }


def _artifact_row(case_id: int, evidence_id: int, rec: dict) -> Artifact:
    return Artifact(
        case_id=case_id,
        evidence_id=evidence_id,
        source_type=rec.get("source_type") or "unknown",
        event_type=rec.get("event_type") or "event",
        timestamp=rec.get("timestamp"),
        description=rec.get("description") or "",
        actor=rec.get("actor") or "",
        target=(rec.get("target") or "")[:512],
        raw_data=rec.get("raw_data") or "",
        fingerprint=rec.get("fingerprint") or "",
        parser_name=rec.get("parser_name") or "",
        source_file=rec.get("source_file") or "",
        correlation_id=rec.get("correlation_id") or "",
        process=rec.get("process") or "",
        pid=str(rec.get("pid") or ""),
        source_path=rec.get("source_path") or "",
        destination_path=rec.get("destination_path") or "",
        source_ip=rec.get("source_ip") or "",
        source_port=str(rec.get("source_port") or ""),
        destination_ip=rec.get("destination_ip") or "",
        destination_port=str(rec.get("destination_port") or ""),
    )


def process_evidence_file(db: Session, case: Case, dest: Path, original_name: str, notes: str = "") -> Evidence:
    digest = sha256_file(dest)
    ev = Evidence(
        case_id=case.id,
        filename=original_name,
        stored_path=str(dest),
        sha256=digest,
        source_type=_guess_type(original_name),
        size_bytes=dest.stat().st_size,
        notes=notes,
        integrity_ok=True,
    )
    db.add(ev)
    db.flush()
    db.add(
        CustodyEvent(
            case_id=case.id,
            evidence_id=ev.id,
            action="ingested",
            actor="system",
            detail=f"SHA-256 {digest}",
        )
    )
    work_files: list[Path] = []
    if zipfile.is_zipfile(dest):
        extract_dir = dest.parent / f"extracted_{ev.id}"
        extract_dir.mkdir(exist_ok=True)
        with zipfile.ZipFile(dest) as zf:
            zf.extractall(extract_dir)
        work_files = [p for p in extract_dir.rglob("*") if p.is_file()]
    else:
        work_files = [dest]

    raw = []
    skipped = []
    for fp in work_files:
        reason = classify_skipped(fp)
        if reason:
            skipped.append(f"{fp.name} ({reason})")
            continue
        parsed = parse_file(fp, ev.source_type)
        if not parsed:
            skipped.append(f"{fp.name} (no forensic events)")
            continue
        for rec in parsed:
            rec["evidence_id"] = ev.id
            rec["fingerprint"] = fingerprint(rec)
            raw.append(rec)
    if skipped:
        db.add(
            CustodyEvent(
                case_id=case.id,
                evidence_id=ev.id,
                action="artifact_classification",
                actor="system",
                detail="Excluded from investigative timeline: " + "; ".join(skipped),
            )
        )
    timeline = build_timeline(raw)
    for rec in timeline:
        db.add(
            Artifact(
                case_id=case.id,
                evidence_id=ev.id,
                source_type=rec.get("source_type") or "unknown",
                event_type=rec.get("event_type") or "event",
                timestamp=rec.get("timestamp"),
                description=rec.get("description") or "",
                actor=rec.get("actor") or "",
                target=rec.get("target") or "",
                raw_data=rec.get("raw_data") or "",
                fingerprint=rec.get("fingerprint") or "",
            )
        )
    db.commit()
    db.refresh(ev)
    return ev


def _guess_type(name: str) -> str:
    n = name.lower()
    if n.endswith(".evtx"):
        return "windows_event"
    if n.endswith(".pcap") or n.endswith(".pcapng"):
        return "network"
    if "history" in n or n.endswith(".sqlite"):
        return "browser"
    if n.endswith(".zip") or n.endswith(".e01") or n.endswith(".dd"):
        return "container"
    return "file"


def rebuild_analysis(db: Session, case: Case):
    arts = db.query(Artifact).filter(Artifact.case_id == case.id).order_by(Artifact.timestamp.asc()).all()
    events = [_art_to_dict(a) for a in arts]
    index_case_events(case.id, events)
    result = analyze_timeline(events)
    db.query(Finding).filter(Finding.case_id == case.id).delete()
    for f in result["findings"]:
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
                description="Synthetic teaching case: login, GitHub, USB, archive, Google Drive.",
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
    return {"ok": True, "service": "DFIS"}


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
            "size_bytes": e.size_bytes,
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


@app.post("/api/cases/{case_id}/evidence")
async def upload_evidence(case_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    dest = EVIDENCE_DIR / f"case{c.id}_{datetime.utcnow().strftime('%H%M%S')}_{file.filename}"
    with dest.open("wb") as out:
        shutil.copyfileobj(file.file, out)
    ev = process_evidence_file(db, c, dest, file.filename)
    analysis = rebuild_analysis(db, c)
    return {"evidence_id": ev.id, "sha256": ev.sha256, "analysis": analysis}


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


@app.get("/api/cases/{case_id}/graph")
def graph(case_id: int, db: Session = Depends(get_db)):
    _case_or_404(db, case_id)
    arts = db.query(Artifact).filter(Artifact.case_id == case_id).all()
    nodes = {}
    edges = []

    def node(nid, label, group):
        nodes[nid] = {"id": nid, "label": label[:48], "group": group}

    for a in arts:
        evn = f"e{a.id}"
        node(evn, a.event_type, a.source_type)
        if a.actor:
            an = "a:" + a.actor
            node(an, a.actor, "actor")
            edges.append({"from": an, "to": evn, "label": "performed"})
        if a.target:
            tn = "t:" + a.target
            node(tn, a.target, "target")
            edges.append({"from": evn, "to": tn, "label": "involves"})
    return {"nodes": list(nodes.values()), "edges": edges}


@app.post("/api/cases/{case_id}/reprocess")
def reprocess(case_id: int, db: Session = Depends(get_db)):
    """Re-run parsers on stored evidence (does not re-hash originals)."""
    c = _case_or_404(db, case_id)
    db.query(Artifact).filter(Artifact.case_id == case_id).delete()
    db.query(Finding).filter(Finding.case_id == case_id).delete()
    db.commit()
    db.add(
        CustodyEvent(
            case_id=c.id,
            action="reprocessed",
            actor="system",
            detail="Artifacts cleared and parsers re-run on stored working copies",
        )
    )
    db.commit()
    for ev in db.query(Evidence).filter(Evidence.case_id == case_id).all():
        path = Path(ev.stored_path)
        if not path.exists():
            continue
        # Re-parse without creating a new evidence row
        raw = []
        work_files = []
        if zipfile.is_zipfile(path):
            extract_dir = path.parent / f"extracted_{ev.id}"
            extract_dir.mkdir(exist_ok=True)
            with zipfile.ZipFile(path) as zf:
                zf.extractall(extract_dir)
            work_files = [p for p in extract_dir.rglob("*") if p.is_file()]
        else:
            work_files = [path]
        skipped = []
        for fp in work_files:
            reason = classify_skipped(fp)
            if reason:
                skipped.append(f"{fp.name} ({reason})")
                continue
            for rec in parse_file(fp, ev.source_type):
                rec["fingerprint"] = fingerprint(rec)
                raw.append(rec)
        if skipped:
            db.add(
                CustodyEvent(
                    case_id=c.id,
                    evidence_id=ev.id,
                    action="artifact_classification",
                    actor="system",
                    detail="Excluded from investigative timeline: " + "; ".join(skipped),
                )
            )
        for rec in build_timeline(raw):
            db.add(_artifact_row(c.id, ev.id, rec))
    db.commit()
    return rebuild_analysis(db, c)


@app.post("/api/cases/{case_id}/analyze")
def analyze(case_id: int, db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    return rebuild_analysis(db, c)


@app.post("/api/cases/{case_id}/chat")
def chat(case_id: int, body: ChatIn, db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    arts = db.query(Artifact).filter(Artifact.case_id == case_id).all()
    events = [_art_to_dict(a) for a in arts]
    rag = retrieve(case_id, body.question)
    analysis = analyze_timeline(events)
    text = answer_question(body.question, rag, events, analysis)
    return {"answer": text, "rag": rag, "category": analysis.get("category")}


@app.get("/api/cases/{case_id}/report")
def report(case_id: int, db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    arts = db.query(Artifact).filter(Artifact.case_id == case_id).order_by(Artifact.timestamp.asc()).all()
    findings = db.query(Finding).filter(Finding.case_id == case_id).all()
    analysis = {
        "category": findings[0].category if findings else "Unknown",
        "risk_score": findings[0].risk_score if findings else 0,
    }
    path = generate_report(c, c.evidence, arts, findings, analysis)
    return FileResponse(path, filename=path.name, media_type="application/pdf")
