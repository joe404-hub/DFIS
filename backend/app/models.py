from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db import Base


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_number: Mapped[str] = mapped_column(String(64), unique=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    investigator: Mapped[str] = mapped_column(String(128), default="Investigator")
    status: Mapped[str] = mapped_column(String(32), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    evidence = relationship("Evidence", back_populates="case", cascade="all, delete")
    artifacts = relationship("Artifact", back_populates="case", cascade="all, delete")
    findings = relationship("Finding", back_populates="case", cascade="all, delete")
    recommendations = relationship("Recommendation", back_populates="case", cascade="all, delete")


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"))
    filename: Mapped[str] = mapped_column(String(512))
    stored_path: Mapped[str] = mapped_column(String(1024))
    sha256: Mapped[str] = mapped_column(String(64))
    source_type: Mapped[str] = mapped_column(String(64), default="unknown")
    detected_type: Mapped[str] = mapped_column(String(64), default="")
    magic_signature: Mapped[str] = mapped_column(String(128), default="")
    mime_type: Mapped[str] = mapped_column(String(128), default="")
    artifact_count: Mapped[int] = mapped_column(Integer, default=0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[str] = mapped_column(Text, default="")
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    integrity_ok: Mapped[bool] = mapped_column(Boolean, default=True)
    case = relationship("Case", back_populates="evidence")
    artifacts = relationship("Artifact", back_populates="evidence")


class Artifact(Base):
    __tablename__ = "artifacts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"))
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"))
    
    # Common Forensic Event Schema fields
    event_id: Mapped[str] = mapped_column(String(64), default="")
    timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    timestamp_utc: Mapped[str] = mapped_column(String(64), default="")
    source: Mapped[str] = mapped_column(String(255), default="")
    source_type: Mapped[str] = mapped_column(String(64))
    artifact_type: Mapped[str] = mapped_column(String(128), default="")
    event_type: Mapped[str] = mapped_column(String(128))
    
    # User / Actor / Host / Process / Action / Object / Path
    user: Mapped[str] = mapped_column(String(255), default="")
    actor: Mapped[str] = mapped_column(String(255), default="")
    host: Mapped[str] = mapped_column(String(128), default="")
    process: Mapped[str] = mapped_column(String(255), default="")
    pid: Mapped[str] = mapped_column(String(32), default="")
    action: Mapped[str] = mapped_column(String(128), default="")
    object: Mapped[str] = mapped_column(String(512), default="")
    target: Mapped[str] = mapped_column(String(512), default="")
    path: Mapped[str] = mapped_column(String(512), default="")
    source_path: Mapped[str] = mapped_column(String(512), default="")
    destination_path: Mapped[str] = mapped_column(String(512), default="")
    
    # Network fields
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    source_port: Mapped[str] = mapped_column(String(16), default="")
    destination_ip: Mapped[str] = mapped_column(String(64), default="")
    destination_port: Mapped[str] = mapped_column(String(16), default="")
    
    # Description & Forensic metadata
    description: Mapped[str] = mapped_column(Text)
    evidence_hash: Mapped[str] = mapped_column(String(64), default="")
    fingerprint: Mapped[str] = mapped_column(String(64), default="")
    correlation_id: Mapped[str] = mapped_column(String(64), default="")
    raw_data: Mapped[str] = mapped_column(Text, default="")
    parser_name: Mapped[str] = mapped_column(String(64), default="")
    source_file: Mapped[str] = mapped_column(String(255), default="")
    time_kind: Mapped[str] = mapped_column(String(32), default="event")
    observation_time: Mapped[str] = mapped_column(String(64), default="")
    
    case = relationship("Case", back_populates="artifacts")
    evidence = relationship("Evidence", back_populates="artifacts")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"))
    category: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    confidence: Mapped[float] = mapped_column(Float, default=0)
    attack_stage: Mapped[str] = mapped_column(String(128), default="")
    mitre_ids: Mapped[str] = mapped_column(String(255), default="")
    artifact_ids: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    case = relationship("Case", back_populates="findings")


class Recommendation(Base):
    __tablename__ = "recommendations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"))
    priority: Mapped[int] = mapped_column(Integer, default=1)
    action: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(Text, default="")
    evidence_ids: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(64), default="pending_examiner_verification")
    layer: Mapped[str] = mapped_column(String(32), default="verify")  # observed | inferred | verify
    case = relationship("Case", back_populates="recommendations")


class CustodyEvent(Base):
    __tablename__ = "custody"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"))
    evidence_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(128))
    actor: Mapped[str] = mapped_column(String(128))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
