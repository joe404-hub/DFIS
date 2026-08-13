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


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"))
    filename: Mapped[str] = mapped_column(String(512))
    stored_path: Mapped[str] = mapped_column(String(1024))
    sha256: Mapped[str] = mapped_column(String(64))
    source_type: Mapped[str] = mapped_column(String(64), default="unknown")
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
    source_type: Mapped[str] = mapped_column(String(64))
    event_type: Mapped[str] = mapped_column(String(128))
    timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    description: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(255), default="")
    target: Mapped[str] = mapped_column(String(512), default="")
    raw_data: Mapped[str] = mapped_column(Text, default="")
    fingerprint: Mapped[str] = mapped_column(String(64), default="")
    parser_name: Mapped[str] = mapped_column(String(64), default="")
    source_file: Mapped[str] = mapped_column(String(255), default="")
    correlation_id: Mapped[str] = mapped_column(String(64), default="")
    process: Mapped[str] = mapped_column(String(255), default="")
    pid: Mapped[str] = mapped_column(String(32), default="")
    source_path: Mapped[str] = mapped_column(String(512), default="")
    destination_path: Mapped[str] = mapped_column(String(512), default="")
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    source_port: Mapped[str] = mapped_column(String(16), default="")
    destination_ip: Mapped[str] = mapped_column(String(64), default="")
    destination_port: Mapped[str] = mapped_column(String(16), default="")
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


class CustodyEvent(Base):
    __tablename__ = "custody"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"))
    evidence_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(128))
    actor: Mapped[str] = mapped_column(String(128))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
