from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
EVIDENCE_DIR = DATA_DIR / "evidence"
EVIDENCE_DIR.mkdir(exist_ok=True)
REPORT_DIR = DATA_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)
CHROMA_DIR = str(DATA_DIR / "chroma")

DATABASE_URL = f"sqlite:///{DATA_DIR / 'dfis.db'}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def migrate():
    """Add columns introduced after initial SQLite schema creation."""
    artifact_cols = {
        "event_id": "VARCHAR(64) DEFAULT ''",
        "timestamp_utc": "VARCHAR(64) DEFAULT ''",
        "source": "VARCHAR(255) DEFAULT ''",
        "artifact_type": "VARCHAR(128) DEFAULT ''",
        "user": "VARCHAR(255) DEFAULT ''",
        "host": "VARCHAR(128) DEFAULT ''",
        "action": "VARCHAR(128) DEFAULT ''",
        "object": "VARCHAR(512) DEFAULT ''",
        "path": "VARCHAR(512) DEFAULT ''",
        "evidence_hash": "VARCHAR(64) DEFAULT ''",
        "parser_name": "VARCHAR(64) DEFAULT ''",
        "source_file": "VARCHAR(255) DEFAULT ''",
        "correlation_id": "VARCHAR(64) DEFAULT ''",
        "process": "VARCHAR(255) DEFAULT ''",
        "pid": "VARCHAR(32) DEFAULT ''",
        "source_path": "VARCHAR(512) DEFAULT ''",
        "destination_path": "VARCHAR(512) DEFAULT ''",
        "source_ip": "VARCHAR(64) DEFAULT ''",
        "source_port": "VARCHAR(16) DEFAULT ''",
        "destination_ip": "VARCHAR(64) DEFAULT ''",
        "destination_port": "VARCHAR(16) DEFAULT ''",
        "time_kind": "VARCHAR(32) DEFAULT 'event'",
        "observation_time": "VARCHAR(64) DEFAULT ''",
    }
    evidence_cols = {
        "detected_type": "VARCHAR(64) DEFAULT ''",
        "magic_signature": "VARCHAR(128) DEFAULT ''",
        "mime_type": "VARCHAR(128) DEFAULT ''",
        "artifact_count": "INTEGER DEFAULT 0",
    }
    rec_cols = {
        "question": "VARCHAR(255) DEFAULT ''",
    }
    with engine.begin() as conn:
        existing_art = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(artifacts)")}
        for name, ddl in artifact_cols.items():
            if name not in existing_art:
                conn.exec_driver_sql(f"ALTER TABLE artifacts ADD COLUMN {name} {ddl}")
                
        existing_ev = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(evidence)")}
        for name, ddl in evidence_cols.items():
            if name not in existing_ev:
                conn.exec_driver_sql(f"ALTER TABLE evidence ADD COLUMN {name} {ddl}")

        existing_rec = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(recommendations)")}
        for name, ddl in rec_cols.items():
            if name not in existing_rec:
                conn.exec_driver_sql(f"ALTER TABLE recommendations ADD COLUMN {name} {ddl}")
