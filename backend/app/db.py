from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

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
    """Add columns introduced after the first SQLite schema."""
    cols = {
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
    }
    with engine.begin() as conn:
        existing = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(artifacts)")}
        for name, ddl in cols.items():
            if name not in existing:
                conn.exec_driver_sql(f"ALTER TABLE artifacts ADD COLUMN {name} {ddl}")
