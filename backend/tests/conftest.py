"""Pytest Configuration for Isolated Testing Database."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, migrate
import app.db as app_db

TEST_ENGINE = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
TestSessionLocal = sessionmaker(bind=TEST_ENGINE, autoflush=False, autocommit=False)


@pytest.fixture(scope="session", autouse=True)
def setup_test_schema():
    """Create test tables in memory."""
    Base.metadata.create_all(bind=TEST_ENGINE)
    app_db.engine = TEST_ENGINE
    app_db.SessionLocal = TestSessionLocal
    yield
    Base.metadata.drop_all(bind=TEST_ENGINE)


@pytest.fixture
def db_session():
    """Provide an isolated database session per test."""
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()
