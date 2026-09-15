"""
Test fixtures: every test gets a throw-away SQLite DB with a small set of
assets and IOCs, wired into the FastAPI app via dependency override.
"""
import os
import sys
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from database import Base, get_db  # noqa: E402
import models  # noqa: E402,F401


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = Session()

    now = datetime.utcnow()
    session.add_all([
        models.Asset(hostname="DC01.corp.local", ip_address="10.0.0.10", asset_type="Domain Controller",
                     criticality="CRITICAL", department="IT"),
        models.Asset(hostname="HR-LAPTOP-12", ip_address="192.168.1.45", asset_type="Laptop",
                     criticality="LOW", department="HR"),
        models.IOC(ioc_value="185.220.101.47", ioc_type="IP", reputation=95, confidence=92,
                   threat_type="Command & Control", first_seen=now - timedelta(days=30), last_seen=now),
        models.IOC(ioc_value="198.51.100.22", ioc_type="IP", reputation=15, confidence=30,
                   threat_type=None, first_seen=now - timedelta(days=30), last_seen=now),
    ])
    session.commit()
    yield session
    session.close()


@pytest.fixture()
def client(db_session):
    from main import app

    def _override():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
