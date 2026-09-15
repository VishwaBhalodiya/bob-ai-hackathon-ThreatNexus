import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Anchor the SQLite file to the backend/ directory so the API and seed.py
# always hit the same database regardless of the current working directory.
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = "sqlite:///" + os.path.join(_BACKEND_DIR, "threatenexus.db").replace("\\", "/")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_schema():
    """
    Create missing tables, then add any columns that exist on the models but
    not yet in the SQLite file (SQLite has no automatic migrations).  Safe to
    run on every start-up.
    """
    Base.metadata.create_all(bind=engine)
    insp = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in existing:
                    continue
                coltype = col.type.compile(dialect=engine.dialect)
                default = ""
                if col.default is not None and getattr(col.default, "arg", None) is not None                         and not callable(col.default.arg):
                    arg = col.default.arg
                    default = f" DEFAULT {arg!r}" if isinstance(arg, str) else f" DEFAULT {arg}"
                conn.execute(text(
                    f'ALTER TABLE {table.name} ADD COLUMN "{col.name}" {coltype}{default}'
                ))
