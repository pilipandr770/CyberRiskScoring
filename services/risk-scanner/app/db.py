import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import DATABASE_URL

if DATABASE_URL.startswith("sqlite"):
    db_path = "/" + DATABASE_URL.split("sqlite:///")[-1].lstrip("/")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from app import models  # noqa: F401  (ensure models are registered)
    Base.metadata.create_all(bind=engine)
    _add_missing_columns()


def _add_missing_columns():
    """Minimal migration for a dev-stage SQLite DB with no migration
    framework yet — adds any model column the existing table is missing,
    so test data from earlier scans survives schema changes instead of
    requiring a DB wipe every time a field gets added."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    for table in Base.metadata.tables.values():
        if table.name not in inspector.get_table_names():
            continue
        existing_cols = {c["name"] for c in inspector.get_columns(table.name)}
        for col in table.columns:
            if col.name not in existing_cols:
                col_type = col.type.compile(engine.dialect)
                with engine.begin() as conn:
                    conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN "{col.name}" {col_type}'))
