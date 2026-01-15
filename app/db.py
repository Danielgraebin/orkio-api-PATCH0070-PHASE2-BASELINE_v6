from __future__ import annotations
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

def _db_url() -> str:
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        return ""
    # Railway sometimes provides postgres:// -> SQLAlchemy prefers postgresql://
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return url

class Base(DeclarativeBase):
    pass

def make_engine():
    url = _db_url()
    if not url:
        return None
    pool_size = int(os.getenv("DB_POOL_SIZE", "5"))
    max_overflow = int(os.getenv("DB_MAX_OVERFLOW", "10"))
    pool_timeout = int(os.getenv("DB_POOL_TIMEOUT", "30"))
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
    )

ENGINE = make_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=ENGINE) if ENGINE else None

def get_db():
    if SessionLocal is None:
        raise RuntimeError("DATABASE_URL not configured")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
