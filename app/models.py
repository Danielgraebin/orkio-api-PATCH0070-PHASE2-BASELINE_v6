from __future__ import annotations
from sqlalchemy import Column, String, Text, BigInteger, Integer, LargeBinary, Boolean
from .db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    email = Column(String, index=True, nullable=False)
    name = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")  # user|admin
    salt = Column(String, nullable=False)
    pw_hash = Column(String, nullable=False)
    created_at = Column(BigInteger, nullable=False)

class Thread(Base):
    __tablename__ = "threads"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    title = Column(String, nullable=False)
    created_at = Column(BigInteger, nullable=False)

class Message(Base):
    __tablename__ = "messages"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    thread_id = Column(String, index=True, nullable=False)
    role = Column(String, nullable=False)  # user|assistant|system
    content = Column(Text, nullable=False)
    created_at = Column(BigInteger, nullable=False)

class File(Base):
    __tablename__ = "files"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    thread_id = Column(String, index=True, nullable=True)
    filename = Column(String, nullable=False)
    mime_type = Column(String, nullable=True)
    size_bytes = Column(Integer, nullable=False, default=0)
    content = Column(LargeBinary, nullable=True)  # optional (MVP)
    extraction_failed = Column(Boolean, nullable=False, default=False)
    created_at = Column(BigInteger, nullable=False)

class FileText(Base):
    __tablename__ = "file_texts"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    file_id = Column(String, index=True, nullable=False)
    text = Column(Text, nullable=False)
    extracted_chars = Column(Integer, nullable=False, default=0)
    created_at = Column(BigInteger, nullable=False)

class FileChunk(Base):
    __tablename__ = "file_chunks"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    file_id = Column(String, index=True, nullable=False)
    idx = Column(Integer, nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(BigInteger, nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    user_id = Column(String, nullable=True)
    action = Column(String, nullable=False)
    meta = Column(Text, nullable=True)
    request_id = Column(String, nullable=True)
    path = Column(String, nullable=True)
    status_code = Column(Integer, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    created_at = Column(BigInteger, nullable=False)
