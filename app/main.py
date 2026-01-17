from __future__ import annotations

import os, json, time, uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File as UpFile, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from sqlalchemy import select, func, text

from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response

from .db import get_db, ENGINE
from .models import User, Thread, Message, File, FileText, FileChunk, AuditLog
from .security import require_secret, new_salt, pbkdf2_hash, verify_password, mint_token, decode_token
from .extractors import extract_text
from .retrieval import keyword_retrieve

# Optional OpenAI
try:
    from openai import OpenAI
except Exception:
    OpenAI = None  # type: ignore

APP_VERSION = "2.0.1"
RAG_MODE = "keyword"

def new_id() -> str:
    return uuid.uuid4().hex

def now_ts() -> int:
    return int(time.time())

def cors_list() -> List[str]:
    raw = os.getenv("CORS_ORIGINS", "").strip()
    if not raw:
        return ["*"]
    return [x.strip() for x in raw.split(",") if x.strip()]

def tenant_mode() -> str:
    return os.getenv("TENANT_MODE", "multi")

def default_tenant() -> str:
    return os.getenv("DEFAULT_TENANT", "public")

def admin_api_key() -> str:
    return os.getenv("ADMIN_API_KEY", "").strip()

def admin_emails() -> List[str]:
    raw = os.getenv("ADMIN_EMAILS", "").strip()
    if not raw:
        return []
    return [x.strip().lower() for x in raw.split(",") if x.strip()]

def enable_streaming() -> bool:
    return os.getenv("ENABLE_STREAMING", "0").strip() in ("1", "true", "True")

def get_org(x_org_slug: Optional[str]) -> str:
    if tenant_mode() == "single":
        return default_tenant()
    return (x_org_slug or default_tenant()).strip() or default_tenant()

class RegisterIn(BaseModel):
    tenant: str = Field(default_tenant(), min_length=1)
    email: EmailStr
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=6, max_length=256)

class LoginIn(BaseModel):
    tenant: str = Field(default_tenant(), min_length=1)
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]

class ThreadIn(BaseModel):
    title: str = Field(default="Nova conversa", min_length=1, max_length=200)

class MessageOut(BaseModel):
    id: str
    role: str
    content: str
    created_at: int

class ChatIn(BaseModel):
    thread_id: Optional[str] = None
    message: str = Field(min_length=1)
    top_k: int = 6

class ChatOut(BaseModel):
    thread_id: str
    answer: str
    citations: List[Dict[str, Any]] = []

def audit(db: Session, org_slug: str, user_id: Optional[str], action: str, request_id: str, path: str, status_code: int, latency_ms: int, meta: Optional[Dict[str, Any]] = None):
    a = AuditLog(
        id=new_id(),
        org_slug=org_slug,
        user_id=user_id,
        action=action,
        meta=json.dumps(meta or {}, ensure_ascii=False),
        request_id=request_id,
        path=path,
        status_code=status_code,
        latency_ms=latency_ms,
        created_at=now_ts(),
    )
    db.add(a)
    db.commit()

def get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = decode_token(token)
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_admin(payload: Dict[str, Any]) -> None:
    if payload.get("role") == "admin":
        return
    raise HTTPException(status_code=403, detail="Admin required")

def require_admin_key(x_admin_key: Optional[str]) -> None:
    k = admin_api_key()
    if not k:
        raise HTTPException(status_code=500, detail="ADMIN_API_KEY not configured")
    if not x_admin_key or x_admin_key != k:
        raise HTTPException(status_code=401, detail="Invalid admin key")

def db_ok() -> bool:
    if ENGINE is None:
        return False
    try:
        with ENGINE.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

app = FastAPI(title="Orkio API", version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_list(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def request_id_mw(request: Request, call_next):
    rid = request.headers.get("x-request-id") or new_id()
    start = time.time()
    try:
        resp = await call_next(request)
    finally:
        pass
    resp.headers["x-request-id"] = rid
    resp.headers["x-orkio-version"] = APP_VERSION
    return resp

@app.on_event("startup")
def _startup():
    require_secret()
    if not admin_api_key():
        raise RuntimeError("ADMIN_API_KEY is not configured (refuse to start)")

@app.get("/api/health")
def health():
    return {"status": "ok", "db": "ok" if db_ok() else "down", "version": APP_VERSION, "rag": RAG_MODE}

@app.get("/api/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/api/auth/register", response_model=TokenOut)
def register(inp: RegisterIn, db: Session = Depends(get_db)):
    org = (inp.tenant or default_tenant()).strip()
    email = inp.email.lower().strip()
    # auto-admin
    role = "admin" if email in admin_emails() else "user"

    existing = db.execute(select(User).where(User.org_slug == org, User.email == email)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    salt = new_salt()
    pw_hash = pbkdf2_hash(inp.password, salt)
    u = User(id=new_id(), org_slug=org, email=email, name=inp.name.strip(), role=role, salt=salt, pw_hash=pw_hash, created_at=now_ts())
    db.add(u)
    db.commit()

    token = mint_token({"sub": u.id, "org": org, "email": u.email, "name": u.name, "role": u.role})
    return {"access_token": token, "token_type": "bearer", "user": {"id": u.id, "email": u.email, "name": u.name, "role": u.role}}

@app.post("/api/auth/login", response_model=TokenOut)
def login(inp: LoginIn, db: Session = Depends(get_db)):
    org = (inp.tenant or default_tenant()).strip()
    email = inp.email.lower().strip()
    u = db.execute(select(User).where(User.org_slug == org, User.email == email)).scalar_one_or_none()
    if not u or not verify_password(inp.password, u.salt, u.pw_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = mint_token({"sub": u.id, "org": org, "email": u.email, "name": u.name, "role": u.role})
    return {"access_token": token, "token_type": "bearer", "user": {"id": u.id, "email": u.email, "name": u.name, "role": u.role}}

@app.get("/api/threads")
def list_threads(x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    rows = db.execute(select(Thread).where(Thread.org_slug == org).order_by(Thread.created_at.desc())).scalars().all()
    return [{"id": t.id, "title": t.title, "created_at": t.created_at} for t in rows]

@app.post("/api/threads")
def create_thread(inp: ThreadIn, x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    t = Thread(id=new_id(), org_slug=org, title=inp.title, created_at=now_ts())
    db.add(t)
    db.commit()
    return {"id": t.id, "title": t.title, "created_at": t.created_at}

@app.get("/api/messages")
def list_messages(thread_id: str, x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    rows = db.execute(select(Message).where(Message.org_slug == org, Message.thread_id == thread_id).order_by(Message.created_at.asc())).scalars().all()
    return [{"id": m.id, "role": m.role, "content": m.content, "created_at": m.created_at} for m in rows]

def _openai_answer(message: str, context_chunks: List[Dict[str, Any]]) -> Optional[str]:
    key = os.getenv("OPENAI_API_KEY", "").strip()
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()
    if not key or OpenAI is None:
        return None
    client = OpenAI(api_key=key)
    ctx = ""
    for c in context_chunks[:6]:
        fn = c.get("filename") or c.get("file_id")
        ctx += f"\n\n[Arquivo: {fn}]\n{c.get('content','')}"
    system = "Você é o Orkio. Responda de forma objetiva. Use o contexto de documentos quando disponível."
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": f"Contexto:\n{ctx}\n\nPergunta: {message}"},
    ]
    try:
        r = client.chat.completions.create(model=model, messages=messages)
        return (r.choices[0].message.content or "").strip()
    except Exception:
        return None

@app.post("/api/chat", response_model=ChatOut)
def chat(inp: ChatIn, x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)

    # Ensure thread
    tid = inp.thread_id
    if not tid:
        t = Thread(id=new_id(), org_slug=org, title="Nova conversa", created_at=now_ts())
        db.add(t)
        db.commit()
        tid = t.id

    # Save user message
    m_user = Message(id=new_id(), org_slug=org, thread_id=tid, role="user", content=inp.message, created_at=now_ts())
    db.add(m_user)
    db.commit()

    # Retrieve context (keyword fallback)
    citations = keyword_retrieve(db, org_slug=org, query=inp.message, top_k=inp.top_k)

    # Answer
    answer = _openai_answer(inp.message, citations)
    if not answer:
        if citations:
            snippet = (citations[0].get("content") or "")[:600]
            fn = citations[0].get("filename") or citations[0].get("file_id")
            answer = f"Encontrei esta informação no documento ({fn}):\n\n{snippet}"
        else:
            answer = "Ainda não encontrei informação nos documentos enviados para responder com precisão. Você pode anexar um documento relacionado?"
    # Save assistant message
    m_ass = Message(id=new_id(), org_slug=org, thread_id=tid, role="assistant", content=answer, created_at=now_ts())
    db.add(m_ass)
    db.commit()

    return {"thread_id": tid, "answer": answer, "citations": citations}

@app.post("/api/files/upload")
async def upload(file: UploadFile = UpFile(...), x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    filename = file.filename or "upload"
    raw = await file.read()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Arquivo muito grande (max 10MB)")

    f = File(id=new_id(), org_slug=org, thread_id=None, filename=filename, mime_type=file.content_type, size_bytes=len(raw), content=raw, extraction_failed=False, created_at=now_ts())
    db.add(f)
    db.commit()

    extracted_chars = 0
    text_content = ""
    try:
        text_content, extracted_chars = extract_text(filename, raw)
        ft = FileText(id=new_id(), org_slug=org, file_id=f.id, text=text_content, extracted_chars=extracted_chars, created_at=now_ts())
        db.add(ft)

        # Chunking (deterministic)
        chunk_chars = int(os.getenv("RAG_CHUNK_CHARS", "1200"))
        overlap = int(os.getenv("RAG_CHUNK_OVERLAP", "200"))
        text_len = len(text_content)
        idx = 0
        pos = 0
        while pos < text_len:
            end = min(text_len, pos + chunk_chars)
            chunk = text_content[pos:end].strip()
            if chunk:
                db.add(FileChunk(id=new_id(), org_slug=org, file_id=f.id, idx=idx, content=chunk, created_at=now_ts()))
                idx += 1
            if end >= text_len:
                break
            pos = max(0, end - overlap)

        db.commit()
    except Exception:
        f.extraction_failed = True
        db.add(f)
        db.commit()

    return {"file_id": f.id, "filename": f.filename, "status": "stored", "extracted_chars": extracted_chars}

@app.get("/api/files")
def list_files(x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    rows = db.execute(select(File).where(File.org_slug == org).order_by(File.created_at.desc())).scalars().all()
    return [{"id": f.id, "filename": f.filename, "size_bytes": f.size_bytes, "extraction_failed": f.extraction_failed, "created_at": f.created_at} for f in rows]

# --- Admin ---
@app.get("/api/admin/overview")
def admin_overview(x_admin_key: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    require_admin_key(x_admin_key)
    return {
        "tenants": db.execute(select(func.count(func.distinct(User.org_slug)))).scalar_one(),
        "users": db.execute(select(func.count(User.id))).scalar_one(),
        "threads": db.execute(select(func.count(Thread.id))).scalar_one(),
        "messages": db.execute(select(func.count(Message.id))).scalar_one(),
        "files": db.execute(select(func.count(File.id))).scalar_one(),
    }

@app.get("/api/admin/users")
def admin_users(x_admin_key: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    require_admin_key(x_admin_key)
    rows = db.execute(select(User).order_by(User.created_at.desc()).limit(200)).scalars().all()
    return [{"id": u.id, "org_slug": u.org_slug, "email": u.email, "name": u.name, "role": u.role, "created_at": u.created_at} for u in rows]

@app.get("/api/admin/files")
def admin_files(x_admin_key: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    require_admin_key(x_admin_key)
    rows = db.execute(select(File).order_by(File.created_at.desc()).limit(200)).scalars().all()
    return [{"id": f.id, "org_slug": f.org_slug, "filename": f.filename, "size_bytes": f.size_bytes, "extraction_failed": f.extraction_failed, "created_at": f.created_at} for f in rows]

@app.get("/api/admin/audit")
def admin_audit(x_admin_key: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    require_admin_key(x_admin_key)
    rows = db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(200)).scalars().all()
    out = []
    for a in rows:
        try:
            meta = json.loads(a.meta) if a.meta else {}
        except Exception:
            meta = {}
        out.append(
            {
                "id": a.id,
                "org_slug": a.org_slug,
                "user_id": a.user_id,
                "action": a.action,
                "meta": meta,
                "request_id": a.request_id,
                "path": a.path,
                "status_code": a.status_code,
                "latency_ms": a.latency_ms,
                "created_at": a.created_at,
            }
        )
    return out

