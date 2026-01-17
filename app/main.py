import os
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.db import ENGINE, SessionLocal
from app.models import AuditLog, FileBlob, FileText, Message, Tenant, Thread, User
from app.retrieval import keyword_retrieve
from app.security import decode_token, hash_password, mint_token, verify_password


APP_ENV = os.getenv("APP_ENV", "development")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRES_IN = int(os.getenv("JWT_EXPIRES_IN", "3600"))

TENANT_MODE = os.getenv("TENANT_MODE", "multi")
DEFAULT_TENANT = os.getenv("DEFAULT_TENANT", "public")

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
ADMIN_EMAILS = os.getenv("ADMIN_EMAILS", "")

ENABLE_STREAMING = os.getenv("ENABLE_STREAMING", "0") == "1"

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


def admin_emails() -> set:
    return {e.strip().lower() for e in (ADMIN_EMAILS or "").split(",") if e.strip()}


app = FastAPI(title="Orkio API Phase2", version="2.0.0")


def _parse_origins(value: str) -> List[str]:
    value = (value or "").strip()
    if not value:
        return ["*"]
    if value == "*":
        return ["*"]
    # allow comma-separated list
    return [v.strip() for v in value.split(",") if v.strip()]


origins = _parse_origins(CORS_ORIGINS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if "*" not in origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def now_ms() -> int:
    return int(time.time() * 1000)


def request_id() -> str:
    return str(uuid.uuid4())


def get_org(x_org_slug: Optional[str]) -> str:
    if TENANT_MODE == "single":
        return DEFAULT_TENANT
    return (x_org_slug or DEFAULT_TENANT).strip() or DEFAULT_TENANT


def audit(
    db: Session,
    org: str,
    actor_user_id: Optional[str],
    action: str,
    path: str,
    status: int,
):
    try:
        db.add(
            AuditLog(
                org=org,
                actor_user_id=actor_user_id,
                action=action,
                path=path,
                status=status,
                created_at=now_ms(),
            )
        )
        db.commit()
    except Exception:
        db.rollback()


def db_ok(db: Session) -> bool:
    try:
        db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def get_current_user(authorization: Optional[str]) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_token(token, secret=JWT_SECRET, algorithm=JWT_ALGORITHM)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload


def require_admin_key(x_admin_key: Optional[str]):
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=500, detail="ADMIN_API_KEY not set")
    if not x_admin_key or x_admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")


def require_admin_access(
    authorization: Optional[str] = Header(default=None),
    x_admin_key: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Allow admin by ADMIN_API_KEY (x-admin-key) OR JWT role=admin."""
    # 1) service/admin key
    if x_admin_key:
        try:
            import secrets as _secrets

            if ADMIN_API_KEY and _secrets.compare_digest(x_admin_key, ADMIN_API_KEY):
                return {"auth": "admin_key"}
        except Exception:
            pass

    # 2) JWT token with admin role (recommended for browser UI)
    payload = get_current_user(authorization)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return payload


@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    ok = db_ok(db)
    return {
        "status": "ok",
        "db": "ok" if ok else "down",
        "version": "2.0.0",
        "rag": "keyword",
    }


@app.post("/api/auth/register")
def register(
    tenant: str,
    email: str,
    name: str,
    password: str,
    x_org_slug: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    org = get_org(tenant or x_org_slug)

    # Ensure tenant exists
    t = db.query(Tenant).filter(Tenant.slug == org).first()
    if not t:
        t = Tenant(slug=org, created_at=now_ms())
        db.add(t)
        db.commit()

    email_norm = email.strip().lower()
    existing = db.query(User).filter(User.org == org, User.email == email_norm).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    role = "admin" if email_norm in admin_emails() else "user"
    u = User(
        org=org,
        email=email_norm,
        name=name.strip(),
        role=role,
        password_hash=hash_password(password),
        created_at=now_ms(),
    )
    db.add(u)
    db.commit()

    token = mint_token(
        {
            "org": org,
            "user_id": u.id,
            "email": u.email,
            "name": u.name,
            "role": u.role,
        },
        secret=JWT_SECRET,
        algorithm=JWT_ALGORITHM,
        expires_in=JWT_EXPIRES_IN,
    )

    audit(db, org, u.id, "auth.register", "/api/auth/register", 200)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": u.id, "email": u.email, "name": u.name, "role": u.role},
    }


@app.post("/api/auth/login")
def login(
    tenant: str,
    email: str,
    password: str,
    x_org_slug: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    org = get_org(tenant or x_org_slug)
    email_norm = email.strip().lower()

    u = db.query(User).filter(User.org == org, User.email == email_norm).first()
    if not u or not verify_password(password, u.password_hash):
        audit(db, org, None, "auth.login_failed", "/api/auth/login", 401)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = mint_token(
        {
            "org": org,
            "user_id": u.id,
            "email": u.email,
            "name": u.name,
            "role": u.role,
        },
        secret=JWT_SECRET,
        algorithm=JWT_ALGORITHM,
        expires_in=JWT_EXPIRES_IN,
    )

    audit(db, org, u.id, "auth.login", "/api/auth/login", 200)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": u.id, "email": u.email, "name": u.name, "role": u.role},
    }


@app.get("/api/threads")
def list_threads(
    authorization: Optional[str] = Header(default=None),
    x_org_slug: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    payload = get_current_user(authorization)
    org = get_org(x_org_slug or payload.get("org"))

    items = (
        db.query(Thread)
        .filter(Thread.org == org, Thread.user_id == payload["user_id"])
        .order_by(Thread.created_at.desc())
        .all()
    )
    return [{"id": t.id, "title": t.title, "created_at": t.created_at} for t in items]


@app.post("/api/threads")
def create_thread(
    title: str = Form(...),
    authorization: Optional[str] = Header(default=None),
    x_org_slug: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    payload = get_current_user(authorization)
    org = get_org(x_org_slug or payload.get("org"))

    th = Thread(org=org, user_id=payload["user_id"], title=title, created_at=now_ms())
    db.add(th)
    db.commit()

    audit(db, org, payload["user_id"], "threads.create", "/api/threads", 200)
    return {"id": th.id, "title": th.title, "created_at": th.created_at}


@app.get("/api/messages")
def list_messages(
    thread_id: str,
    authorization: Optional[str] = Header(default=None),
    x_org_slug: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    payload = get_current_user(authorization)
    org = get_org(x_org_slug or payload.get("org"))

    th = db.query(Thread).filter(Thread.id == thread_id, Thread.org == org).first()
    if not th or th.user_id != payload["user_id"]:
        raise HTTPException(status_code=404, detail="Thread not found")

    items = (
        db.query(Message)
        .filter(Message.org == org, Message.thread_id == thread_id)
        .order_by(Message.created_at.asc())
        .all()
    )
    return [
        {"id": m.id, "role": m.role, "content": m.content, "created_at": m.created_at}
        for m in items
    ]


@app.post("/api/messages")
def create_message(
    thread_id: str = Form(...),
    content: str = Form(...),
    authorization: Optional[str] = Header(default=None),
    x_org_slug: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    payload = get_current_user(authorization)
    org = get_org(x_org_slug or payload.get("org"))

    th = db.query(Thread).filter(Thread.id == thread_id, Thread.org == org).first()
    if not th or th.user_id != payload["user_id"]:
        raise HTTPException(status_code=404, detail="Thread not found")

    msg = Message(
        org=org,
        thread_id=thread_id,
        role="user",
        content=content,
        created_at=now_ms(),
    )
    db.add(msg)
    db.commit()

    audit(db, org, payload["user_id"], "messages.create", "/api/messages", 200)
    return {"id": msg.id, "thread_id": msg.thread_id, "created_at": msg.created_at}


def _openai_answer(prompt: str) -> str:
    # Optional: if OPENAI_API_KEY is not set, do a deterministic echo-style answer
    if not OPENAI_API_KEY:
        return f"[stub] {prompt}"

    # Best-effort OpenAI call (kept extremely simple; if it fails, we fallback to stub)
    try:
        from openai import OpenAI

        client = OpenAI(api_key=OPENAI_API_KEY)
        resp = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are Orkio. Answer using the provided context when relevant. If the context is empty, answer normally.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return resp.choices[0].message.content or ""
    except Exception:
        return f"[stub] {prompt}"


@app.post("/api/chat")
def chat(
    thread_id: str,
    message: str,
    top_k: int = 6,
    authorization: Optional[str] = Header(default=None),
    x_org_slug: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    payload = get_current_user(authorization)
    org = get_org(x_org_slug or payload.get("org"))

    th = db.query(Thread).filter(Thread.id == thread_id, Thread.org == org).first()
    if not th or th.user_id != payload["user_id"]:
        raise HTTPException(status_code=404, detail="Thread not found")

    # Save user message
    user_msg = Message(
        org=org, thread_id=thread_id, role="user", content=message, created_at=now_ms()
    )
    db.add(user_msg)
    db.commit()

    # Retrieve context (keyword fallback)
    citations = keyword_retrieve(db, org=org, query=message, top_k=top_k)

    ctx = "\n\n".join([f"[{c['source']}] {c['text']}" for c in citations])
    prompt = (
        f"Tenant: {org}\n"
        f"Thread: {thread_id}\n\n"
        f"Context:\n{ctx}\n\n"
        f"User:\n{message}\n\n"
        f"Answer:"
    )
    answer = _openai_answer(prompt).strip() or "..."

    # Save assistant message
    asst_msg = Message(
        org=org,
        thread_id=thread_id,
        role="assistant",
        content=answer,
        created_at=now_ms(),
    )
    db.add(asst_msg)
    db.commit()

    audit(db, org, payload["user_id"], "chat", "/api/chat", 200)
    return {"answer": answer, "citations": citations, "thread_id": thread_id}


def _extract_text(filename: str, content_type: str, data: bytes) -> Tuple[str, bool]:
    name = (filename or "").lower()
    ctype = (content_type or "").lower()

    try:
        if name.endswith(".txt") or name.endswith(".md") or "text/" in ctype:
            return data.decode("utf-8", errors="ignore"), True

        if name.endswith(".docx"):
            from docx import Document
            import io

            doc = Document(io.BytesIO(data))
            text_out = "\n".join([p.text for p in doc.paragraphs])
            return text_out, True

        if name.endswith(".pdf"):
            from pypdf import PdfReader
            import io

            reader = PdfReader(io.BytesIO(data))
            parts = []
            for page in reader.pages:
                parts.append(page.extract_text() or "")
            return "\n".join(parts), True

        # unsupported
        return "", False
    except Exception:
        return "", False


@app.post("/api/files/upload")
def upload_file(
    file: UploadFile = File(...),
    thread_id: Optional[str] = Form(default=None),
    authorization: Optional[str] = Header(default=None),
    x_org_slug: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    payload = get_current_user(authorization)
    org = get_org(x_org_slug or payload.get("org"))

    data = file.file.read()
    fb = FileBlob(
        org=org,
        user_id=payload["user_id"],
        thread_id=thread_id,
        filename=file.filename,
        content_type=file.content_type,
        size_bytes=len(data),
        data=data,
        created_at=now_ms(),
    )
    db.add(fb)
    db.commit()

    text_out, extracted = _extract_text(file.filename, file.content_type, data)
    ft = FileText(
        org=org,
        file_id=fb.id,
        thread_id=thread_id,
        text=text_out or "",
        extracted_chars=len(text_out or ""),
        extraction_failed=not extracted,
        created_at=now_ms(),
    )
    db.add(ft)
    db.commit()

    audit(db, org, payload["user_id"], "files.upload", "/api/files/upload", 200)
    return {
        "file_id": fb.id,
        "filename": fb.filename,
        "status": "stored",
        "extracted_chars": ft.extracted_chars,
    }


@app.get("/api/admin/overview")
def admin_overview(
    admin: Dict[str, Any] = Depends(require_admin_access),
    db: Session = Depends(get_db),
):
    # aggregated counts (simple)
    tenants = db.query(func.count(Tenant.id)).scalar() or 0
    users = db.query(func.count(User.id)).scalar() or 0
    threads = db.query(func.count(Thread.id)).scalar() or 0
    messages = db.query(func.count(Message.id)).scalar() or 0
    files = db.query(func.count(FileBlob.id)).scalar() or 0

    return {
        "tenants": tenants,
        "users": users,
        "threads": threads,
        "messages": messages,
        "files": files,
    }


@app.get("/api/admin/users")
def admin_users(
    admin: Dict[str, Any] = Depends(require_admin_access),
    db: Session = Depends(get_db),
):
    items = db.query(User).order_by(User.created_at.desc()).limit(200).all()
    return [
        {
            "id": u.id,
            "org": u.org,
            "email": u.email,
            "name": u.name,
            "role": u.role,
            "created_at": u.created_at,
        }
        for u in items
    ]


@app.get("/api/admin/files")
def admin_files(
    admin: Dict[str, Any] = Depends(require_admin_access),
    db: Session = Depends(get_db),
):
    items = db.query(FileBlob).order_by(FileBlob.created_at.desc()).limit(200).all()
    out = []
    for f in items:
        ft = db.query(FileText).filter(FileText.file_id == f.id).first()
        out.append(
            {
                "id": f.id,
                "org": f.org,
                "filename": f.filename,
                "content_type": f.content_type,
                "size_bytes": f.size_bytes,
                "created_at": f.created_at,
                "extracted_chars": (ft.extracted_chars if ft else 0),
                "extraction_failed": (ft.extraction_failed if ft else True),
            }
        )
    return out


@app.get("/api/admin/audit")
def admin_audit(
    limit: int = 30,
    admin: Dict[str, Any] = Depends(require_admin_access),
    db: Session = Depends(get_db),
):
    lim = max(1, min(200, int(limit)))
    items = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(lim).all()
    return [
        {
            "when": a.created_at,
            "org": a.org,
            "action": a.action,
            "path": a.path,
            "status": a.status,
        }
        for a in items
    ]


@app.on_event("startup")
def startup_checks():
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET is required")
    if not ADMIN_API_KEY:
        raise RuntimeError("ADMIN_API_KEY is required")
