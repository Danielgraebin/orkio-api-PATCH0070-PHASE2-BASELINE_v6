# Orkio API — PATCH0070 PHASE2 BASELINE

## Start (Railway)
**Start command**: (leave default from Dockerfile)  
`uvicorn app.main:app --host 0.0.0.0 --port $PORT`

**Pre-deploy command**:
`alembic upgrade head`

## Endpoints (core)
- GET /api/health
- POST /api/auth/register
- POST /api/auth/login
- GET /api/threads
- POST /api/threads
- GET /api/messages?thread_id=...
- POST /api/chat
- POST /api/files/upload
- GET /api/files
- GET /api/admin/overview  (X-Admin-Key)
- GET /api/admin/users     (X-Admin-Key)
- GET /api/admin/files     (X-Admin-Key)
- GET /api/admin/audit     (X-Admin-Key)

## Notes
- Streaming is disabled by default (ENABLE_STREAMING=0)
- RAG is **keyword fallback** only in baseline; no pgvector required.
