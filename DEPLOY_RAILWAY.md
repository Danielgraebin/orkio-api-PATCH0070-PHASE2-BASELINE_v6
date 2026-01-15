# Railway Deploy Checklist (PATCH0070)

## Service: orkio-api (Dockerfile)
### Pre-deploy
`alembic upgrade head`

### Env vars (minimum)
APP_ENV=production
DATABASE_URL=<from Railway Postgres>
JWT_SECRET=<strong>
JWT_ALGORITHM=HS256
JWT_EXPIRES_IN=3600
TENANT_MODE=multi
DEFAULT_TENANT=public
CORS_ORIGINS=https://<your orkio-web domain>
ADMIN_API_KEY=<strong>
ADMIN_EMAILS=daniel@patroai.com
ENABLE_STREAMING=0
LOG_LEVEL=INFO

### Optional
OPENAI_API_KEY=<optional>
OPENAI_MODEL=gpt-4o-mini

## Validation
- GET /api/health -> 200 JSON {status, db, version, rag}
- Register + Login -> returns token
- POST /api/files/upload -> returns extracted_chars
- POST /api/chat -> saves assistant message
