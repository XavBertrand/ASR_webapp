# ASR WebApp

Flask/Gunicorn + Caddy reverse proxy for the Jetson ASR service, with application-level authentication (sessions, RBAC, optional admin 2FA) and an optional global “gateway” BasicAuth handled by Caddy.

## Roles and usage
- **Admin**: logs in via `/login`, enables 2FA if required, manages users at `/admin/users` (create, reset password, enable/disable), reviews audit at `/admin/audit`, can regenerate recovery codes at `/admin/2fa/setup`.
- **User**: logs in via `/login` then uses the main UI to upload audio/metadata. No admin access.

## Authentication flow
- Username/password login with session cookies (HttpOnly + SameSite=Lax + Secure when HTTPS). Session is rotated on login.
- CSRF required on all POST/PUT/DELETE (header `X-CSRF-Token` or form field `csrf_token`; token is stored in session and exposed via a readable `csrf_token` cookie).
- RBAC: `/admin/*` is admin-only; `is_active=False` users are denied and their session is cleared.
- Rate limiting: `/login` limited (5/min/IP + 20/hour/IP); sensitive admin endpoints limited (5/min). Backend configurable via `RATELIMIT_STORAGE_URL` (dev: memory; prod: shared Redis).
- Real client IP only trusted via `TRUST_PROXY_HEADERS=true` (when behind a trusted reverse proxy). Direct hits on Gunicorn cannot spoof `X-Forwarded-For`.
- Audit log: login success/fail, logout, user creation, password reset, active toggle, enable 2FA, recovery code use, bootstrap admin.
- Admin 2FA (TOTP): if `REQUIRE_ADMIN_2FA=true`, admins are redirected to `/admin/2fa/setup` before any admin page. Secrets can be encrypted with `TOTP_ENC_KEY`. Recovery codes are generated only on demand (first setup or explicit “Regenerate”), shown once, and stored hashed.

## Key environment variables
- Required: `SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` (≥12 chars). A bootstrap admin is created at startup if none exists.
- Security: `REQUIRE_ADMIN_2FA` (true/false), `TOTP_ENC_KEY` (Fernet key), `SESSION_COOKIE_SAMESITE` (default Lax), `SESSION_COOKIE_SECURE` (default true), `SESSION_LIFETIME_HOURS` (default 12), `RATELIMIT_STORAGE_URL` (`memory://` by default; set `redis://...` for shared rate limits), `WEBAPP_ENV` (set to `production` to surface stricter warnings), `TRUST_PROXY_HEADERS` (true only when behind a trusted reverse proxy).
- Uploads: `UPLOAD_FOLDER` (./recordings default), `MAX_CONTENT_LENGTH_MB` (default 100), `UPLOAD_UID` / `UPLOAD_GID` to chown uploads.
- Reports: `REPORTS_ROOT` (defaults to `UPLOAD_FOLDER`), `REPORTS_QUEUE_DIR` (defaults to `<REPORTS_ROOT>/queue`) for the History tab status.
- Gateway BasicAuth (Caddy, optional, global): `GATEWAY_BASICAUTH_USER`, `GATEWAY_BASICAUTH_HASHED_PASSWORD` (from `caddy hash-password --plaintext '...'`). If empty, the Caddy lock is disabled.
- Gunicorn: `GUNICORN_BIND_LOCAL_ONLY` (default true in production; forces bind on loopback), `GUNICORN_HOST` (default `127.0.0.1` — keep loopback when Caddy is in front), `GUNICORN_PORT` (default 8000), `GUNICORN_WORKERS`, `GUNICORN_THREADS`, `GUNICORN_TIMEOUT`.

## CLI (optional, everything is also doable in the UI)
```bash
uv run python -m server.manage create-admin --username alice --password "LongAdminPwd"
uv run python -m server.manage create-user --username bob --password "Password123" --role user
uv run python -m server.manage reset-password --username bob --password "NewPass123"
uv run python -m server.manage disable-user --username bob
uv run python -m server.manage enable-user --username bob
```

## UI
- `/login`: username/password + OTP (if admin 2FA). Errors are shown inline.
- `/`: main webapp (upload). “Administration” link only appears for admins.
- `/` History tab: lists the current user’s report PDFs from `<REPORTS_ROOT>/<user>/output/pdf/`, with queue status and direct download.
- `/admin/users`: list users, create, reset password, toggle active/inactive.
- `/admin/audit`: browse audit actions with simple filters.
- `/admin/2fa/setup`: TOTP secret/URI + recovery codes; validate OTP to enable 2FA; regenerate recovery codes explicitly (old codes invalidated).
- `/health`: public.

## Quick dev install
```bash
UV_CACHE_DIR=.uv_cache uv sync
export SECRET_KEY=dev-secret
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=SuperSecureAdmin!
uv run python -m server.app
```
Open http://127.0.0.1:8000/login, log in, and create users from `/admin/users`.

## Réinitialisation de mot de passe
- Lien “Mot de passe oublié ?” sur `/login`. La réponse est toujours générique pour éviter l’énumération.
- Si SMTP est configuré, un email est envoyé; sinon le lien est journalisé côté serveur (niveau WARNING) et visible dans l’audit (`password_reset_requested`).
- Jetons à usage unique, expirent après `RESET_TOKEN_TTL_MINUTES` (30 par défaut), invalidés dès qu’un mot de passe est réinitialisé.
- Variables SMTP : `MAIL_HOST`, `MAIL_PORT` (587 par défaut), `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_FROM`, `MAIL_USE_TLS` (true/false).

## Docker
```bash
docker build -t asr-webapp:latest .
cat > .env <<'EOF'
SECRET_KEY=change-me
ADMIN_USERNAME=admin
ADMIN_PASSWORD=SuperSecureAdmin!
CADDY_DOMAIN=localhost
# Optional: global gateway lock
# GATEWAY_BASICAUTH_USER=gateway
# GATEWAY_BASICAUTH_HASHED_PASSWORD=$(caddy hash-password --plaintext 'StrongGatewayPwd')
EOF

docker run -d \
  --name asr-webapp \
  --env-file .env \
  -p 80:80 -p 443:443 \
  -v "$(pwd)/recordings:/app/recordings" \
  -v caddy-data:/root/.local/share/caddy \
  -v caddy-config:/root/.config/caddy \
  asr-webapp:latest
```
Caddy keeps a single optional global BasicAuth pair if configured. All user auth is managed by the app. When Caddy is enabled, keep Gunicorn bound to loopback (`GUNICORN_BIND_LOCAL_ONLY=true`, `GUNICORN_HOST=127.0.0.1`) so it is not reachable directly; avoid `--network host` unless you intentionally expose port 8000 (not recommended).

## Security
- Argon2id password hashing; no plaintext passwords stored or logged.
- CSRF on all state-changing routes; token in session + readable cookie.
- Session cookies: HttpOnly + SameSite=Lax (+ Secure in HTTPS). Session rotation on login.
- Admin 2FA via TOTP (pyotp), hashed recovery codes; secrets can be encrypted with `TOTP_ENC_KEY`.
- Rate limiting via Flask-Limiter; shared backend configurable with `RATELIMIT_STORAGE_URL`.
- Security headers sent by Flask/Caddy: CSP (self + inline where needed), `X-Content-Type-Options=nosniff`, `X-Frame-Options=DENY`, `Referrer-Policy=strict-origin-when-cross-origin`, `Permissions-Policy=geolocation=(), microphone=(), camera=()`.
- CORS is disabled by default; no `Access-Control-Allow-Origin` header is sent unless explicitly configured.
- Real client IP is only trusted when `TRUST_PROXY_HEADERS=true` (behind a trusted reverse proxy such as Caddy).
- Persistent audit log in SQLite (`audit_log`: ts, actor, target, action, ip, user-agent, metadata_json).

## Tests
```bash
UV_CACHE_DIR=.uv_cache uv run pytest
```
Coverage: bootstrap admin, login success/fail + rate limit, CSRF, RBAC non-admin, create+reset+login, 2FA (OTP + recovery), public /health.
