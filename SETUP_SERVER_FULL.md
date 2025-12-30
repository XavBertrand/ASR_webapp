# ASR Web App – Full Server Setup (WSL + DuckDNS + Caddy + HTTPS)

End-to-end guide to publish the webapp over HTTPS with Caddy and DuckDNS. Application authentication (sessions, roles, 2FA) is handled by the webapp; Caddy only provides an optional single “gateway” BasicAuth lock.

## Overview
- Flask/Gunicorn backend on 127.0.0.1:8000 (loopback behind Caddy)
- Caddy reverse proxy (HTTPS/HTTP3, compression) + optional global BasicAuth (`GATEWAY_BASICAUTH_*`)
- DuckDNS for public domain + IP updates
- Router NAT 80/443 to Windows; Windows portproxy to WSL

## Prerequisites
- DuckDNS domain (e.g., `ai-actionavocats.duckdns.org`)
- Windows with WSL2
- Router admin access to forward 80/443
- Repo cloned to `~/ASR_webapp`
- `caddy`, `ffmpeg`, Python/uv installed

## Steps
1. **DuckDNS**  
   - Create the domain at https://duckdns.org.  
   - Add a cron to update IP every 5 minutes (see DuckDNS instructions).

2. **Router NAT/PAT**  
   - Forward TCP 80 and 443 to the Windows host IP (e.g., 192.168.1.18). Reserve the IP.

3. **Windows portproxy → WSL (PowerShell Admin, run after each WSL IP change)**  
   ```powershell
   $WSLIP = (wsl hostname -I).Trim()
   netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=80  connectaddress=$WSLIP connectport=80
   netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=443 connectaddress=$WSLIP connectport=443
   netsh advfirewall firewall add rule name="Caddy 80"  dir=in action=allow protocol=TCP localport=80
   netsh advfirewall firewall add rule name="Caddy 443" dir=in action=allow protocol=TCP localport=443
   ```

4. **WSL dependencies**  
   ```bash
   sudo apt-get update
   sudo apt-get install -y caddy ffmpeg
   cd ~/ASR_webapp
   UV_CACHE_DIR=.uv_cache uv sync
   ```

5. **Caddy config (optional gateway lock)**  
   - If you want the lock, generate the hash:  
     ```bash
     caddy hash-password --plaintext 'StrongGatewayPwd'
     ```
   - Minimal `~/Caddyfile.public`:
     ```caddyfile
     {
         admin off
         email you@example.com
     }

     ai-actionavocats.duckdns.org {
         encode zstd gzip
         header {
            Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self' blob:; frame-ancestors 'none'"
             X-Content-Type-Options "nosniff"
             X-Frame-Options "DENY"
             Referrer-Policy "no-referrer"
             Permissions-Policy "geolocation=()"
         }
         # Optional global lock (single pair)
         basic_auth {
             gateway_user GATEWAY_HASH_HERE
         }

         @health {
             path /health
         }
         handle @health {
             reverse_proxy 127.0.0.1:8000
         }

         handle {
             reverse_proxy 127.0.0.1:8000 {
                 transport http {
                     read_timeout  300s
                     write_timeout 300s
                     dial_timeout  10s
                 }
             }
         }
     }
     ```
   - Remove the `basic_auth` block if you do not want the gateway lock.

6. **App environment variables (must be exported before Gunicorn)**  
   - Required: `SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` (≥12 chars).  
   - Optional security: `REQUIRE_ADMIN_2FA=true` to force admin 2FA; `TOTP_ENC_KEY` (Fernet key) to encrypt TOTP secret; `SESSION_COOKIE_SECURE` (default true), `SESSION_COOKIE_SAMESITE` (default Lax); `WEBAPP_ENV=production` to enable stricter warnings.  
   - Rate limiting: `RATELIMIT_STORAGE_URL` (`memory://` dev default; set `redis://redis:6379/0` in prod with a Redis backend installed).  
   - Proxy headers: `TRUST_PROXY_HEADERS=true` only when requests come through a trusted reverse proxy (e.g., Caddy); prevents IP spoofing when Gunicorn is hit directly.  
   - Uploads: `UPLOAD_FOLDER`, `MAX_CONTENT_LENGTH_MB`, `UPLOAD_UID/GID`.  
   - Gateway lock (used by container entrypoint/Caddyfile): `GATEWAY_BASICAUTH_USER`, `GATEWAY_BASICAUTH_HASHED_PASSWORD`.  
   - Gunicorn bind: `GUNICORN_BIND_LOCAL_ONLY` (default true in production; forces loopback), `GUNICORN_HOST` (default `127.0.0.1`, keep loopback when Caddy is in front), `GUNICORN_PORT` (default 8000), `GUNICORN_WORKERS`, `GUNICORN_THREADS`, `GUNICORN_TIMEOUT`.

7. **Start Gunicorn**  
   ```bash
   cd ~/ASR_webapp
   export SECRET_KEY=change-me
   export ADMIN_USERNAME=admin
   export ADMIN_PASSWORD=SuperSecureAdmin!
   uv run gunicorn server.app:app -w 4 -k gthread --threads 4 --bind 127.0.0.1:8000 --timeout 300
   ```
   Gunicorn should stay on loopback when Caddy is in front (set `GUNICORN_BIND_LOCAL_ONLY=true`). Bind to `0.0.0.0` only if you intentionally expose the app directly (not recommended). Avoid `--network host` unless you understand it will expose port 8000 unless loopback is enforced.

8. **Start Caddy (new WSL terminal)**  
   ```bash
   caddy fmt --overwrite ~/Caddyfile.public
   sudo pkill -f 'caddy run' || true
   sudo caddy run --config ~/Caddyfile.public --adapter caddyfile
   ```
   For development & tests, server can be launched without reunning gunicorn and caddy with:
   ```bash 
   export UV_CACHE_DIR=.uv_cache
   export SECRET_KEY=dev-secret 
   export ADMIN_USERNAME=admin 
   export ADMIN_PASSWORD=SuperSecureAdmin! 
   uv run python -m server.app
   ```

9. **Usage flow**  
   - Browse to https://<your-domain>/login (Caddy gateway lock first if enabled).  
   - Log in with the bootstrap admin.  
   - If `REQUIRE_ADMIN_2FA=true`, go to `/admin/2fa/setup`, scan the secret, validate an OTP.  
   - Create users via `/admin/users` (no CLI needed).  
   - Reset passwords and enable/disable accounts from the same page.  
   - View audit at `/admin/audit`.  
   - Users log in at `/login` and use the main upload UI.

10. **Quick checks**  
   ```bash
   curl -vk https://ai-actionavocats.duckdns.org/health
   # if gateway lock is enabled:
   # curl -vk -u gateway_user:GatewayPwd https://ai-actionavocats.duckdns.org/health
   ```

## Technical notes
- App auth: session cookies HttpOnly + SameSite=Lax (+ Secure in HTTPS), CSRF on POST/PUT/DELETE (`X-CSRF-Token` or `csrf_token`).  
- Passwords hashed with Argon2id. Inactive users are denied and session cleared.  
- Rate limiting: `/login` 5/min IP + 20/hour IP; sensitive admin endpoints 5/min. Backend configurable via `RATELIMIT_STORAGE_URL` (use Redis for multi-worker).  
- Security headers added by Caddy/Flask: CSP (self + inline where needed), `X-Content-Type-Options=nosniff`, `X-Frame-Options=DENY`, `Referrer-Policy=strict-origin-when-cross-origin`, `Permissions-Policy=geolocation=(), microphone=(), camera=()`.  
- CORS disabled by default; no `Access-Control-Allow-Origin` header unless explicitly added.  
- Real client IP trusted only when `TRUST_PROXY_HEADERS=true` (behind Caddy). Direct hits on Gunicorn cannot spoof `X-Forwarded-For`.  
- Audit in SQLite (`audit_log`).  
- Admin 2FA via TOTP (pyotp) + hashed recovery codes; secrets can be encrypted with `TOTP_ENC_KEY`. Recovery codes are generated at first setup and only regenerated via the dedicated button (old codes invalidated).  
- Gateway BasicAuth: single global pair if configured; all per-user auth is handled by the app.
