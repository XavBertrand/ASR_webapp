# ASR Web App – Full Server Setup Guide (WSL + DuckDNS + Caddy + HTTPS)

This guide walks through every step required to expose the ASR Web App securely on the internet using WSL2, DuckDNS, and Caddy.

## Overview
- WSL2 backend (Flask + Gunicorn)
- Caddy reverse proxy with HTTPS/HTTP3, compression, and static serving
- DuckDNS subdomain with automatic IP renewal
- Let’s Encrypt SSL certificates
- HTTP Basic Authentication
- Worldwide access through your home router

## 1. Requirements Summary
You need the following components prepared:
- DuckDNS domain
- Windows PC running WSL2
- Router with NAT/PAT administration access
- Repository cloned to `~/ASR_webapp`
- Python virtual environment set up
- `caddy` and `ffmpeg` installed inside WSL
- Windows `portproxy` rules configured

## 2. DuckDNS Setup
### 2.1 Create a Domain
1. Visit https://www.duckdns.org and log in.
2. Choose a subdomain, e.g. `ai-actionavocats`.
3. Resulting FQDN: `ai-actionavocats.duckdns.org`.

### 2.2 Install DuckDNS Cron Updater
```bash
mkdir -p ~/duckdns
cd ~/duckdns
echo "url=\"https://www.duckdns.org/update?domains=ai-actionavocats&token=YOURTOKEN&ip=\" " > duck.sh
chmod 700 duck.sh
(crontab -l ; echo "*/5 * * * * ~/duckdns/duck.sh >/dev/null 2>&1") | crontab -
```

### 2.3 Test DNS Resolution
```bash
ping ai-actionavocats.duckdns.org
```

## 3. Router NAT/PAT (Livebox)
Forward these ports from your router to the **Windows host** (not the WSL VM). Reserve this LAN IP in your router to stop it from changing.

| External Port | Protocol | Internal IP (Windows) | Internal Port |
| --- | --- | --- | --- |
| 80 | TCP | 192.168.1.18 | 80 |
| 443 | TCP | 192.168.1.18 | 443 |

## 4. Windows Portproxy → WSL
### 4.1 Get the Current WSL IP
`WSL_IP` is different from the Windows IP used in the router table; it is usually in the `172.x.x.x` range and **changes after each reboot**.
```powershell
wsl hostname -I
```

### 4.2 Configure Portproxy Rules
Run the commands below in **PowerShell Admin** every time the WSL IP changes. Replace `WSL_IP` with the value from step 4.1 (or reuse the snippet).
```powershell
$WSLIP = (wsl hostname -I).Trim()
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=80  connectaddress=$WSLIP connectport=80
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=443 connectaddress=$WSLIP connectport=443
```

### 4.3 Allow Traffic in Windows Firewall
```powershell
netsh advfirewall firewall add rule name="Caddy 80"  dir=in action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="Caddy 443" dir=in action=allow protocol=TCP localport=443
```

## 5. WSL Environment
### 5.1 Activate the Python Virtual Environment
```bash
cd ~/ASR_webapp
source .venv/bin/activate
```

### 5.2 Install System and Python Dependencies
```bash
sudo apt-get update
sudo apt-get install -y caddy ffmpeg
uv sync
```

## 6. Configure Caddy (HTTPS + Reverse Proxy)
### 6.1 Generate the BasicAuth Password Hash
```bash
caddy hash-password --plaintext 'MyPassword'
```

### 6.2 Create `~/Caddyfile.public`
Replace `REPLACE_WITH_HASH` below with the generated hash.

```caddyfile
{
    admin off
}

ai-actionavocats.duckdns.org {
    encode zstd gzip

    basic_auth {
        xavier $2a$14$REPLACE_WITH_HASH
    }

    @health {
        path /health
    }
    reverse_proxy @health 127.0.0.1:8000

    @uploads {
        path /upload*
    }
    reverse_proxy @uploads 127.0.0.1:8000 {
        transport http {
            read_timeout  300s
            write_timeout 300s
            dial_timeout  10s
        }
    }

    root * /home/xavier/ASR_webapp/webapp
    file_server
}
```

## 7. Running the Server
### 7.1 Start Gunicorn
> ⚠️ `server.app` must be importable, so either run the command from the repository root or pass `--chdir ~/ASR_webapp`. Otherwise Gunicorn raises `ModuleNotFoundError: No module named 'server'`.

**Option A — from the project folder**
```bash
cd ~/ASR_webapp
source .venv/bin/activate
gunicorn -w 2 -b 127.0.0.1:8000 server.app:app
```

**Option B — from anywhere**
```bash
source ~/ASR_webapp/.venv/bin/activate
gunicorn --chdir ~/ASR_webapp -w 2 -b 127.0.0.1:8000 server.app:app
```

### 7.2 Start Caddy (new terminal)
```bash
caddy fmt --overwrite ~/Caddyfile.public
sudo pkill -f 'caddy run' || true
sudo caddy run --config ~/Caddyfile.public
```

- Access the app at https://ai-actionavocats.duckdns.org/.
- Test the API:

```bash
curl -vk https://ai-actionavocats.duckdns.org/health -u xavier:MyPassword

# Local test without router loopback (useful if your box does not support loopback)
curl -vk --resolve ai-actionavocats.duckdns.org:443:127.0.0.1 \
     https://ai-actionavocats.duckdns.org/health -u xavier:MyPassword
```

> ℹ️ `https://localhost:8443` is only reachable when using the local mode in section 9 with `Caddyfile.local`. When `Caddyfile.public` is used, always test with your DuckDNS domain on port 443.

## 8. Manage BasicAuth Users
### Add a User
```bash
caddy hash-password --plaintext 'DelphinePassword'
```

Update the `basic_auth` block:

```caddyfile
basic_auth {
    xavier   HASH_XAV
    delphine HASH_DEL
}
```

Restart Caddy afterward. To remove a user, delete the corresponding line and restart again.

## 9. Local-only HTTPS Mode (Optional)
Create `~/Caddyfile.local`:

```caddyfile
https://localhost:8443 {
    tls internal
    basic_auth {
        xavier HASH
    }
    reverse_proxy 127.0.0.1:8000
    root * /home/xavier/ASR_webapp/webapp
    file_server
}
```

Run Caddy locally:
```bash
caddy run --config ~/Caddyfile.local
```

## 10. Quick Commands Summary
### Start Backend
```bash
cd ~/ASR_webapp
source .venv/bin/activate
gunicorn -w 2 -b 127.0.0.1:8000 server.app:app
```

### Start Caddy
```bash
sudo caddy run --config ~/Caddyfile.public
```

### Stop Everything
```bash
sudo pkill -f 'caddy run'
pkill -f "gunicorn .*server.app:app"
```

### Generate Password
```bash
caddy hash-password --plaintext 'MyPassword'
```

### Test Health Endpoint
```bash
curl -vk https://ai-actionavocats.duckdns.org/health -u xavier:MyPassword
```

### Test Health Endpoint (bypass router loopback)
```bash
curl -vk --resolve ai-actionavocats.duckdns.org:443:127.0.0.1 \
     https://ai-actionavocats.duckdns.org/health -u xavier:MyPassword
```

## 11. Troubleshooting External Access
If the site is unreachable from 4G/external networks, check the following:

1. **Public IP is current** – In WSL, compare `curl https://icanhazip.com` with `ping ai-actionavocats.duckdns.org`. If they differ, rerun `~/duckdns/duck.sh` or fix the token.
2. **Router forwarding** – Ensure ports 80/443 are NAT’ed to the current *Windows* LAN IP (e.g., 192.168.1.18). Reserve that IP in the router to prevent changes.
3. **Windows portproxy → WSL** – WSL IP changes after reboot. In admin PowerShell:
   ```powershell
   wsl hostname -I
   netsh interface portproxy show all
   ```
   Delete/recreate the rules if `connectaddress` no longer matches the WSL IP.
4. **Windows Firewall** – Confirm rules `Caddy 80` and `Caddy 443` are active:
   ```powershell
   netsh advfirewall firewall show rule name="Caddy 443"
   ```
   Recreate them if needed.
5. **Caddy listening on 0.0.0.0** – In WSL, while Caddy runs, check `sudo ss -ltnp '( sport = :443 )'` to confirm the port is open.
6. **External port check** – Use a smartphone on 4G or a site like yougetsignal.com/open-ports to verify that your public IP exposes ports 80/443. If not, the block is still NAT/firewall.

Once these are green, `https://ai-actionavocats.duckdns.org/health` should return `{"status":"ok"}` from outside.

## 12. Automated Deployment via Docker
If you prefer to skip all WSL setup (Python, Caddy, DuckDNS cron, etc.), the provided Docker image performs the same stack: Gunicorn → Caddy (HTTPS/HTTP/3, BasicAuth) → DuckDNS, assuming your router forwards 80/443 to the Docker host.

1. **Build the image** (once or via CI):
   ```bash
   docker build -t asr-webapp:latest .
   ```
2. **Prepare the secrets** in an `.env` file:
   ```bash
   cat <<'EOF' > asr.env
   CADDY_DOMAIN=ai-actionavocats.duckdns.org
   CADDY_EMAIL=you@example.com        # Let's Encrypt notifications (optional)
   BASIC_AUTH_USER=xavier
   BASIC_AUTH_PASSWORD=StrongPasswordHere
   DUCKDNS_DOMAIN=ai-actionavocats
   DUCKDNS_TOKEN=YOUR_DUCKDNS_TOKEN
   EOF
   ```
3. **Run the container** (host network = bind directly on 80/443/8000):
   ```bash
   docker run -d \
     --name asr-webapp \
     --network host \
     --env-file asr.env \
     -v asr-recordings:/app/recordings \
     -v caddy-data:/root/.local/share/caddy \
     -v caddy-config:/root/.config/caddy \
     asr-webapp:latest
   ```
   If recordings appear as `root` on the host, pass your host IDs so uploads inherit your group: `-e UPLOAD_UID=$(id -u) -e UPLOAD_GID=$(id -g)` (or set them in `asr.env`). This is especially useful with the named Docker volume `asr-recordings`.
   No `--network host`? Publish ports: `-p 80:80 -p 443:443 -p 8000:8000`.

### Docker Image Behavior
- Installs Python deps, ffmpeg, Caddy.
- Runs Gunicorn (`server.app:app`) as in section 7.
- Starts Caddy with the same config (HTTPS, BasicAuth, reverse proxy /upload, static `webapp/`).
- Updates DuckDNS every 5 minutes if `DUCKDNS_DOMAIN`/`DUCKDNS_TOKEN` are provided.
- Persistence:
  - `/app/recordings` → uploads (recommended mount). Compatibility symlink `/data/recordings` points to it.
  - Uploads are stored per BasicAuth user: `/app/recordings/<user>/name_timestamp.ext` + `_meta.json`.
  - `/root/.local/share/caddy` and `/root/.config/caddy` → certificates and TLS state.

### Variables

| Variable | Role | Default |
| --- | --- | --- |
| `CADDY_DOMAIN` | Public domain served by Caddy (DuckDNS) | `localhost` |
| `CADDY_EMAIL` | ACME/Let’s Encrypt email | empty |
| `BASIC_AUTH_USER` | BasicAuth username | `xavier` |
| `BASIC_AUTH_PASSWORD` | Plaintext password (hash computed automatically) | `MyPassword` |
| `BASIC_AUTH_PASSWORD_HASH` | Precomputed `caddy hash-password` (overrides plaintext) | empty |
| `BASIC_AUTH_EXTRA_USERS` | Extra `user hash` pairs separated by `;` | empty |
| `DUCKDNS_DOMAIN` / `DUCKDNS_TOKEN` | Enable DuckDNS auto-update | disabled |
| `DUCKDNS_INTERVAL` | Seconds between DuckDNS updates | `300` |
| `GUNICORN_HOST/PORT/WORKERS/THREADS/TIMEOUT` | Gunicorn options | `0.0.0.0` / `8000` / `4` / `4` / `300` |
| `UPLOAD_FOLDER` | Path for uploads (per BasicAuth user) | `/app/recordings` (`/data/recordings` is an alias) |
| `UPLOAD_UID` / `UPLOAD_GID` | UID/GID applied to uploaded files (fallback to owner of `UPLOAD_FOLDER`) | empty |

With this image, the only manual steps are providing DuckDNS and BasicAuth secrets, then running the container (plus keeping router forwarding 80/443 to the Docker host). All steps 5–10 of this guide happen inside the image.
