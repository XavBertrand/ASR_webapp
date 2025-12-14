# ASR WebApp

This repository contains the web application that interfaces with the ASR system running on a Jetson device (see: [ASR_jetson](https://github.com/XavBertrand/ASR_jetson)). The webapp provides a front-end UI and backend server to interact with the speech‑to‑text service on Jetson.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Running](#running)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Development & Deployment](#development--deployment)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

- Web interface to send audio or commands to the ASR system.
- Real-time or near‑real-time transcription display.
- Backend proxy / API that forwards requests to the Jetson endpoint.
- Support for WebSocket or HTTP streaming (if implemented).
- Cross-platform launch scripts (Shell, PowerShell, Batch).

## Architecture

The project is structured as follows:

```
/
├── server/             ← backend server (e.g. Python, Flask, FastAPI, etc.)
├── webapp/             ← frontend app (HTML / JS / CSS)
├── run.sh              ← script to launch the full stack on Unix
├── run.bat / run_simple.bat ← Windows wrappers
├── setup_windows.ps1   ← Windows setup script
└── .gitignore
```

- The **server/** folder handles HTTP/WebSocket requests from the front-end and forwards them to the Jetson ASR device (or returns responses).
- The **webapp/** folder contains the client‑side code (web UI).
- Launch scripts help to start both frontend + backend easily in development or production mode.

## Getting Started

### Prerequisites

You will need:

- A Jetson device running the ASR service (see `ASR_jetson` repository).
- Node.js (for frontend, if applicable)
- Python (or the language used by `server/`)
- Network connectivity between this webapp host and the Jetson device (same LAN or accessible IP).
- (Optional) WebSocket support, SSL/TLS if exposing over internet.

### Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/XavBertrand/ASR_webapp.git
   cd ASR_webapp
   ```

2. Install server dependencies:

   ```bash
   cd server
   pip install -r requirements.txt
   ```

3. Install frontend dependencies (if applicable):

   ```bash
   cd ../webapp
   npm install
   ```

### Configuration

You need to configure how the webapp connects to the Jetson ASR service.

In the server config (e.g. `server/config.py` or `.env`), set:

- `JETSON_HOST` — IP or hostname of the Jetson ASR server
- `JETSON_PORT` — port on which the ASR service listens
- (Optional) API key, authentication, SSL settings

In the frontend, you may need to set:

- The backend API base URL
- WebSocket URL (if using real-time streaming)

### Running

You can launch everything (virtualenv, dependencies, Gunicorn server bound to `0.0.0.0:8000`) with:

```bash
python launch_server.py
```

Environment variables `GUNICORN_HOST`, `GUNICORN_PORT`, `GUNICORN_WORKERS`, and `GUNICORN_TIMEOUT` let you adjust the listener and worker count if needed.  
To chain the Caddy reverse proxy (e.g. for DuckDNS/HTTPS), pass the Caddyfile path:

```bash
python launch_server.py --caddyfile ../Caddyfile.local
```

Use `--caddyfile ../Caddyfile.public` for the public DuckDNS config (requires running the script with sufficient privileges to bind :80/:443 or a `setcap`-enabled Caddy binary). `--caddy-bin /full/path/to/caddy` overrides the binary if it is not on PATH.

You can use the provided scripts to launch the app:

- **Unix / Linux / macOS**:

  ```bash
  ./run.sh
  ```

- **Windows**:

  ```bat
  run.bat
  ```

Or in “simple” mode (just starting backend or frontend) via `run_simple.bat`.

Alternatively, run manually:

```bash
# In one terminal
cd server
python app.py

# In another terminal
cd webapp
npm start
```

Then open your browser to `http://localhost:PORT` (default port defined in server/frontend config).

#### Production via Docker (Caddy + DuckDNS automation)

The provided `Dockerfile` now reproduces the full setup described in `SETUP_SERVER_FULL.md` (Gunicorn + Caddy HTTPS reverse proxy + optional DuckDNS cron). This keeps the host configuration minimal (only port-forwarding on the Livebox is assumed).

1. Build the image:
   ```bash
   docker build -t asr-webapp:latest .
   ```
2. Create an `.env` file with at least the public domain and credentials:
   ```bash
   cat <<'EOF' > .env
   CADDY_DOMAIN=ai-actionavocats.duckdns.org
   CADDY_EMAIL=you@example.com
   BASIC_AUTH_USER=xavier
   BASIC_AUTH_PASSWORD=StrongPasswordHere
   DUCKDNS_DOMAIN=ai-actionavocats
   DUCKDNS_TOKEN=YOUR_DUCKDNS_TOKEN
   EOF
   ```
3. Run the container (either with `--network host` or by publishing the ports):
   ```bash
   # Option A – Linux host with host networking
   docker run -d \
     --name asr-webapp \
     --network host \
     --env-file .env \
     -v "$(pwd)/recordings:/app/recordings" \
     -v caddy-data:/root/.local/share/caddy \
      -v caddy-config:/root/.config/caddy \
     asr-webapp:latest

   # Option B – WSL2 / Windows: publish the ports explicitly
   docker run -d \
     --name asr-webapp \
     --env-file .env \
     -p 80:80 -p 443:443 -p 8000:8000 \
     -v "$(pwd)/recordings:/app/recordings" \
     -v caddy-data:/root/.local/share/caddy \
      -v caddy-config:/root/.config/caddy \
     asr-webapp:latest
   ```
   When running under WSL2, remember that Windows still needs the `netsh interface portproxy` rules from `SETUP_SERVER_FULL.md` so that traffic reaching Windows on 80/443 is forwarded to WSL/Docker.
   If you see uploads owned by `root`, add `-e UPLOAD_UID=$(id -u) -e UPLOAD_GID=$(id -g)` (or set these in `.env`) so recordings inherit your host user/group even with Docker volumes.

Environment variables recognized by the image:

| Variable | Description | Default |
| --- | --- | --- |
| `CADDY_DOMAIN` | Public hostname (DuckDNS domain) served by Caddy | `localhost` |
| `CADDY_EMAIL` | Optional email for Let’s Encrypt / ACME | empty |
| `BASIC_AUTH_USER` | Username for HTTP Basic Auth | `xavier` |
| `BASIC_AUTH_PASSWORD` | Plaintext password (hash generated automatically) | `MyPassword` |
| `BASIC_AUTH_PASSWORD_HASH` | Precomputed hash (overrides plaintext) | empty |
| `BASIC_AUTH_EXTRA_USERS` | Extra `username hash` pairs separated by `;` | empty |
| `DUCKDNS_DOMAIN` / `DUCKDNS_TOKEN` | Enable automatic DuckDNS IP updates from inside the container | disabled |
| `DUCKDNS_INTERVAL` | Seconds between DuckDNS refresh | `300` |
| `GUNICORN_HOST`, `GUNICORN_PORT`, `GUNICORN_WORKERS`, `GUNICORN_THREADS`, `GUNICORN_TIMEOUT` | Gunicorn tuning | `0.0.0.0`, `8000`, `4`, `4`, `300` |
| `UPLOAD_FOLDER` | Destination folder for uploaded audio (bind-mount `/app/recordings`) | `/app/recordings` |
| `UPLOAD_UID` / `UPLOAD_GID` | UID/GID to apply to uploaded files (fallback to `stat` of `UPLOAD_FOLDER`) | empty |

Uploads are stored per authenticated user (Basic Auth) under `UPLOAD_FOLDER/<user>/filename_timestamp.ext` with a companion `_meta.json` in the same folder. Mount `/app/recordings` on the host to retrieve them (a compatibility symlink exists at `/data/recordings` for legacy mounts).

With these settings the image automatically:

- Installs Python deps, Gunicorn, ffmpeg, Caddy.
- Runs Gunicorn serving `server.app:app`.
- Serves the `webapp/` static bundle via Caddy with HTTPS + HTTP/3.
- Configures HTTP Basic Auth exactly like the manual Caddyfile in `SETUP_SERVER_FULL.md`.
- Optionally keeps the DuckDNS IP fresh via the same cron URL as in the guide.

This reduces manual host steps to: providing environment variables, ensuring the Livebox forwards 80/443 to the Docker host, and running `docker run`.

## Usage

Once running:

1. Access the web UI.
2. Upload or record audio (if feature supported).
3. Submit to the ASR service.
4. View the transcribed text or streaming result.
5. Optionally, send commands or settings to adjust ASR behavior.

You might also see status, logs, or error messages in the server console.

## API Endpoints

Here is a sample of API endpoints that the server provides (adjust as per your implementation):

| Endpoint         | Method   | Description |
|------------------|----------|-------------|
| `/api/transcribe` | `POST`   | Send audio file or audio data to transcribe |
| `/api/stream`     | `WebSocket` / `POST` | Real-time streaming ASR (if supported) |
| `/api/status`     | `GET`    | Get status or health check of ASR backend |
| `/api/config`     | `GET` / `POST` | Get or update settings (e.g. language, model) |

Be sure to document all API routes, accepted payloads (e.g. audio format, JSON structure) and responses (transcription JSON, error codes).

## Development & Deployment

When developing:

- Use hot-reload or watcher (on frontend)
- Use logging and debugging in backend
- Add CORS as needed

For deployment:

- Consider bundling frontend and serving as static assets via backend server
- Use reverse proxy (e.g. Nginx)
- Secure with HTTPS, authentication
- Monitor latency, error rates

## Troubleshooting

- **Cannot connect to Jetson host** — check network, firewall, IP configuration.
- **Timeouts or no response** — ensure the ASR system is running and reachable.
- **CORS or browser errors** — adjust CORS headers in backend.
- **Audio format not accepted** — convert to a supported format (e.g. WAV, 16 kHz, mono).
- **WebSocket not working** — check if port open, proxy passes WebSocket traffic.

## Contributing

Contributions are welcome! Here are some ideas:

- Add support for more audio formats
- Improve frontend UI/UX
- Add more ASR backend options
- Add authentication / user accounts
- Add test suite / CI integration

Please fork, create a branch, and submit a pull request.

## License

Specify your license here (e.g. MIT, Apache 2.0, etc.).
