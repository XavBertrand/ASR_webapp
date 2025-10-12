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
