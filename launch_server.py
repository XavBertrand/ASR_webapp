#!/usr/bin/env python3
"""
Automated launcher for the Flask/Gunicorn server and the optional Caddy reverse proxy.

This script will:
1. Create (if needed) and reuse the local virtual environment.
2. Install/update the Python dependencies, including Gunicorn.
3. Start Gunicorn bound to 0.0.0.0 so the server is reachable from other devices.
4. Optionally launch Caddy with the provided Caddyfile so HTTPS/DuckDNS access works.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SERVER_DIR = ROOT / "server"
VENV_DIR = ROOT / "venv"
BIN_DIR = VENV_DIR / ("Scripts" if os.name == "nt" else "bin")
PYTHON_BIN = BIN_DIR / ("python.exe" if os.name == "nt" else "python")
PROCESSES: list[tuple[str, subprocess.Popen]] = []


def log_step(message: str) -> None:
    print(f"\n[+] {message}")


def run(cmd: list[str], *, cwd: Path | None = None, check: bool = True) -> None:
    """Wrapper to echo and run subprocess commands."""
    print(f"    $ {shlex.join(cmd)}")
    subprocess.run(cmd, cwd=cwd or ROOT, check=check)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Launch Gunicorn (and optionally Caddy).")
    parser.add_argument(
        "--host",
        default=os.environ.get("GUNICORN_HOST", "0.0.0.0"),
        help="Host/IP for Gunicorn (default: %(default)s)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("GUNICORN_PORT", "8000")),
        help="Port for Gunicorn (default: %(default)s)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.environ.get("GUNICORN_WORKERS", "4")),
        help="Number of Gunicorn workers (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.environ.get("GUNICORN_TIMEOUT", "120")),
        help="Gunicorn worker timeout (seconds, default: %(default)s)",
    )
    parser.add_argument(
        "--caddyfile",
        type=Path,
        help="Optional path to a Caddyfile (e.g. ../Caddyfile.local).",
    )
    parser.add_argument(
        "--caddy-bin",
        default=os.environ.get("CADDY_BIN", "caddy"),
        help="Caddy executable to use (default: %(default)s)",
    )
    return parser.parse_args()


def ensure_virtualenv() -> None:
    if VENV_DIR.exists():
        log_step(f"Virtualenv found at {VENV_DIR}")
        return
    log_step(f"Creating virtualenv at {VENV_DIR}")
    run([sys.executable, "-m", "venv", str(VENV_DIR)])


def install_dependencies() -> None:
    log_step("Upgrading pip")
    run([str(PYTHON_BIN), "-m", "pip", "install", "--upgrade", "pip"])

    log_step("Installing server requirements")
    requirements_file = ROOT / "server" / "requirements.txt"
    run([str(PYTHON_BIN), "-m", "pip", "install", "-r", str(requirements_file)])

    log_step("Ensuring Gunicorn is installed")
    run([str(PYTHON_BIN), "-m", "pip", "install", "gunicorn"])


def start_background_process(name: str, cmd: list[str], *, cwd: Path) -> None:
    print(f"    $ {shlex.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd, cwd=cwd)
    except FileNotFoundError as exc:
        raise SystemExit(f"Failed to start {name}: {exc}") from exc
    PROCESSES.append((name, proc))
    log_step(f"{name} started with PID {proc.pid}")


def start_gunicorn(host: str, port: int, workers: int, timeout: int) -> None:
    log_step(f"Starting Gunicorn on {host}:{port} with {workers} worker(s)")
    cmd = [
        str(PYTHON_BIN),
        "-m",
        "gunicorn",
        "app:app",
        "--bind",
        f"{host}:{port}",
        "--workers",
        str(workers),
        "--timeout",
        str(timeout),
    ]
    start_background_process("Gunicorn", cmd, cwd=SERVER_DIR)


def start_caddy(config_path: Path, binary: str) -> None:
    log_step(f"Launching Caddy with {config_path}")
    if not config_path.is_file():
        raise SystemExit(f"Caddyfile not found: {config_path}")
    cmd = [
        binary,
        "run",
        "--config",
        str(config_path),
        "--adapter",
        "caddyfile",
    ]
    start_background_process("Caddy", cmd, cwd=config_path.parent)


def stop_processes() -> None:
    for name, proc in PROCESSES:
        if proc.poll() is None:
            log_step(f"Stopping {name}...")
            proc.terminate()
    for name, proc in PROCESSES:
        if proc.poll() is None:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                log_step(f"Forcing {name} to stop...")
                proc.kill()


def monitor_processes() -> int:
    if not PROCESSES:
        return 0
    try:
        while True:
            for name, proc in PROCESSES:
                ret = proc.poll()
                if ret is not None:
                    log_step(f"{name} exited with code {ret}")
                    return ret
            time.sleep(1)
    except KeyboardInterrupt:
        log_step("CTRL+C detected, shutting down...")
        return 130
    finally:
        stop_processes()


def main() -> None:
    args = parse_args()
    if not SERVER_DIR.exists():
        raise SystemExit(f"Cannot find server directory at {SERVER_DIR}")

    ensure_virtualenv()
    install_dependencies()
    start_gunicorn(args.host, args.port, args.workers, args.timeout)

    if args.caddyfile:
        caddyfile = args.caddyfile.expanduser().resolve()
        start_caddy(caddyfile, args.caddy_bin)
    else:
        log_step("No Caddyfile provided — skipping Caddy launch.")

    exit_code = monitor_processes()
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
