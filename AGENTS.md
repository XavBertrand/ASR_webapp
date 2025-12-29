# Repository Guidelines

## Project Structure & Module Organization
The core Flask app lives in `server/` (entrypoints: `server/app.py`, CLI helpers in `server/manage.py`, models in `server/models.py`, templates in `server/templates/`). Static PWA assets are in `webapp/` (`index.html`, `manifest.webmanifest`, icons). Tests live in `tests/` (plus a small `server/test_simple.py`). Runtime uploads and reports default to `recordings/`, and the local SQLite DB is `app.db`. Docker and deployment scripts are under `docker/`, with root scripts like `run.sh` and `launch_server.py` for local runs.

## Build, Test, and Development Commands
- `UV_CACHE_DIR=.uv_cache uv sync`: install Python deps using uv (recommended).
- `uv run python -m server.app`: start the dev server on `127.0.0.1:8000`.
- `UV_CACHE_DIR=.uv_cache uv run pytest`: run the full test suite.
- `./run.sh`: create a venv, install `server/requirements.txt`, run `server/app.py`.
- `docker build -t asr-webapp:latest .`: build the Docker image.

## Coding Style & Naming Conventions
Use Python PEP 8 conventions: 4-space indentation, `snake_case` functions/variables, `CapWords` classes, `UPPER_SNAKE_CASE` constants. Keep Flask route handlers and helpers in `server/app.py` and database models in `server/models.py`. Jinja templates belong in `server/templates/`. If using optional tooling from dev deps, format with `uv run black .` and lint with `uv run ruff check .`.

## Testing Guidelines
Tests are written with pytest. New tests should go in `tests/` and follow `test_*.py` naming. Use shared fixtures in `tests/conftest.py`. For focused runs: `uv run pytest tests/test_app.py`. Cover auth, CSRF, RBAC, and rate limiting behavior when adding or changing related logic.

## Commit & Pull Request Guidelines
Recent history uses short, descriptive subjects with occasional prefixes like `(feat)` or `(fix)` and PR/issue references (e.g., `(#18)`). Follow that pattern: concise summary, optional prefix, and include a reference when applicable. PRs should include: a clear description, steps to test, any config or env var changes, and screenshots for UI changes.

## Security & Configuration Tips
Set required env vars (`SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`) before running. Do not commit secrets; use `.env` for Docker runs. Uploads default to `recordings/` and may need correct UID/GID via `UPLOAD_UID`/`UPLOAD_GID` in deployment setups.
