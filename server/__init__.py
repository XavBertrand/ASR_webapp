import os

# Avoid auto-instantiation when tests are collecting modules
if "PYTEST_CURRENT_TEST" in os.environ:
    os.environ.setdefault("ASR_WEBAPP_SKIP_AUTOAPP", "1")

from server.app import create_app

if os.environ.get("ASR_WEBAPP_SKIP_AUTOAPP") != "1":
    app = create_app()
else:
    app = None

__all__ = ["create_app", "app"]
