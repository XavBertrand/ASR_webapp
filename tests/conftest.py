import os

# Evite l'auto-création de l'app Flask pendant l'import des modules en tests
os.environ.setdefault("ASR_WEBAPP_SKIP_AUTOAPP", "1")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
