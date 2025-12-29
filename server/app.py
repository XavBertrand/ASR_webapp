from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import (
    Flask,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
    current_app,
)
from flask_limiter import Limiter
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_

from server.models import AuditLog, PasswordResetToken, RecoveryCode, User, db
from server.security import (
    decrypt_secret,
    encrypt_secret,
    generate_recovery_codes,
    generate_totp_secret,
    hash_password,
    hash_recovery_codes,
    needs_rehash,
    safe_json,
    totp_from_secret,
    verify_password,
    verify_recovery_code_hash,
    make_fernet,
)


logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
DEFAULT_UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", str(ROOT_DIR / "recordings"))
DEFAULT_REPORTS_ROOT = os.environ.get("REPORTS_ROOT") or os.environ.get("RECORDINGS_DIR") or DEFAULT_UPLOAD_FOLDER
DEFAULT_REPORTS_QUEUE_DIR = os.environ.get("REPORTS_QUEUE_DIR") or os.environ.get("ASR_QUEUE_DIR")
if not DEFAULT_REPORTS_QUEUE_DIR:
    DEFAULT_REPORTS_QUEUE_DIR = str(Path(DEFAULT_REPORTS_ROOT) / "queue")
DEFAULT_WEBAPP_PYPROJECT = ROOT_DIR / "pyproject.toml"
DEFAULT_ACTION_PYPROJECT = ROOT_DIR / "pyproject_action_avocats.toml"
DEFAULT_JETSON_VERSION_FILE = Path(DEFAULT_UPLOAD_FOLDER) / ".asr_versions" / "asr_jetson.txt"
ALLOWED_EXTENSIONS = {"webm", "wav", "mp3", "ogg", "m4a", "mp4"}
DEFAULT_MAX_MB = int(os.environ.get("MAX_CONTENT_LENGTH_MB", "100"))
DEFAULT_DB_URI = os.environ.get("DATABASE_URL", f"sqlite:///{ROOT_DIR / 'app.db'}")
DEFAULT_SAME_SITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
WEBAPP_ENV = os.environ.get("WEBAPP_ENV", "").lower()
SESSION_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() != "false"
REQUIRE_ADMIN_2FA = os.environ.get("REQUIRE_ADMIN_2FA", "false").lower() == "true"
TOTP_ENC_KEY = os.environ.get("TOTP_ENC_KEY")
DEFAULT_RESET_TOKEN_TTL_MINUTES = 30

MAX_CONTENT_LENGTH = DEFAULT_MAX_MB * 1024 * 1024


def _parse_env_int(env_name: str) -> int | None:
    raw = os.environ.get(env_name)
    if raw is None or raw == "":
        return None
    try:
        return int(raw, 10)
    except ValueError:
        logger.warning("%s doit être un entier, valeur ignorée: %r", env_name, raw)
        return None


def _env_bool(env_name: str, default: bool = False) -> bool:
    raw = os.environ.get(env_name)
    if raw is None or raw == "":
        return default
    return str(raw).lower() not in {"0", "false", "no", "off"}


def _read_pyproject_version(path: Path) -> str | None:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return None
    in_project = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_project = line == "[project]"
            continue
        if in_project:
            match = re.match(r'version\s*=\s*["\']([^"\']+)["\']', line)
            if match:
                return match.group(1).strip()
    return None


def _read_version_file(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def _resolve_version(default_path: Path | None, env_version: str, env_path: str) -> str | None:
    if env_version:
        return env_version
    path = Path(env_path) if env_path else default_path
    if not path:
        return None
    if not path.is_absolute():
        path = (ROOT_DIR / path).resolve()
    if not path.exists():
        return None
    return _read_pyproject_version(path)


ENV_UPLOAD_UID = _parse_env_int("UPLOAD_UID")
ENV_UPLOAD_GID = _parse_env_int("UPLOAD_GID")

DEFAULT_MEETING_REPORT_LABELS: dict[str, str] = {
    "entretien_collaborateur": "Entretien collaborateur",
    "entretien_client_particulier_contentieux": "Client particulier (contentieux)",
    "entretien_client_professionnel_conseil": "Client professionnel (conseil)",
    "entretien_client_professionnel_contentieux": "Client professionnel (contentieux)",
}
_PROMPTS_CACHE: dict[str, Any] = {}
_PROMPTS_MTIME: float | None = None


def _resolve_prompts_path() -> Path | None:
    config_dir = os.environ.get("ASR_CONFIG_DIR", "").strip()
    if not config_dir:
        return None
    path = Path(config_dir).expanduser() / "mistral_prompts.json"
    if not path.is_absolute():
        path = (ROOT_DIR / path).resolve()
    return path


def _load_prompts_data() -> dict[str, Any]:
    global _PROMPTS_CACHE, _PROMPTS_MTIME
    path = _resolve_prompts_path()
    if not path or not path.exists():
        return {}
    try:
        mtime = path.stat().st_mtime
        if _PROMPTS_CACHE and _PROMPTS_MTIME == mtime:
            return _PROMPTS_CACHE
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            _PROMPTS_CACHE = data
            _PROMPTS_MTIME = mtime
            return data
    except Exception as exc:
        logger.warning("Impossible de lire les prompts Mistral (%s): %s", path, exc)
    return {}


def _humanize_prompt_key(key: str) -> str:
    cleaned = re.sub(r"[_\\s]+", " ", key).strip()
    return cleaned[:1].upper() + cleaned[1:] if cleaned else key


def get_meeting_report_types() -> list[dict[str, str]]:
    prompts = _load_prompts_data()
    if prompts:
        types: list[dict[str, str]] = []
        for key, payload in prompts.items():
            if not isinstance(key, str):
                continue
            label = None
            if isinstance(payload, dict):
                label = payload.get("label") or payload.get("title")
            label = label or DEFAULT_MEETING_REPORT_LABELS.get(key) or _humanize_prompt_key(key)
            types.append({"key": key, "label": label})
        if types:
            return types
    return [{"key": key, "label": label} for key, label in DEFAULT_MEETING_REPORT_LABELS.items()]

def resolve_upload_owner(base_dir: str) -> tuple[int, int]:
    """Return the uid/gid to apply on uploaded files."""
    st = os.stat(base_dir)
    uid = ENV_UPLOAD_UID if ENV_UPLOAD_UID is not None else st.st_uid
    gid = ENV_UPLOAD_GID if ENV_UPLOAD_GID is not None else st.st_gid
    return uid, gid


def apply_upload_permissions(path: str, *, is_dir: bool, base_dir: str | None = None) -> None:
    """Best-effort chown/chmod so uploads stay writable by the host user/group."""
    base = base_dir or (path if is_dir else str(Path(path).parent))
    uid, gid = resolve_upload_owner(base)
    try:
        os.chown(path, uid, gid)
    except PermissionError:
        logger.debug("Pas de droits suffisants pour chown %s", path)
    except OSError as exc:
        logger.warning("Impossible de chown %s: %s", path, exc)

    try:
        if is_dir:
            os.chmod(path, 0o2775)  # setgid pour hériter du groupe + g+w
        else:
            os.chmod(path, 0o664)
    except OSError as exc:
        logger.warning("Impossible de chmod %s: %s", path, exc)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def report_path_allowed(user: User, fname: str) -> bool:
    if not fname.lower().endswith(".pdf"):
        return False
    parts = Path(fname).parts
    if len(parts) < 4:
        return False
    if parts[1] != "output" or parts[2] != "pdf":
        return False
    if user.role == "admin":
        return True
    safe_username = secure_filename(user.username).strip("._")
    return parts[0] == safe_username


def run_path_allowed(user: User, fname: str) -> bool:
    parts = Path(fname).parts
    if len(parts) < 3:
        return False
    if parts[1] != "runs":
        return False
    if user.role == "admin":
        return True
    safe_username = secure_filename(user.username).strip("._")
    return parts[0] == safe_username


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _coerce_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso_from_epoch(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso_timestamp(value: str | None) -> float | None:
    if not value:
        return None
    try:
        cleaned = value[:-1] + "+00:00" if value.endswith("Z") else value
        return datetime.fromisoformat(cleaned).timestamp()
    except ValueError:
        return None


def _queue_status(meta_path: Path, queue_dir: Path | None) -> str | None:
    if not queue_dir:
        return None
    try:
        rel = meta_path.relative_to(queue_dir)
    except ValueError:
        return None
    if not rel.parts:
        return None
    head = rel.parts[0]
    if head in {"pending", "processing", "done", "failed"}:
        return head
    return None


def _load_meta(meta_path: Path) -> dict[str, Any] | None:
    try:
        with meta_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        logger.warning("Impossible de lire le metadata: %s", meta_path)
        return None


def _load_manifest(manifest_path: Path) -> dict[str, Any] | None:
    try:
        with manifest_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        logger.warning("Impossible de lire le manifest: %s", manifest_path)
        return None


def _is_safe_run_id(run_id: str) -> bool:
    if not run_id:
        return False
    parts = Path(run_id).parts
    if len(parts) != 1:
        return False
    if parts[0] in {".", ".."}:
        return False
    return True


def _update_run_metadata(run_root: Path, *, user_folder: str, old_run_id: str, new_run_id: str) -> None:
    old_root = str(Path(user_folder) / "runs" / old_run_id)
    new_root = str(Path(user_folder) / "runs" / new_run_id)
    manifest_path = run_root / "manifest.json"
    manifest = _load_manifest(manifest_path) if manifest_path.exists() else None
    if isinstance(manifest, dict):
        manifest["run_id"] = new_run_id
        manifest["run_root"] = new_root
        manifest["updated_at"] = _utcnow().isoformat().replace("+00:00", "Z")
        artifacts = manifest.get("artifacts")
        if isinstance(artifacts, list) and old_root != new_root:
            for entry in artifacts:
                path_value = entry.get("path") if isinstance(entry, dict) else None
                if not isinstance(path_value, str):
                    continue
                if path_value == old_root or path_value.startswith(old_root + "/"):
                    entry["path"] = new_root + path_value[len(old_root):]
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    meta_path = run_root / "meta.json"
    meta = _load_meta(meta_path) if meta_path.exists() else None
    if isinstance(meta, dict):
        meta["run_id"] = new_run_id
        if "run_root" in meta:
            meta["run_root"] = new_root
        meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def _set_run_case_name(run_root: Path, case_name: str | None) -> None:
    normalized = (case_name or "").strip()
    case_value = normalized or None

    manifest_path = run_root / "manifest.json"
    manifest = _load_manifest(manifest_path) if manifest_path.exists() else None
    if isinstance(manifest, dict):
        meta = manifest.get("meta")
        if not isinstance(meta, dict):
            meta = {}
        if case_value:
            meta["case_name"] = case_value
        else:
            meta.pop("case_name", None)
        manifest["meta"] = meta
        manifest["updated_at"] = _utcnow().isoformat().replace("+00:00", "Z")
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    meta_path = run_root / "meta.json"
    meta = _load_meta(meta_path) if meta_path.exists() else None
    if isinstance(meta, dict):
        if case_value:
            meta["case_name"] = case_value
        else:
            meta.pop("case_name", None)
        meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def _collect_run_entries(
    runs_root: Path,
    root: Path,
    *,
    allow_downloads: bool,
    status_override: str | None = None,
    include_trash_time: bool = False,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if not runs_root.is_dir():
        return items

    for manifest_path in runs_root.glob("*/manifest.json"):
        manifest = _load_manifest(manifest_path)
        if not manifest:
            continue
        run_id = manifest.get("run_id") or manifest_path.parent.name
        meta = manifest.get("meta") or {}
        audio = manifest.get("audio") or {}
        artifacts = manifest.get("artifacts") or []
        raw_case_name = meta.get("case_name")
        case_name = raw_case_name.strip() if isinstance(raw_case_name, str) else ""

        artifact_entries: list[dict[str, Any]] = []
        pdf_entry: dict[str, Any] | None = None
        for artifact in artifacts:
            path_value = artifact.get("path")
            if not isinstance(path_value, str):
                continue
            path_obj = Path(path_value)
            full_path = path_obj if path_obj.is_absolute() else (root / path_obj)
            exists = full_path.is_file()
            mtime_iso = None
            if exists:
                try:
                    mtime_iso = _iso_from_epoch(full_path.stat().st_mtime)
                except OSError:
                    mtime_iso = None
            rel_path = path_value if not path_obj.is_absolute() else None
            entry = {
                "path": path_value,
                "name": artifact.get("name") or full_path.name,
                "category": artifact.get("category"),
                "size": artifact.get("size"),
                "mtime": mtime_iso or artifact.get("mtime"),
                "exists": exists,
                "download_url": f"/runs/{rel_path}" if allow_downloads and rel_path else None,
            }
            artifact_entries.append(entry)
            if path_value.lower().endswith(".pdf"):
                if not pdf_entry or (entry.get("mtime") or "") > (pdf_entry.get("mtime") or ""):
                    pdf_entry = entry

        status = manifest.get("status") or "ready"
        if status == "ready" and (not pdf_entry or not pdf_entry.get("exists")):
            status = "missing"
        if status_override:
            status = status_override

        created_at = manifest.get("created_at") or meta.get("uploaded_at")
        if not created_at:
            try:
                created_at = _iso_from_epoch(manifest_path.stat().st_mtime)
            except OSError:
                created_at = None

        trashed_at = None
        if include_trash_time:
            try:
                trashed_at = _iso_from_epoch(manifest_path.parent.stat().st_mtime)
            except OSError:
                trashed_at = None

        audio_path = audio.get("path")
        audio_url = None
        audio_exists = False
        if isinstance(audio_path, str) and not Path(audio_path).is_absolute():
            audio_full = root / audio_path
            audio_exists = audio_full.is_file()
            if audio_exists and allow_downloads:
                audio_url = f"/recordings/{audio_path}"

        items.append(
            {
                "id": run_id,
                "run_id": run_id,
                "display_name": case_name
                or audio.get("original_filename")
                or audio.get("saved_filename")
                or run_id,
                "case_name": case_name or None,
                "meeting_date": meta.get("meeting_date"),
                "meeting_report_type": meta.get("meeting_report_type"),
                "uploaded_at": created_at,
                "trashed_at": trashed_at,
                "status": "missing" if status == "ready" and (not audio_exists) else status,
                "status_reason": (manifest.get("error") or {}).get("message"),
                "report_filename": pdf_entry.get("name") if pdf_entry else None,
                "report_created_at": pdf_entry.get("mtime") if pdf_entry else None,
                "download_url": pdf_entry.get("download_url") if pdf_entry else None,
                "audio_url": audio_url,
                "artifacts": artifact_entries,
            }
        )

    return items


def wants_json_response() -> bool:
    if request.is_json:
        return True
    best = request.accept_mimetypes.best_match(["application/json", "text/html"])
    return best == "application/json" and request.accept_mimetypes[best] > request.accept_mimetypes["text/html"]


def json_error(message: str, code: int) -> Any:
    return jsonify({"error": message}), code


def client_ip() -> str:
    trust_proxy = False
    if current_app:
        trust_proxy = bool(current_app.config.get("TRUST_PROXY_HEADERS"))
    if trust_proxy:
        if request.access_route:
            return request.access_route[0]
        if request.remote_addr:
            return request.remote_addr
        return ""
    return request.remote_addr or ""


def _limiter_key_func() -> str:
    return client_ip()


limiter = Limiter(key_func=_limiter_key_func)


def ensure_dirs(app: Flask) -> None:
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    apply_upload_permissions(app.config["UPLOAD_FOLDER"], is_dir=True, base_dir=app.config["UPLOAD_FOLDER"])
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite:///"):
        db_path = Path(app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "", 1))
        if db_path.parent:
            os.makedirs(db_path.parent, exist_ok=True)


def apply_sqlite_schema_fixes(app: Flask) -> None:
    uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if not uri.startswith("sqlite"):
        return
    engine = db.engine

    def has_column(conn, table: str, column: str) -> bool:
        res = conn.exec_driver_sql(f"PRAGMA table_info({table})")
        return any(row[1] == column for row in res)

    with engine.begin() as conn:
        try:
            if not has_column(conn, "users", "email"):
                conn.exec_driver_sql("ALTER TABLE users ADD COLUMN email VARCHAR(255)")
            if not has_column(conn, "users", "email_verified"):
                conn.exec_driver_sql("ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT 0")
                conn.exec_driver_sql("UPDATE users SET email_verified = 0 WHERE email_verified IS NULL")
            conn.exec_driver_sql(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email) WHERE email IS NOT NULL"
            )
        except Exception as exc:
            logger.warning("Impossible d'appliquer les migrations SQLite: %s", exc)


def require_secret_key(app: Flask) -> None:
    if app.config.get("SECRET_KEY"):
        return
    if app.config.get("TESTING"):
        app.config["SECRET_KEY"] = "test-secret-key"
        return
    raise RuntimeError("SECRET_KEY est obligatoire en production")


def create_app(test_config: dict | None = None) -> Flask:
    trust_proxy_headers = os.environ.get("TRUST_PROXY_HEADERS", "false").lower() == "true"
    ratelimit_storage = os.environ.get("RATELIMIT_STORAGE_URL", "memory://")
    scheme = ratelimit_storage.split("://", 1)[0]
    if scheme.startswith("redis"):
        try:
            import redis  # type: ignore # noqa: F401
        except ImportError:
            logger.warning(
                "Limiter backend %s demandé mais le client redis n'est pas installé — fallback sur memory://",
                ratelimit_storage,
            )
            ratelimit_storage = "memory://"
    webapp_env = os.environ.get("WEBAPP_ENV", WEBAPP_ENV).lower()

    app = Flask(
        __name__,
        static_folder=str(ROOT_DIR / "webapp"),
        static_url_path="",
        template_folder=str(BASE_DIR / "templates"),
    )

    reset_ttl = _parse_env_int("RESET_TOKEN_TTL_MINUTES") or DEFAULT_RESET_TOKEN_TTL_MINUTES
    mail_port = _parse_env_int("MAIL_PORT") or 587
    mail_use_tls = _env_bool("MAIL_USE_TLS", True)
    app.config.update(
        UPLOAD_FOLDER=DEFAULT_UPLOAD_FOLDER,
        REPORTS_ROOT=DEFAULT_REPORTS_ROOT,
        REPORTS_QUEUE_DIR=DEFAULT_REPORTS_QUEUE_DIR,
        MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
        SQLALCHEMY_DATABASE_URI=DEFAULT_DB_URI,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        SESSION_COOKIE_SECURE=SESSION_SECURE,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=DEFAULT_SAME_SITE,
        PREFERRED_URL_SCHEME="https",
        REQUIRE_ADMIN_2FA=REQUIRE_ADMIN_2FA,
        TRUST_PROXY_HEADERS=trust_proxy_headers,
        WEBAPP_ENV=webapp_env,
        RATELIMIT_STORAGE_URL=ratelimit_storage,
        RATELIMIT_STORAGE_URI=ratelimit_storage,
        RESET_TOKEN_TTL_MINUTES=reset_ttl,
        MAIL_HOST=os.environ.get("MAIL_HOST"),
        MAIL_PORT=mail_port,
        MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
        MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
        MAIL_FROM=os.environ.get("MAIL_FROM"),
        MAIL_USE_TLS=mail_use_tls,
        PERMANENT_SESSION_LIFETIME=timedelta(
            hours=int(os.environ.get("SESSION_LIFETIME_HOURS", "12"))
        ),
        SKIP_BOOTSTRAP_ADMIN=False,
    )
    if test_config:
        app.config.update(test_config)

    if app.config.get("TRUST_PROXY_HEADERS"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    require_secret_key(app)

    db.init_app(app)
    limiter.init_app(app)
    env_markers = [
        app.config.get("WEBAPP_ENV") or "",
        os.environ.get("FLASK_ENV", ""),
        os.environ.get("APP_ENV", ""),
    ]
    env_markers = [e.lower() for e in env_markers if e]
    if app.config["RATELIMIT_STORAGE_URL"] == "memory://" and ("production" in env_markers or "prod" in env_markers):
        logger.warning("Limiter not shared across workers (memory backend). Configure RATELIMIT_STORAGE_URL=redis://...")
    app.config["TOTP_FERNET"] = make_fernet(TOTP_ENC_KEY)

    ensure_dirs(app)
    register_routes(app)
    with app.app_context():
        db.create_all()
        apply_sqlite_schema_fixes(app)
        if not app.config.get("SKIP_BOOTSTRAP_ADMIN"):
            bootstrap_admin(app)
    return app


def bootstrap_admin(app: Flask) -> None:
    admin_exists = User.query.filter_by(role="admin").first()
    if admin_exists:
        return
    username = os.environ.get("ADMIN_USERNAME")
    password = os.environ.get("ADMIN_PASSWORD")
    if not username or not password:
        raise RuntimeError("ADMIN_USERNAME et ADMIN_PASSWORD sont requis pour le bootstrap initial")
    if len(password) < 12:
        raise RuntimeError("ADMIN_PASSWORD doit contenir au moins 12 caractères")
    password_hash = hash_password(password)
    admin = User(username=username.strip(), password_hash=password_hash, role="admin", is_active=True)
    db.session.add(admin)
    db.session.commit()
    log_action(
        action="bootstrap_admin",
        actor=None,
        target=admin,
        metadata={"username": admin.username},
        ip="bootstrap",
        user_agent=None,
    )
    logger.info("Admin bootstrap créé: %s", username)


def log_action(
    *,
    action: str,
    actor: User | None,
    target: User | None = None,
    metadata: dict | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    entry = AuditLog(
        action=action,
        actor_user_id=actor.id if actor else None,
        actor_username_snapshot=actor.username if actor else None,
        target_user_id=target.id if target else None,
        target_username_snapshot=target.username if target else None,
        ip=ip,
        user_agent=user_agent[:250] if user_agent else None,
        metadata_json=safe_json(metadata),
    )
    db.session.add(entry)
    db.session.commit()


def make_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    return token


def enforce_csrf() -> Any | None:
    token = session.get("csrf_token")
    sent = (
        request.headers.get("X-CSRF-Token")
        or (request.form.get("csrf_token") if request.form else None)
        or ((request.get_json(silent=True) or {}).get("csrf_token") if request.is_json else None)
    )
    if not token or not sent or not secrets.compare_digest(str(token), str(sent)):
        return json_error("CSRF token manquant ou invalide", 400)
    return None


def load_current_user() -> None | Any:
    g.current_user = None
    uid = session.get("user_id")
    if uid:
        user = User.query.get(uid)
        if user and user.is_active:
            g.current_user = user
        else:
            session.clear()
    g.csrf_token = make_csrf_token()
    if request.method in {"POST", "PUT", "DELETE"}:
        resp = enforce_csrf()
        if resp:
            return resp
    if request.endpoint == "static" and request.path.endswith("index.html") and not g.current_user:
        return redirect(url_for("login"))
    return None


def persist_csrf_cookie(response):
    secure = current_app.config.get("SESSION_COOKIE_SECURE", True)
    same_site = current_app.config.get("SESSION_COOKIE_SAMESITE", "Lax")
    response.set_cookie(
        "csrf_token",
        g.get("csrf_token") or session.get("csrf_token") or "",
        secure=secure,
        httponly=False,
        samesite=same_site,
        max_age=int(timedelta(days=7).total_seconds()),
    )
    return response


def apply_security_headers(response):
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'"
    )
    response.headers.setdefault("Content-Security-Policy", csp)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(self), camera=()")
    return response


def mail_settings(app: Flask) -> dict | None:
    host = app.config.get("MAIL_HOST")
    if not host:
        return None
    return {
        "host": host,
        "port": app.config.get("MAIL_PORT") or 587,
        "username": app.config.get("MAIL_USERNAME"),
        "password": app.config.get("MAIL_PASSWORD"),
        "sender": app.config.get("MAIL_FROM") or app.config.get("MAIL_USERNAME") or "no-reply@example.com",
        "use_tls": bool(app.config.get("MAIL_USE_TLS")),
    }


def send_password_reset_email(app: Flask, user: User, reset_url: str) -> str:
    cfg = mail_settings(app)
    if not cfg:
        logger.warning("PASSWORD RESET LINK for %s: %s", user.username, reset_url)
        return "log"
    if not user.email:
        logger.warning("PASSWORD RESET LINK (no email) for %s: %s", user.username, reset_url)
        return "no_email"
    msg = EmailMessage()
    msg["Subject"] = "ASR WebApp - Réinitialisation du mot de passe"
    msg["From"] = cfg["sender"]
    msg["To"] = user.email
    msg.set_content(
        f"Bonjour {user.username},\n\n"
        "Un lien de réinitialisation de mot de passe a été demandé pour votre compte.\n"
        f"Si vous êtes à l'origine de cette demande, utilisez ce lien (valide pour une durée limitée) : {reset_url}\n\n"
        "Si vous n'êtes pas à l'origine de cette demande, ignorez ce message."
    )
    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as smtp:
            if cfg["use_tls"]:
                smtp.starttls()
            if cfg["username"]:
                smtp.login(cfg["username"], cfg.get("password") or "")
            smtp.send_message(msg)
        return "smtp"
    except Exception as exc:
        logger.error("Echec envoi email reset pour %s: %s", user.username, exc)
        logger.warning("PASSWORD RESET LINK for %s: %s", user.username, reset_url)
        return "error"


def hash_reset_token(raw_token: str) -> str:
    digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return digest


def generate_password_reset_token(user: User, ip: str | None, ua: str | None, ttl_minutes: int) -> tuple[str, PasswordResetToken]:
    ttl = max(int(ttl_minutes), 1)
    expires_at = _utcnow() + timedelta(minutes=ttl)
    attempt = 0
    while attempt < 3:
        attempt += 1
        raw_token = secrets.token_urlsafe(32)
        token_hash = hash_reset_token(raw_token)
        record = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            request_ip=ip,
            request_user_agent=(ua[:250] if ua else None),
        )
        db.session.add(record)
        try:
            db.session.commit()
            return raw_token, record
        except IntegrityError:
            db.session.rollback()
    raise RuntimeError("Impossible de générer un jeton de réinitialisation unique")


def find_valid_reset_token(raw_token: str) -> PasswordResetToken | None:
    if not raw_token:
        return None
    token_hash = hash_reset_token(raw_token)
    now = _utcnow()
    token = (
        PasswordResetToken.query.filter_by(token_hash=token_hash, used_at=None)
        .filter(PasswordResetToken.expires_at > now)
        .first()
    )
    if not token:
        return None
    if not secrets.compare_digest(token_hash, token.token_hash):
        return None
    return token


def invalidate_user_tokens(user_id: int) -> None:
    now = _utcnow()
    PasswordResetToken.query.filter(
        PasswordResetToken.user_id == user_id, PasswordResetToken.used_at.is_(None)
    ).update({"used_at": now})
    db.session.commit()


def validate_new_password(password: str, role: str) -> str | None:
    if role == "admin" and len(password) < 12:
        return "Le mot de passe admin doit contenir au moins 12 caractères"
    if len(password) < 8:
        return "Le mot de passe doit contenir au moins 8 caractères"
    return None


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(raw: str | None) -> str | None:
    if raw is None:
        return None
    cleaned = raw.strip().lower()
    return cleaned or None


def mask_email(email: str | None) -> str | None:
    if not email:
        return None
    try:
        local, domain = email.split("@", 1)
    except ValueError:
        return "***"
    local_mask = (local[0] + "***") if local else "***"
    domain_parts = domain.split(".")
    if len(domain_parts) >= 2:
        domain_mask = "***." + domain_parts[-1]
    else:
        domain_mask = "***"
    return f"{local_mask}@{domain_mask}"


def login_required(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not getattr(g, "current_user", None):
            if wants_json_response():
                return json_error("Authentication required", 401)
            return redirect(url_for("login", next=request.path))
        if not g.current_user.is_active:
            session.clear()
            return json_error("Compte inactif", 403)
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not getattr(g, "current_user", None):
            if wants_json_response():
                return json_error("Authentication required", 401)
            return redirect(url_for("login", next=request.path))
        if g.current_user.role != "admin":
            return json_error("Accès réservé aux administrateurs", 403)
        if g.current_user.twofa_enabled and not session.get("twofa_verified"):
            session.clear()
            if wants_json_response():
                return json_error("OTP requis, reconnectez-vous", 401)
            return redirect(url_for("login"))
        if current_app_requires_2fa() and not g.current_user.twofa_enabled:
            if wants_json_response():
                return json_error("Activation 2FA requise pour l'admin", 403)
            return redirect(url_for("admin_2fa_setup"))
        return fn(*args, **kwargs)

    return wrapper


def current_app_requires_2fa() -> bool:
    return bool(current_app.config.get("REQUIRE_ADMIN_2FA"))


def rotation_session(user: User, *, otp_validated: bool) -> None:
    session.clear()
    session["user_id"] = user.id
    session["username"] = user.username
    session["role"] = user.role
    session["twofa_verified"] = otp_validated or not (user.role == "admin" and user.twofa_enabled)
    session["csrf_token"] = secrets.token_hex(16)
    session.permanent = True


def current_user_folder() -> str:
    username = ""
    if getattr(g, "current_user", None):
        username = g.current_user.username
    safe = secure_filename(username).strip("._")
    return safe or "anonymous"


def user_can_access_path(user: User, fname: str) -> bool:
    if user.role == "admin":
        return True
    safe_username = secure_filename(user.username).strip("._")
    return fname.startswith(f"{safe_username}/")


def register_routes(app: Flask) -> None:
    app.before_request(load_current_user)
    app.after_request(apply_security_headers)
    app.after_request(persist_csrf_cookie)

    @app.errorhandler(429)
    def handle_ratelimit(exc):
        message = "Trop de requêtes, réessayez plus tard."
        if wants_json_response():
            return json_error(message, 429)
        csrf = getattr(g, "csrf_token", None) or session.get("csrf_token") or make_csrf_token()
        template = "login.html"
        context = {"error": message, "csrf_token": csrf, "show_otp": False}
        if request.path.startswith("/forgot-password"):
            template = "forgot_password.html"
            context = {"error": message, "csrf_token": csrf}
        elif request.path.startswith("/reset-password"):
            template = "reset_password.html"
            context = {"error": message, "csrf_token": csrf, "invalid": False}
        return render_template(template, **context), 429

    @app.get("/health")
    def health():
        return {"status": "ok"}, 200

    @app.get("/login")
    def login():
        if getattr(g, "current_user", None):
            return redirect(url_for("home"))
        message = None
        if request.args.get("reset") == "1":
            message = "Mot de passe mis à jour. Vous pouvez vous connecter."
        return render_template("login.html", csrf_token=g.csrf_token, show_otp=False, message=message)

    @app.post("/login")
    @limiter.limit("5/minute;20/hour")
    def handle_login():
        data = request.form if request.form else request.get_json(silent=True) or {}
        as_form = bool(request.form)

        def login_error(msg: str, status: int, *, show_otp: bool = False):
            if wants_json_response() or not as_form:
                return json_error(msg, status)
            return render_template("login.html", error=msg, csrf_token=g.csrf_token, show_otp=show_otp), status

        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        otp = (data.get("otp") or "").strip()
        user = User.query.filter_by(username=username).first()
        ip = client_ip()
        ua = request.headers.get("User-Agent")

        if not user or not verify_password(user.password_hash, password):
            log_action(action="login_failed", actor=user, metadata={"reason": "bad_credentials"}, ip=ip, user_agent=ua)
            return login_error("Identifiants invalides", 401)
        if not user.is_active:
            log_action(action="login_failed", actor=user, metadata={"reason": "inactive"}, ip=ip, user_agent=ua)
            return login_error("Compte inactif", 403)

        otp_validated = False
        if user.role == "admin" and user.twofa_enabled:
            secret = decrypt_secret(user.totp_secret, app.config["TOTP_FERNET"])
            if not secret:
                return login_error("Secret TOTP introuvable, contactez un administrateur", 500)
            totp = totp_from_secret(secret)
            if otp and totp.verify(otp, valid_window=1):
                otp_validated = True
            else:
                # recovery codes
                if otp:
                    code = RecoveryCode.query.filter_by(user_id=user.id, used_at=None).all()
                    matched = None
                    for rc in code:
                        if verify_recovery_code_hash(rc.code_hash, otp):
                            matched = rc
                            break
                    if matched:
                        matched.used_at = _utcnow()
                        db.session.commit()
                        otp_validated = True
                        log_action(
                            action="recovery_code_used",
                            actor=user,
                            target=user,
                            metadata={"recovery_code_id": matched.id},
                            ip=ip,
                            user_agent=ua,
                        )
                if not otp_validated:
                    log_action(action="login_failed", actor=user, metadata={"reason": "otp_required"}, ip=ip, user_agent=ua)
                    return login_error("OTP requis ou invalide", 401, show_otp=True)

        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
            db.session.commit()

        rotation_session(user, otp_validated=otp_validated)
        user.last_login_at = _utcnow()
        db.session.commit()
        log_action(action="login_success", actor=user, ip=ip, user_agent=ua)

        if wants_json_response():
            return jsonify({"ok": True, "next": url_for("home")})
        return redirect(url_for("home"))

    @app.get("/forgot-password")
    def forgot_password_form():
        if getattr(g, "current_user", None):
            return redirect(url_for("home"))
        return render_template("forgot_password.html", csrf_token=g.csrf_token)

    @app.post("/forgot-password")
    @limiter.limit("5/minute;20/hour")
    def forgot_password():
        data = request.form if request.form else request.get_json(silent=True) or {}
        as_form = bool(request.form)
        identifier = (data.get("identifier") or "").strip()
        ip = client_ip()
        ua = request.headers.get("User-Agent")
        user = None
        if identifier:
            normalized_email = identifier.lower()
            user = User.query.filter(or_(User.username == identifier, User.email == normalized_email)).first()

        delivery = None
        if user and user.is_active:
            try:
                raw_token, _ = generate_password_reset_token(
                    user, ip, ua, app.config.get("RESET_TOKEN_TTL_MINUTES", DEFAULT_RESET_TOKEN_TTL_MINUTES)
                )
                reset_url = url_for("reset_password_form", token=raw_token, _external=True)
                delivery = send_password_reset_email(app, user, reset_url)
            except Exception as exc:
                logger.error("Erreur lors de la génération ou de l'envoi du lien de réinitialisation: %s", exc)
                delivery = "error"

        metadata = {"found": bool(user and user.is_active)}
        if user and user.is_active and delivery:
            metadata["delivery"] = delivery
        log_action(
            action="password_reset_requested",
            actor=None,
            target=user if (user and user.is_active) else None,
            metadata=metadata,
            ip=ip,
            user_agent=ua,
        )

        message = "Si un compte correspond, un lien de réinitialisation a été envoyé."
        if wants_json_response() or not as_form:
            return jsonify({"ok": True, "message": message})
        return render_template("forgot_password.html", csrf_token=g.csrf_token, message=message)

    @app.get("/reset-password/<token>")
    def reset_password_form(token: str):
        token_row = find_valid_reset_token(token)
        if not token_row or not token_row.user or not token_row.user.is_active:
            return render_template("reset_password.html", invalid=True, csrf_token=g.csrf_token), 400
        return render_template("reset_password.html", csrf_token=g.csrf_token, invalid=False, token=token)

    @app.post("/reset-password/<token>")
    @limiter.limit("5/minute")
    def reset_password_submit(token: str):
        data = request.form if request.form else request.get_json(silent=True) or {}
        as_form = bool(request.form)
        ip = client_ip()
        ua = request.headers.get("User-Agent")
        token_row = find_valid_reset_token(token)

        def reset_error(msg: str, status: int = 400, *, invalid: bool = False):
            if wants_json_response() or not as_form:
                return json_error(msg, status)
            return render_template(
                "reset_password.html", csrf_token=g.csrf_token, error=msg, invalid=invalid, token=token
            ), status

        if not token_row or not token_row.user or not token_row.user.is_active:
            existing = PasswordResetToken.query.filter_by(token_hash=hash_reset_token(token)).first() if token else None
            reason = "invalid_or_expired"
            target_user = None
            if existing:
                target_user = existing.user
                if existing.used_at:
                    reason = "used"
                else:
                    expires_at = _coerce_utc(existing.expires_at)
                    if expires_at and expires_at <= _utcnow():
                        reason = "expired"
            log_action(
                action="password_reset_invalid_token",
                actor=None,
                target=target_user,
                metadata={
                    "reason": reason,
                    "token_id": existing.id if existing else None,
                    "token_suffix": token[-4:] if token else None,
                },
                ip=ip,
                user_agent=ua,
            )
            return reset_error("Lien invalide ou expiré", 400, invalid=True)

        password = data.get("password") or data.get("new_password") or ""
        confirm = data.get("confirm_password") or data.get("confirm") or ""
        error_msg = validate_new_password(password, token_row.user.role)
        if error_msg:
            return reset_error(error_msg, 400)
        if password != confirm:
            return reset_error("La confirmation ne correspond pas", 400)

        token_row.user.password_hash = hash_password(password)
        invalidate_user_tokens(token_row.user_id)
        log_action(
            action="password_reset_success",
            actor=None,
            target=token_row.user,
            metadata={"token_id": token_row.id},
            ip=ip,
            user_agent=ua,
        )
        if wants_json_response() or not as_form:
            return jsonify({"ok": True, "next": url_for("login")})
        return redirect(url_for("login", reset="1"))

    @app.post("/logout")
    @login_required
    def logout():
        user = g.current_user
        ip = client_ip()
        ua = request.headers.get("User-Agent")
        session.clear()
        log_action(action="logout", actor=user, ip=ip, user_agent=ua)
        if wants_json_response():
            return jsonify({"ok": True})
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def home():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/index.html")
    @login_required
    def index_html():
        return send_from_directory(app.static_folder, "index.html")

    @app.post("/upload")
    @login_required
    def upload():
        if "file" not in request.files:
            return jsonify({"error": "Aucun fichier dans la requête"}), 400
        f = request.files["file"]
        if f.filename == "":
            return jsonify({"error": "Nom de fichier vide"}), 400
        if not allowed_file(f.filename):
            return jsonify({"error": f"Extension non autorisée. Autorisées: {sorted(ALLOWED_EXTENSIONS)}"}), 400
        stem, ext = os.path.splitext(secure_filename(f.filename))
        ts = _utcnow().strftime("%Y%m%dT%H%M%SZ")
        safe_name = f"{stem}_{ts}{ext.lower()}"
        user_folder = current_user_folder()
        user_dir = os.path.join(app.config["UPLOAD_FOLDER"], user_folder)
        os.makedirs(user_dir, exist_ok=True)
        apply_upload_permissions(user_dir, is_dir=True, base_dir=app.config["UPLOAD_FOLDER"])
        save_path = os.path.join(user_dir, safe_name)
        try:
            metadata = extract_metadata(request.form)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        f.save(save_path)
        apply_upload_permissions(save_path, is_dir=False, base_dir=app.config["UPLOAD_FOLDER"])
        metadata.update(
            {
                "saved_filename": safe_name,
                "saved_path": os.path.abspath(save_path),
                "user_folder": user_folder,
                "original_filename": f.filename,
                "uploaded_at": _utcnow().isoformat().replace("+00:00", "Z"),
            }
        )
        meta_path = os.path.join(user_dir, f"{stem}_{ts}_meta.json")
        with open(meta_path, "w", encoding="utf-8") as meta_file:
            json.dump(metadata, meta_file, ensure_ascii=False, indent=2)
        apply_upload_permissions(meta_path, is_dir=False, base_dir=app.config["UPLOAD_FOLDER"])

        logger.info("Upload OK: %s (%d bytes)", save_path, os.path.getsize(save_path))
        return jsonify({"ok": True, "filename": safe_name, "metadata": metadata}), 201

    @app.get("/recordings/<path:fname>")
    @login_required
    def serve_recording(fname):
        if not g.current_user or not user_can_access_path(g.current_user, fname):
            return json_error("Accès refusé", 403)
        return send_from_directory(app.config["UPLOAD_FOLDER"], fname)

    @app.get("/reports/<path:fname>")
    @login_required
    def serve_report(fname):
        if not g.current_user or not report_path_allowed(g.current_user, fname):
            return json_error("Accès refusé", 403)
        return send_from_directory(app.config["REPORTS_ROOT"], fname, as_attachment=True)

    @app.get("/runs/<path:fname>")
    @login_required
    def serve_run_artifact(fname):
        if not g.current_user or not run_path_allowed(g.current_user, fname):
            return json_error("Accès refusé", 403)
        return send_from_directory(app.config["REPORTS_ROOT"], fname, as_attachment=True)

    @app.get("/api/reports")
    @login_required
    def list_reports():
        user_folder = current_user_folder()
        root = Path(app.config["REPORTS_ROOT"]).expanduser()
        runs_root = root / user_folder / "runs"
        items = _collect_run_entries(runs_root, root, allow_downloads=True)

        items.sort(
            key=lambda entry: _parse_iso_timestamp(entry.get("uploaded_at")) or 0,
            reverse=True,
        )
        return jsonify(items)

    @app.post("/api/runs/<run_id>/rename")
    @login_required
    def rename_run(run_id: str):
        if not _is_safe_run_id(run_id):
            return json_error("Identifiant invalide", 400)
        payload = request.get_json(silent=True) or request.form or {}
        case_name = (payload.get("case_name") or "").strip()
        if len(case_name) > 160:
            return json_error("Nom du dossier trop long (max 160 caractères)", 400)
        user_folder = current_user_folder()
        root = Path(app.config["REPORTS_ROOT"]).expanduser()
        run_root = root / user_folder / "runs" / run_id
        if not run_root.is_dir():
            return json_error("Run introuvable", 404)
        _set_run_case_name(run_root, case_name or None)
        return jsonify({"ok": True, "case_name": case_name})

    @app.post("/api/runs/<run_id>/rerun-report")
    @login_required
    def rerun_report(run_id: str):
        if not _is_safe_run_id(run_id):
            return json_error("Identifiant invalide", 400)
        user_folder = current_user_folder()
        root = Path(app.config["REPORTS_ROOT"]).expanduser()
        run_root = root / user_folder / "runs" / run_id
        if not run_root.is_dir():
            return json_error("Run introuvable", 404)
        manifest_path = run_root / "manifest.json"
        manifest = _load_manifest(manifest_path) or {}
        status = manifest.get("status")
        if status != "ready":
            return json_error("Le run doit être prêt pour relancer le rapport", 409)

        meta_path = run_root / "meta.json"
        meta = _load_meta(meta_path)
        if not isinstance(meta, dict):
            return json_error("Metadata introuvable", 404)

        queue_dir_value = app.config.get("REPORTS_QUEUE_DIR") or ""
        if not queue_dir_value.strip():
            return json_error("File d'attente indisponible", 503)
        queue_dir = Path(queue_dir_value).expanduser()
        pending_dir = queue_dir / "pending"
        pending_dir.mkdir(parents=True, exist_ok=True)

        meta["run_id"] = run_id
        meta["user_folder"] = meta.get("user_folder") or user_folder
        meta["report_only"] = True

        stamp = _utcnow().strftime("%Y%m%dT%H%M%SZ")
        job_name = f"{stamp}_{secrets.token_hex(2)}_{run_id}_report_meta.json"
        job_path = pending_dir / job_name
        job_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        apply_upload_permissions(str(job_path), is_dir=False, base_dir=app.config["REPORTS_ROOT"])

        manifest["status"] = "queued"
        manifest["updated_at"] = _utcnow().isoformat().replace("+00:00", "Z")
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

        return jsonify({"ok": True})

    @app.get("/api/meeting-report-types")
    @login_required
    def meeting_report_types():
        types = get_meeting_report_types()
        default_key = types[0]["key"] if types else ""
        return jsonify({"types": types, "default": default_key})

    @app.post("/api/runs/<run_id>/trash")
    @login_required
    def trash_run(run_id: str):
        if not _is_safe_run_id(run_id):
            return json_error("Identifiant invalide", 400)
        user_folder = current_user_folder()
        root = Path(app.config["REPORTS_ROOT"]).expanduser()
        run_root = root / user_folder / "runs" / run_id
        if not run_root.is_dir():
            return json_error("Run introuvable", 404)
        manifest = _load_manifest(run_root / "manifest.json") or {}
        status = manifest.get("status")
        if status in {"queued", "processing"}:
            return json_error("Impossible de supprimer un run en cours", 409)
        trash_root = root / user_folder / "trash"
        trash_root.mkdir(parents=True, exist_ok=True)
        dest = trash_root / run_id
        if dest.exists():
            suffix = _utcnow().strftime("%Y%m%dT%H%M%SZ")
            dest = trash_root / f"{run_id}_{suffix}"
        shutil.move(str(run_root), str(dest))
        return jsonify({"ok": True, "trash_path": str(dest.relative_to(root))})

    @app.get("/api/trash")
    @login_required
    def list_trash():
        user_folder = current_user_folder()
        root = Path(app.config["REPORTS_ROOT"]).expanduser()
        trash_root = root / user_folder / "trash"
        items = _collect_run_entries(
            trash_root,
            root,
            allow_downloads=False,
            status_override="trashed",
            include_trash_time=True,
        )
        items.sort(
            key=lambda entry: _parse_iso_timestamp(entry.get("trashed_at")) or 0,
            reverse=True,
        )
        return jsonify(items)

    @app.post("/api/trash/<run_id>/restore")
    @login_required
    def restore_trash(run_id: str):
        if not _is_safe_run_id(run_id):
            return json_error("Identifiant invalide", 400)
        user_folder = current_user_folder()
        root = Path(app.config["REPORTS_ROOT"]).expanduser()
        trash_root = root / user_folder / "trash" / run_id
        if not trash_root.is_dir():
            return json_error("Run introuvable", 404)

        dest_root = root / user_folder / "runs"
        dest_root.mkdir(parents=True, exist_ok=True)
        dest = dest_root / run_id
        if dest.exists():
            suffix = _utcnow().strftime("%Y%m%dT%H%M%SZ")
            dest = dest_root / f"{run_id}_{suffix}"
        shutil.move(str(trash_root), str(dest))
        _update_run_metadata(dest, user_folder=user_folder, old_run_id=run_id, new_run_id=dest.name)
        return jsonify({"ok": True, "run_id": dest.name})

    @app.post("/api/trash/<run_id>/delete")
    @login_required
    def delete_trash(run_id: str):
        if not _is_safe_run_id(run_id):
            return json_error("Identifiant invalide", 400)
        user_folder = current_user_folder()
        root = Path(app.config["REPORTS_ROOT"]).expanduser()
        trash_root = root / user_folder / "trash" / run_id
        if not trash_root.is_dir():
            return json_error("Run introuvable", 404)
        shutil.rmtree(str(trash_root))
        return jsonify({"ok": True})

    @app.get("/admin/users")
    @admin_required
    def admin_users_page():
        users = User.query.order_by(User.created_at.desc()).all()
        return render_template("admin_users.html", users=users, csrf_token=g.csrf_token)

    @app.get("/api/admin/users")
    @admin_required
    def admin_users_list():
        users = User.query.order_by(User.created_at.desc()).all()
        return jsonify(
            [
                {
                    "id": u.id,
                    "username": u.username,
                    "email": u.email,
                    "role": u.role,
                    "is_active": u.is_active,
                    "twofa_enabled": u.twofa_enabled,
                    "email_verified": u.email_verified,
                    "created_at": u.created_at.isoformat() + "Z",
                    "updated_at": u.updated_at.isoformat() + "Z" if u.updated_at else None,
                }
                for u in users
            ]
        )

    @app.get("/api/me")
    @login_required
    def current_profile():
        user = g.current_user
        return jsonify(
            {
                "id": user.id,
                "username": user.username,
                "role": user.role,
                "is_active": user.is_active,
                "twofa_enabled": user.twofa_enabled,
            }
        )

    @app.get("/api/versions")
    @login_required
    def versions():
        webapp_env_version = os.environ.get("APP_VERSION", "").strip()
        if not webapp_env_version or webapp_env_version.lower() == "dev":
            webapp_env_version = os.environ.get("ASR_WEBAPP_VERSION", "").strip()
        jetson_file_override = os.environ.get("ASR_JETSON_VERSION_FILE", "").strip()
        if jetson_file_override:
            jetson_version_file = Path(jetson_file_override)
            if not jetson_version_file.is_absolute():
                jetson_version_file = (ROOT_DIR / jetson_version_file).resolve()
        else:
            jetson_version_file = DEFAULT_JETSON_VERSION_FILE
        return jsonify(
            {
                "webapp": webapp_env_version
                or _resolve_version(
                    DEFAULT_WEBAPP_PYPROJECT,
                    "",
                    os.environ.get("ASR_WEBAPP_PYPROJECT", "").strip(),
                ),
                "action_avocats": _resolve_version(
                    DEFAULT_ACTION_PYPROJECT,
                    os.environ.get("ASR_ACTION_VERSION", "").strip(),
                    os.environ.get("ASR_ACTION_PYPROJECT", "").strip(),
                ),
                "jetson": os.environ.get("ASR_JETSON_VERSION", "").strip()
                or _read_version_file(jetson_version_file)
                or _resolve_version(
                    None,
                    "",
                    os.environ.get("ASR_JETSON_PYPROJECT", "").strip(),
                ),
            }
        )

    @app.post("/api/admin/users")
    @admin_required
    @limiter.limit("5/minute")
    def create_user():
        data = request.get_json() or request.form
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        role = (data.get("role") or "user").strip()
        email = (data.get("email") or "").strip() or None
        if email:
            email = email.lower()
        if role not in {"admin", "user"}:
            return json_error("Role invalide", 400)
        if (role == "admin" and len(password) < 12) or len(password) < 8:
            return json_error("Mot de passe trop court", 400)
        user = User(username=username, email=email, password_hash=hash_password(password), role=role, is_active=True)
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return json_error("Nom d'utilisateur ou email déjà utilisé", 400)
        log_action(
            action="create_user",
            actor=g.current_user,
            target=user,
            metadata={"role": role},
            ip=client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify({"ok": True, "id": user.id})

    @app.post("/api/admin/users/<int:user_id>/email")
    @admin_required
    @limiter.limit("20/hour")
    def update_user_email(user_id: int):
        data = request.get_json() or request.form
        raw_email = data.get("email")
        email_verified_raw = data.get("email_verified")
        user = User.query.get_or_404(user_id)
        new_email = normalize_email(raw_email)
        if new_email and len(new_email) > 255:
            return json_error("Email trop long", 400)
        if new_email and not EMAIL_RE.match(new_email):
            return json_error("Format d'email invalide", 400)
        # bool parsing
        if email_verified_raw is None:
            email_verified = user.email_verified if new_email == user.email else False
        else:
            email_verified = str(email_verified_raw).lower() in {"1", "true", "yes", "on"}
        if new_email:
            existing = User.query.filter(User.email == new_email, User.id != user.id).first()
            if existing:
                return json_error("Email déjà utilisé", 400)
        old_email = user.email
        email_changed = new_email != old_email
        user.email = new_email
        user.email_verified = email_verified
        if email_changed:
            invalidate_user_tokens(user.id)
        else:
            db.session.commit()
        log_action(
            action="admin_user_email_updated",
            actor=g.current_user,
            target=user,
            metadata={
                "user_id": user.id,
                "old_email": mask_email(old_email),
                "new_email": mask_email(new_email),
                "email_verified": email_verified,
                "changed_by_admin_id": g.current_user.id if g.current_user else None,
            },
            ip=client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify({"ok": True})

    @app.post("/api/admin/users/<int:user_id>/reset-password")
    @admin_required
    @limiter.limit("5/minute")
    def reset_password(user_id: int):
        data = request.get_json() or request.form
        password = data.get("password") or ""
        user = User.query.get_or_404(user_id)
        if (user.role == "admin" and len(password) < 12) or len(password) < 8:
            return json_error("Mot de passe trop court", 400)
        user.password_hash = hash_password(password)
        db.session.commit()
        log_action(
            action="reset_password",
            actor=g.current_user,
            target=user,
            metadata=None,
            ip=client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify({"ok": True})

    @app.post("/api/admin/users/<int:user_id>/toggle-active")
    @admin_required
    def toggle_active(user_id: int):
        user = User.query.get_or_404(user_id)
        user.is_active = not user.is_active
        db.session.commit()
        log_action(
            action="toggle_active",
            actor=g.current_user,
            target=user,
            metadata={"is_active": user.is_active},
            ip=client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify({"ok": True, "is_active": user.is_active})

    @app.get("/admin/audit")
    @admin_required
    def admin_audit_page():
        page = max(int(request.args.get("page", 1)), 1)
        per_page = min(max(int(request.args.get("per_page", 20)), 1), 100)
        query = AuditLog.query.order_by(AuditLog.ts.desc())
        action = request.args.get("action")
        username = request.args.get("username")
        if action:
            query = query.filter(AuditLog.action == action)
        if username:
            query = query.filter(AuditLog.actor_username_snapshot == username)
        items = query.paginate(page=page, per_page=per_page, error_out=False)
        return render_template(
            "admin_audit.html",
            entries=items.items,
            pagination=items,
            csrf_token=g.csrf_token,
            action=action or "",
            username=username or "",
        )

    @app.get("/api/admin/audit")
    @admin_required
    def admin_audit_list():
        page = max(int(request.args.get("page", 1)), 1)
        per_page = min(max(int(request.args.get("per_page", 20)), 1), 100)
        query = AuditLog.query.order_by(AuditLog.ts.desc())
        action = request.args.get("action")
        username = request.args.get("username")
        if action:
            query = query.filter(AuditLog.action == action)
        if username:
            query = query.filter(AuditLog.actor_username_snapshot == username)
        items = query.paginate(page=page, per_page=per_page, error_out=False)
        return jsonify(
            {
                "items": [
                    {
                        "id": e.id,
                        "action": e.action,
                        "actor_username": e.actor_username_snapshot,
                        "target_username": e.target_username_snapshot,
                        "ip": e.ip,
                        "ts": e.ts.isoformat() + "Z",
                        "metadata": json.loads(e.metadata_json) if e.metadata_json else None,
                    }
                    for e in items.items
                ],
                "page": page,
                "pages": items.pages,
                "total": items.total,
            }
        )

    @app.get("/admin/2fa/setup")
    @login_required
    def admin_2fa_setup():
        if g.current_user.role != "admin":
            return json_error("Accès réservé aux administrateurs", 403)
        secret_plain = ensure_totp_secret(app, g.current_user)
        new_codes = ensure_recovery_codes(g.current_user)
        has_recovery_codes = RecoveryCode.query.filter_by(user_id=g.current_user.id).count() > 0
        provisioning_uri = totp_from_secret(secret_plain).provisioning_uri(
            name=g.current_user.username, issuer_name="ASR WebApp"
        )
        return render_template(
            "admin_2fa_setup.html",
            secret=secret_plain,
            provisioning_uri=provisioning_uri,
            recovery_codes=new_codes or [],
            csrf_token=g.csrf_token,
            twofa_enabled=g.current_user.twofa_enabled,
            has_recovery_codes=has_recovery_codes,
        )

    @app.post("/admin/2fa/verify")
    @login_required
    def admin_2fa_verify():
        if g.current_user.role != "admin":
            return json_error("Accès réservé aux administrateurs", 403)
        payload = request.get_json(silent=True) if request.is_json else request.form
        otp = (payload.get("otp") or "").strip() if payload else ""
        secret = decrypt_secret(g.current_user.totp_secret, app.config["TOTP_FERNET"])
        if not secret:
            return json_error("Secret TOTP introuvable", 400)
        totp = totp_from_secret(secret)
        if not totp.verify(str(otp).strip(), valid_window=1):
            return json_error("OTP invalide", 400)
        g.current_user.twofa_enabled = True
        db.session.commit()
        session["twofa_verified"] = True
        log_action(
            action="enable_2fa",
            actor=g.current_user,
            target=g.current_user,
            ip=client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify({"ok": True})

    @app.post("/admin/2fa/recovery/regenerate")
    @admin_required
    def admin_2fa_recovery_regenerate():
        ensure_totp_secret(app, g.current_user)
        codes = regenerate_recovery_codes(g.current_user)
        log_action(
            action="2fa_recovery_regenerate",
            actor=g.current_user,
            target=g.current_user,
            ip=client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify({"ok": True, "recovery_codes": codes})


def ensure_totp_secret(app: Flask, user: User) -> str:
    secret_plain = decrypt_secret(user.totp_secret, app.config["TOTP_FERNET"])
    if not secret_plain:
        secret_plain = generate_totp_secret()
        stored, encrypted = encrypt_secret(secret_plain, app.config["TOTP_FERNET"])
        user.totp_secret = stored
        user.totp_encrypted = encrypted
        user.twofa_enabled = False
    db.session.commit()
    return secret_plain


def regenerate_recovery_codes(user: User) -> list[str]:
    recovery_codes_plain = generate_recovery_codes()
    hashed = hash_recovery_codes(recovery_codes_plain)
    RecoveryCode.query.filter_by(user_id=user.id).delete()
    for h in hashed:
        db.session.add(RecoveryCode(user_id=user.id, code_hash=h))
    db.session.commit()
    return recovery_codes_plain


def ensure_recovery_codes(user: User) -> list[str] | None:
    existing = RecoveryCode.query.filter_by(user_id=user.id).count()
    if existing == 0:
        return regenerate_recovery_codes(user)
    return None


def extract_metadata(req_form) -> dict:
    default_prompt = os.environ.get("DEFAULT_ASR_PROMPT", "Kleos, Pennylane, CJD, Manupro, El Moussaoui")
    meeting_report_types = [entry["key"] for entry in get_meeting_report_types() if entry.get("key")]
    default_meeting_report_type = meeting_report_types[0] if meeting_report_types else ""

    def normalize_meeting_date(raw: str | None) -> str:
        if not raw:
            return _utcnow().date().isoformat()
        try:
            return datetime.strptime(raw, "%Y-%m-%d").date().isoformat()
        except ValueError:
            raise ValueError("meeting_date doit respecter le format YYYY-MM-DD")

    meeting_report_type = (req_form.get("meeting_report_type") or default_meeting_report_type).strip()
    if meeting_report_types and meeting_report_type not in meeting_report_types:
        raise ValueError("meeting_report_type invalide")

    asr_prompt = (req_form.get("asr_prompt") or default_prompt).strip()
    speaker_context = (req_form.get("speaker_context") or "").strip()
    case_name = (req_form.get("case_name") or "").strip()
    if len(case_name) > 160:
        raise ValueError("Nom du dossier trop long (max 160 caractères)")
    meeting_date = normalize_meeting_date(req_form.get("meeting_date"))

    return {
        "asr_prompt": asr_prompt,
        "speaker_context": speaker_context,
        "case_name": case_name,
        "meeting_date": meeting_date,
        "meeting_report_type": meeting_report_type,
    }


if os.environ.get("ASR_WEBAPP_SKIP_AUTOAPP") != "1":
    app = create_app()
else:
    app = None


if __name__ == "__main__":
    app = app or create_app()
    app.run(host="127.0.0.1", port=8000, debug=True)
