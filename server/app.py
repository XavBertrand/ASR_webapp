from __future__ import annotations

import json
import logging
import os
import secrets
from datetime import datetime, timedelta
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
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError

from server.models import AuditLog, RecoveryCode, User, db
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
ALLOWED_EXTENSIONS = {"webm", "wav", "mp3", "ogg", "m4a", "mp4"}
DEFAULT_MAX_MB = int(os.environ.get("MAX_CONTENT_LENGTH_MB", "100"))
DEFAULT_DB_URI = os.environ.get("DATABASE_URL", f"sqlite:///{ROOT_DIR / 'app.db'}")
DEFAULT_SAME_SITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
SESSION_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() != "false"
REQUIRE_ADMIN_2FA = os.environ.get("REQUIRE_ADMIN_2FA", "false").lower() == "true"
TOTP_ENC_KEY = os.environ.get("TOTP_ENC_KEY")

MAX_CONTENT_LENGTH = DEFAULT_MAX_MB * 1024 * 1024

limiter = Limiter(key_func=get_remote_address, storage_uri=os.environ.get("RATELIMIT_STORAGE_URL", "memory://"))


def _parse_env_int(env_name: str) -> int | None:
    raw = os.environ.get(env_name)
    if raw is None or raw == "":
        return None
    try:
        return int(raw, 10)
    except ValueError:
        logger.warning("%s doit être un entier, valeur ignorée: %r", env_name, raw)
        return None


ENV_UPLOAD_UID = _parse_env_int("UPLOAD_UID")
ENV_UPLOAD_GID = _parse_env_int("UPLOAD_GID")


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


def wants_json_response() -> bool:
    if request.is_json:
        return True
    best = request.accept_mimetypes.best_match(["application/json", "text/html"])
    return best == "application/json" and request.accept_mimetypes[best] > request.accept_mimetypes["text/html"]


def json_error(message: str, code: int) -> Any:
    return jsonify({"error": message}), code


def client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or ""


def ensure_dirs(app: Flask) -> None:
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    apply_upload_permissions(app.config["UPLOAD_FOLDER"], is_dir=True, base_dir=app.config["UPLOAD_FOLDER"])
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite:///"):
        db_path = Path(app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "", 1))
        if db_path.parent:
            os.makedirs(db_path.parent, exist_ok=True)


def require_secret_key(app: Flask) -> None:
    if app.config.get("SECRET_KEY"):
        return
    if app.config.get("TESTING"):
        app.config["SECRET_KEY"] = "test-secret-key"
        return
    raise RuntimeError("SECRET_KEY est obligatoire en production")


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(
        __name__,
        static_folder=str(ROOT_DIR / "webapp"),
        static_url_path="",
        template_folder=str(BASE_DIR / "templates"),
    )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    app.config.update(
        UPLOAD_FOLDER=DEFAULT_UPLOAD_FOLDER,
        MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
        SQLALCHEMY_DATABASE_URI=DEFAULT_DB_URI,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_SECURE=SESSION_SECURE,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=DEFAULT_SAME_SITE,
        PREFERRED_URL_SCHEME="https",
        REQUIRE_ADMIN_2FA=REQUIRE_ADMIN_2FA,
        PERMANENT_SESSION_LIFETIME=timedelta(
            hours=int(os.environ.get("SESSION_LIFETIME_HOURS", "12"))
        ),
        SKIP_BOOTSTRAP_ADMIN=False,
    )
    if test_config:
        app.config.update(test_config)

    require_secret_key(app)

    db.init_app(app)
    limiter.init_app(app)
    app.config["TOTP_FERNET"] = make_fernet(TOTP_ENC_KEY)

    ensure_dirs(app)
    register_routes(app)
    with app.app_context():
        db.create_all()
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
    app.after_request(persist_csrf_cookie)

    @app.errorhandler(429)
    def handle_ratelimit(exc):
        message = "Trop de requêtes, réessayez plus tard."
        if wants_json_response():
            return json_error(message, 429)
        return render_template("login.html", error=message, csrf_token=g.csrf_token), 429

    @app.get("/health")
    def health():
        return {"status": "ok"}, 200

    @app.get("/login")
    def login():
        if getattr(g, "current_user", None):
            return redirect(url_for("home"))
        return render_template("login.html", csrf_token=g.csrf_token)

    @app.post("/login")
    @limiter.limit("5/minute;20/hour")
    def handle_login():
        data = request.form if request.form else request.get_json(silent=True) or {}
        as_form = bool(request.form)

        def login_error(msg: str, status: int):
            if wants_json_response() or not as_form:
                return json_error(msg, status)
            return render_template("login.html", error=msg, csrf_token=g.csrf_token), status

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
                        matched.used_at = datetime.utcnow()
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
                    return login_error("OTP requis ou invalide", 401)

        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
            db.session.commit()

        rotation_session(user, otp_validated=otp_validated)
        user.last_login_at = datetime.utcnow()
        db.session.commit()
        log_action(action="login_success", actor=user, ip=ip, user_agent=ua)

        if wants_json_response():
            return jsonify({"ok": True, "next": url_for("home")})
        return redirect(url_for("home"))

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
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
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
                "uploaded_at": datetime.utcnow().isoformat() + "Z",
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
                    "role": u.role,
                    "is_active": u.is_active,
                    "twofa_enabled": u.twofa_enabled,
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

    @app.post("/api/admin/users")
    @admin_required
    @limiter.limit("5/minute")
    def create_user():
        data = request.get_json() or request.form
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        role = (data.get("role") or "user").strip()
        if role not in {"admin", "user"}:
            return json_error("Role invalide", 400)
        if (role == "admin" and len(password) < 12) or len(password) < 8:
            return json_error("Mot de passe trop court", 400)
        user = User(username=username, password_hash=hash_password(password), role=role, is_active=True)
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return json_error("Nom d'utilisateur déjà utilisé", 400)
        log_action(
            action="create_user",
            actor=g.current_user,
            target=user,
            metadata={"role": role},
            ip=client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify({"ok": True, "id": user.id})

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
        secret_plain, codes = ensure_totp_materials(app, g.current_user)
        provisioning_uri = totp_from_secret(secret_plain).provisioning_uri(
            name=g.current_user.username, issuer_name="ASR WebApp"
        )
        return render_template(
            "admin_2fa_setup.html",
            secret=secret_plain,
            provisioning_uri=provisioning_uri,
            recovery_codes=codes,
            csrf_token=g.csrf_token,
            twofa_enabled=g.current_user.twofa_enabled,
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


def ensure_totp_materials(app: Flask, user: User) -> tuple[str, list[str]]:
    secret_plain = decrypt_secret(user.totp_secret, app.config["TOTP_FERNET"])
    if not secret_plain:
        secret_plain = generate_totp_secret()
        stored, encrypted = encrypt_secret(secret_plain, app.config["TOTP_FERNET"])
        user.totp_secret = stored
        user.totp_encrypted = encrypted
        user.twofa_enabled = False
    recovery_codes_plain = generate_recovery_codes()
    hashed = hash_recovery_codes(recovery_codes_plain)
    RecoveryCode.query.filter_by(user_id=user.id).delete()
    for h in hashed:
        db.session.add(RecoveryCode(user_id=user.id, code_hash=h))
    db.session.commit()
    return secret_plain, recovery_codes_plain


def extract_metadata(req_form) -> dict:
    default_prompt = os.environ.get("DEFAULT_ASR_PROMPT", "Kleos, Pennylane, CJD, Manupro, El Moussaoui")
    meeting_report_types = [
        "entretien_collaborateur",
        "entretien_client_particulier_contentieux",
        "entretien_client_professionnel_conseil",
        "entretien_client_professionnel_contentieux",
    ]
    default_meeting_report_type = meeting_report_types[0]

    def normalize_meeting_date(raw: str | None) -> str:
        if not raw:
            return datetime.utcnow().date().isoformat()
        try:
            return datetime.strptime(raw, "%Y-%m-%d").date().isoformat()
        except ValueError:
            raise ValueError("meeting_date doit respecter le format YYYY-MM-DD")

    meeting_report_type = (req_form.get("meeting_report_type") or default_meeting_report_type).strip()
    if meeting_report_type not in meeting_report_types:
        raise ValueError("meeting_report_type invalide")

    asr_prompt = (req_form.get("asr_prompt") or default_prompt).strip()
    speaker_context = (req_form.get("speaker_context") or "").strip()
    meeting_date = normalize_meeting_date(req_form.get("meeting_date"))

    return {
        "asr_prompt": asr_prompt,
        "speaker_context": speaker_context,
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
