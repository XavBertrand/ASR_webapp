import builtins
import io
import json
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
import pytest

import importlib

app_module = importlib.import_module("server.app")
from server.app import client_ip, create_app, hash_reset_token
from server.models import AuditLog, PasswordResetToken, RecoveryCode, User, db
from server.security import hash_password, verify_password


def build_app(tmp_path, monkeypatch, *, extra_env: dict | None = None, config: dict | None = None):
    monkeypatch.setenv("ASR_WEBAPP_SKIP_AUTOAPP", "1")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "SuperSecureAdmin!")
    monkeypatch.setenv("SECRET_KEY", "testing-secret")
    if extra_env:
        for key, value in extra_env.items():
            monkeypatch.setenv(key, value)
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir(exist_ok=True)
    base_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "UPLOAD_FOLDER": str(upload_dir),
        "MAX_CONTENT_LENGTH": 5 * 1024 * 1024,
        "SESSION_COOKIE_SECURE": False,
    }
    if config:
        base_config.update(config)
    return create_app(base_config)


@pytest.fixture()
def app(tmp_path, monkeypatch):
    return build_app(tmp_path, monkeypatch)


@pytest.fixture()
def client(app):
    return app.test_client()


def set_csrf(client, token="csrf-test"):
    with client.session_transaction() as sess:
        sess["csrf_token"] = token
    return token


def login(client, username, password, otp=None):
    csrf = set_csrf(client)
    payload = {"username": username, "password": password, "csrf_token": csrf}
    if otp:
        payload["otp"] = otp
    return client.post("/login", data=payload, follow_redirects=False)


def forgot_password(client, identifier):
    csrf = set_csrf(client)
    return client.post("/forgot-password", data={"identifier": identifier, "csrf_token": csrf})


def extract_token_from_logs(caplog):
    for record in caplog.records:
        if "PASSWORD RESET LINK" in record.message:
            match = re.search(r"/reset-password/([A-Za-z0-9_\-]+)", record.message)
            if match:
                return match.group(1)
    return None


def admin_update_email(client, user_id, email, verified=False):
    with client.session_transaction() as sess:
        csrf = sess.get("csrf_token") or set_csrf(client)
    return client.post(
        f"/api/admin/users/{user_id}/email",
        json={"email": email, "email_verified": verified},
        headers={"X-CSRF-Token": csrf},
    )


def test_bootstrap_admin_created(app):
    with app.app_context():
        admin = User.query.filter_by(role="admin").first()
        assert admin is not None
        assert admin.username == "admin"


def test_health_public(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_permissions_policy_allows_microphone(client):
    resp = client.get("/health")
    header = resp.headers.get("Permissions-Policy")
    assert header is not None
    assert "microphone=(self)" in header


def test_login_success_and_fail_and_rate_limit(client, app):
    # success
    ok = login(client, "admin", "SuperSecureAdmin!")
    assert ok.status_code in (302, 200)
    # failures + rate limit
    resp = None
    for _ in range(6):
        set_csrf(client, "t")
        resp = client.post(
            "/login", data={"username": "admin", "password": "bad", "csrf_token": "t"}
        )
    assert resp is not None and resp.status_code == 429
    with app.app_context():
        assert AuditLog.query.filter_by(action="login_failed").count() >= 4


def test_templates_include_visual_shell(client):
    login_resp = client.get("/login")
    login_html = login_resp.get_data(as_text=True)
    assert "app_shell.css" in login_html
    assert 'class="page-shell"' in login_html
    assert re.search(r'class="card[^"]*page-card', login_html)

    ok = login(client, "admin", "SuperSecureAdmin!")
    assert ok.status_code in (302, 200)

    admin_users_resp = client.get("/admin/users")
    admin_users_html = admin_users_resp.get_data(as_text=True)
    assert "app_shell.css" in admin_users_html
    assert 'class="page-admin"' in admin_users_html
    assert 'class="topbar"' in admin_users_html

    admin_2fa_resp = client.get("/admin/2fa/setup")
    admin_2fa_html = admin_2fa_resp.get_data(as_text=True)
    assert "app_shell.css" in admin_2fa_html
    assert 'class="modal-backdrop"' in admin_2fa_html


def test_csrf_blocks_admin_post(client):
    login(client, "admin", "SuperSecureAdmin!")
    resp = client.post("/api/admin/users", json={"username": "bob", "password": "Password123", "role": "user"})
    assert resp.status_code == 400


def test_rbac_blocks_non_admin(client, app):
    with app.app_context():
        user = User(username="user1", password_hash=hash_password("Password123"), role="user", is_active=True)
        db.session.add(user)
        db.session.commit()
    resp = login(client, "user1", "Password123")
    assert resp.status_code in (302, 200)
    res = client.get("/admin/users")
    assert res.status_code == 403


def test_create_user_reset_password_and_login(client, app):
    resp = login(client, "admin", "SuperSecureAdmin!")
    assert resp.status_code in (302, 200)
    with client.session_transaction() as sess:
        csrf = sess["csrf_token"]
    # create user
    create_resp = client.post(
        "/api/admin/users",
        json={"username": "newuser", "password": "Password123", "role": "user"},
        headers={"X-CSRF-Token": csrf},
    )
    assert create_resp.status_code == 200
    new_id = create_resp.get_json()["id"]
    # reset password
    reset_resp = client.post(
        f"/api/admin/users/{new_id}/reset-password",
        json={"password": "NewPassword123"},
        headers={"X-CSRF-Token": csrf},
    )
    assert reset_resp.status_code == 200
    # login with new password
    client.post("/logout", data={"csrf_token": csrf})
    resp2 = login(client, "newuser", "NewPassword123")
    assert resp2.status_code in (302, 200)
    with app.app_context():
        assert AuditLog.query.filter_by(action="create_user").count() >= 1
        assert AuditLog.query.filter_by(action="reset_password").count() >= 1


def test_upload_requires_login_and_works(client, app, tmp_path):
    resp = client.post("/upload", data={}, content_type="multipart/form-data")
    assert resp.status_code in (400, 401)
    login(client, "admin", "SuperSecureAdmin!")
    with client.session_transaction() as sess:
        csrf = sess["csrf_token"]
    audio_bytes = b"RIFF....WAVEfmt "
    upload_resp = client.post(
        "/upload",
        data={"file": (io.BytesIO(audio_bytes), "audio.wav"), "csrf_token": csrf},
        content_type="multipart/form-data",
        headers={"X-CSRF-Token": csrf},
    )
    assert upload_resp.status_code == 201
    payload = upload_resp.get_json()
    saved_name = payload["filename"]
    user_folder = payload["metadata"]["user_folder"]
    saved_path = tmp_path / "uploads" / user_folder / saved_name
    assert saved_path.exists()
    meta_path = tmp_path / "uploads" / user_folder / f"{saved_name.rsplit('.', 1)[0]}_meta.json"
    metadata = json.loads(meta_path.read_text())
    assert metadata["saved_filename"] == saved_name
    assert metadata["meeting_date"] == datetime.now(timezone.utc).date().isoformat()


def parse_secret_from_html(html: str) -> str:
    m = re.search(r"Secret:\s*<code>([^<]+)</code>", html)
    assert m, "secret introuvable dans la page"
    return m.group(1)


def parse_recovery_codes_from_html(html: str) -> list[str]:
    return re.findall(r'<div class="code">([^<]+)</div>', html)


def test_admin_2fa_flow_and_recovery_codes(client, app):
    login(client, "admin", "SuperSecureAdmin!")
    with client.session_transaction() as sess:
        csrf = sess["csrf_token"]
    setup_resp = client.get("/admin/2fa/setup")
    assert setup_resp.status_code == 200
    setup_html = setup_resp.data.decode()
    secret = parse_secret_from_html(setup_html)
    codes = parse_recovery_codes_from_html(setup_html)
    assert codes
    recovery_codes = list(codes)
    otp = pyotp.TOTP(secret).now()
    verify_resp = client.post(
        "/admin/2fa/verify",
        json={"otp": otp},
        headers={"X-CSRF-Token": csrf},
    )
    assert verify_resp.status_code == 200
    client.post("/logout", data={"csrf_token": csrf})

    # login without otp should fail
    bad = login(client, "admin", "SuperSecureAdmin!")
    assert bad.status_code == 401
    # login with otp works
    otp2 = pyotp.TOTP(secret).now()
    ok = login(client, "admin", "SuperSecureAdmin!", otp=otp2)
    assert ok.status_code in (302, 200)

    # recovery code works once
    with client.session_transaction() as sess:
        csrf2 = sess["csrf_token"]
    client.post("/logout", data={"csrf_token": csrf2})
    rec_login = login(client, "admin", "SuperSecureAdmin!", otp=recovery_codes[0])
    assert rec_login.status_code in (302, 200)
    client.post("/logout", data={"csrf_token": set_csrf(client)})
    rec_login_again = login(client, "admin", "SuperSecureAdmin!", otp=recovery_codes[0])
    assert rec_login_again.status_code == 401
    with app.app_context():
        assert RecoveryCode.query.filter(RecoveryCode.used_at.isnot(None)).count() >= 1


def test_admin_endpoints_reject_when_not_verified_2fa(client, app, monkeypatch):
    login(client, "admin", "SuperSecureAdmin!")
    with client.session_transaction() as sess:
        csrf = sess["csrf_token"]
    setup_resp = client.get("/admin/2fa/setup")
    secret = parse_secret_from_html(setup_resp.data.decode())
    otp = pyotp.TOTP(secret).now()
    client.post("/admin/2fa/verify", json={"otp": otp}, headers={"X-CSRF-Token": csrf})
    client.post("/logout", data={"csrf_token": csrf})
    # login with OTP to set session, then force twofa_verified to False
    good_login = login(client, "admin", "SuperSecureAdmin!", otp=pyotp.TOTP(secret).now())
    assert good_login.status_code in (302, 200)
    with client.session_transaction() as sess:
        sess["twofa_verified"] = False
    resp = client.get("/admin/users")
    assert resp.status_code in (302, 401)


def test_recovery_codes_not_regenerated_on_get(client, app):
    login(client, "admin", "SuperSecureAdmin!")
    setup1 = client.get("/admin/2fa/setup")
    codes_first = parse_recovery_codes_from_html(setup1.data.decode())
    assert codes_first
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        initial_hashes = [rc.code_hash for rc in RecoveryCode.query.filter_by(user_id=admin.id).all()]
    setup2 = client.get("/admin/2fa/setup")
    codes_second = parse_recovery_codes_from_html(setup2.data.decode())
    assert codes_second == []
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        hashes_after = [rc.code_hash for rc in RecoveryCode.query.filter_by(user_id=admin.id).all()]
        assert hashes_after == initial_hashes


def test_recovery_regenerate_endpoint_changes_codes(client, app):
    login(client, "admin", "SuperSecureAdmin!")
    with client.session_transaction() as sess:
        csrf = sess["csrf_token"]
    setup_resp = client.get("/admin/2fa/setup")
    secret = parse_secret_from_html(setup_resp.data.decode())
    initial_codes = parse_recovery_codes_from_html(setup_resp.data.decode())
    otp = pyotp.TOTP(secret).now()
    client.post("/admin/2fa/verify", json={"otp": otp}, headers={"X-CSRF-Token": csrf})
    regen = client.post("/admin/2fa/recovery/regenerate", json={}, headers={"X-CSRF-Token": csrf})
    assert regen.status_code == 200
    data = regen.get_json()
    assert data["recovery_codes"]
    new_codes = data["recovery_codes"]
    assert set(new_codes) != set(initial_codes)
    client.post("/logout", data={"csrf_token": csrf})
    old = login(client, "admin", "SuperSecureAdmin!", otp=initial_codes[0])
    assert old.status_code == 401
    fresh = login(client, "admin", "SuperSecureAdmin!", otp=new_codes[0])
    assert fresh.status_code in (302, 200)
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        new_hashes = [rc.code_hash for rc in RecoveryCode.query.filter_by(user_id=admin.id).all()]
        assert len(new_hashes) > 0
        assert AuditLog.query.filter_by(action="2fa_recovery_regenerate", actor_user_id=admin.id).count() >= 1


def test_client_ip_ignores_xff_when_not_trusted(tmp_path, monkeypatch):
    app = build_app(tmp_path, monkeypatch, extra_env={"TRUST_PROXY_HEADERS": "false"})

    @app.get("/ip")
    def get_ip():
        return {"ip": client_ip()}

    client = app.test_client()
    resp = client.get("/ip", headers={"X-Forwarded-For": "1.2.3.4"}, environ_overrides={"REMOTE_ADDR": "9.9.9.9"})
    assert resp.status_code == 200
    assert resp.get_json()["ip"] == "9.9.9.9"


def test_client_ip_respects_trusted_proxy_headers(tmp_path, monkeypatch):
    app = build_app(tmp_path, monkeypatch, extra_env={"TRUST_PROXY_HEADERS": "true"})

    @app.get("/ip")
    def get_ip():
        return {"ip": client_ip()}

    client = app.test_client()
    resp = client.get(
        "/ip",
        headers={"X-Forwarded-For": "1.2.3.4, 5.5.5.5"},
        environ_overrides={"REMOTE_ADDR": "9.9.9.9"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["ip"] == "1.2.3.4"


def test_ratelimit_storage_env(monkeypatch, tmp_path):
    storage_url = "memory://?namespace=test"
    app = build_app(tmp_path, monkeypatch, extra_env={"RATELIMIT_STORAGE_URL": storage_url})
    assert app.config["RATELIMIT_STORAGE_URL"] == storage_url
    from server.app import limiter

    assert getattr(limiter, "_storage", None) is not None


def test_ratelimit_memory_warning_in_production(tmp_path, monkeypatch, caplog):
    extra_env = {"WEBAPP_ENV": "production", "RATELIMIT_STORAGE_URL": "memory://"}
    with caplog.at_level(logging.WARNING):
        build_app(tmp_path, monkeypatch, extra_env=extra_env)
    assert any("Limiter not shared across workers" in record.message for record in caplog.records)


def test_ratelimit_redis_fallback_without_client(tmp_path, monkeypatch, caplog):
    original_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "redis":
            raise ImportError("redis blocked for test")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    extra_env = {"RATELIMIT_STORAGE_URL": "redis://localhost:6379/0"}
    with caplog.at_level(logging.WARNING):
        app = build_app(tmp_path, monkeypatch, extra_env=extra_env)
    assert app.config["RATELIMIT_STORAGE_URL"] == "memory://"
    assert any("Limiter backend" in record.message for record in caplog.records)


def test_secret_key_required_when_not_testing(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("ASR_WEBAPP_SKIP_AUTOAPP", "1")
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(
            {
                "TESTING": False,
                "SKIP_BOOTSTRAP_ADMIN": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite://",
                "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            }
        )


def test_security_headers_present(client):
    resp = client.get("/login")
    csp = resp.headers.get("Content-Security-Policy")
    assert csp and "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert resp.headers.get("Permissions-Policy") == "geolocation=(), microphone=(self), camera=()"


def test_secure_cookie_attributes_when_enabled(tmp_path, monkeypatch):
    app = build_app(tmp_path, monkeypatch, config={"SESSION_COOKIE_SECURE": True})
    client = app.test_client()
    resp = client.get("/login")
    cookies = resp.headers.getlist("Set-Cookie")
    session_cookie = next((cookie for cookie in cookies if cookie.startswith("session=")), "")
    csrf_cookie = next((cookie for cookie in cookies if cookie.startswith("csrf_token=")), "")
    assert session_cookie
    assert "Secure" in session_cookie
    assert "HttpOnly" in session_cookie
    assert "SameSite=Lax" in session_cookie
    assert csrf_cookie
    assert "Secure" in csrf_cookie
    assert "SameSite=Lax" in csrf_cookie
    assert "HttpOnly" not in csrf_cookie


def test_reset_url_uses_https_with_proxy_headers(tmp_path, monkeypatch):
    monkeypatch.delenv("MAIL_HOST", raising=False)
    captured = {}

    def fake_send_password_reset_email(app, user, reset_url):
        captured["url"] = reset_url
        return "log"

    monkeypatch.setattr(app_module, "send_password_reset_email", fake_send_password_reset_email)
    app = build_app(tmp_path, monkeypatch, extra_env={"TRUST_PROXY_HEADERS": "true"})
    with app.app_context():
        user = User(
            username="proxyuser",
            email="proxy@example.com",
            password_hash=hash_password("Password123"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
    client = app.test_client()
    base_url = "http://example.test"
    with client.session_transaction(base_url=base_url) as sess:
        sess["csrf_token"] = "csrf-test"
        csrf = sess["csrf_token"]
    resp = client.post(
        "/forgot-password",
        data={"identifier": "proxy@example.com", "csrf_token": csrf},
        headers={"X-Forwarded-Proto": "https"},
        base_url=base_url,
    )
    assert resp.status_code == 200
    reset_url = captured.get("url")
    assert reset_url and reset_url.startswith("https://example.test/")


def test_forgot_password_unknown_identifier_no_token(client, app):
    resp = forgot_password(client, "nobody")
    assert resp.status_code == 200
    with app.app_context():
        assert PasswordResetToken.query.count() == 0


def test_forgot_password_creates_token_and_audit(client, app, caplog):
    with app.app_context():
        user = User(
            username="alice",
            email="alice@example.com",
            password_hash=hash_password("Password123"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    with caplog.at_level(logging.WARNING):
        resp = forgot_password(client, "alice@example.com")
    assert resp.status_code == 200
    raw_token = extract_token_from_logs(caplog)
    assert raw_token
    with app.app_context():
        tokens = PasswordResetToken.query.filter_by(user_id=user_id).all()
        assert len(tokens) == 1
        assert AuditLog.query.filter_by(action="password_reset_requested", target_user_id=user_id).count() >= 1


def test_reset_token_single_use(client, app, caplog):
    with app.app_context():
        user = User(
            username="bob",
            email="bob@example.com",
            password_hash=hash_password("Password123"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    with caplog.at_level(logging.WARNING):
        forgot_password(client, "bob@example.com")
    token = extract_token_from_logs(caplog)
    assert token
    resp_get = client.get(f"/reset-password/{token}")
    assert resp_get.status_code == 200
    with client.session_transaction() as sess:
        csrf = sess["csrf_token"]
    first = client.post(
        f"/reset-password/{token}",
        data={"password": "NewPassword123", "confirm_password": "NewPassword123", "csrf_token": csrf},
    )
    assert first.status_code in (200, 302)
    with client.session_transaction() as sess:
        csrf2 = sess.get("csrf_token") or set_csrf(client)
    second = client.post(
        f"/reset-password/{token}",
        data={"password": "AnotherPass123", "confirm_password": "AnotherPass123", "csrf_token": csrf2},
    )
    assert second.status_code == 400
    with app.app_context():
        tokens = PasswordResetToken.query.filter_by(user_id=user_id).all()
        assert tokens and all(t.used_at is not None for t in tokens)
        user = db.session.get(User, user_id)
        assert verify_password(user.password_hash, "NewPassword123")


def test_reset_token_expired(client, app):
    with app.app_context():
        user = User(
            username="carol",
            email="carol@example.com",
            password_hash=hash_password("Password123"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        raw = "expired-" + secrets.token_urlsafe(8)
        token = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_reset_token(raw),
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        db.session.add(token)
        db.session.commit()
    resp_get = client.get(f"/reset-password/{raw}")
    assert resp_get.status_code == 400
    with client.session_transaction() as sess:
        csrf = sess.get("csrf_token") or set_csrf(client)
    resp_post = client.post(
        f"/reset-password/{raw}",
        data={"password": "AnotherPass123", "confirm_password": "AnotherPass123", "csrf_token": csrf},
    )
    assert resp_post.status_code == 400
    with app.app_context():
        token_db = PasswordResetToken.query.first()
        assert token_db and token_db.used_at is None


def test_password_policy_enforced_for_admin_reset(client, app):
    with app.app_context():
        user = User(
            username="david",
            email="david@example.com",
            password_hash=hash_password("Password123"),
            role="admin",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        raw = "adm-" + secrets.token_urlsafe(8)
        token = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_reset_token(raw),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        db.session.add(token)
        db.session.commit()
    client.get(f"/reset-password/{raw}")
    with client.session_transaction() as sess:
        csrf = sess.get("csrf_token") or set_csrf(client)
    resp = client.post(
        f"/reset-password/{raw}",
        data={"password": "short", "confirm_password": "short", "csrf_token": csrf},
    )
    assert resp.status_code == 400
    with app.app_context():
        token_db = PasswordResetToken.query.first()
        assert token_db.used_at is None
        user = User.query.filter_by(username="david").first()
        assert verify_password(user.password_hash, "Password123")


def test_inactive_user_does_not_get_token(client, app):
    with app.app_context():
        user = User(
            username="eve",
            email="eve@example.com",
            password_hash=hash_password("Password123"),
            role="user",
            is_active=False,
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    resp = forgot_password(client, "eve@example.com")
    assert resp.status_code == 200
    with app.app_context():
        assert PasswordResetToken.query.filter_by(user_id=user_id).count() == 0


def test_reset_invalidates_other_tokens(client, app):
    with app.app_context():
        user = User(
            username="frank",
            email="frank@example.com",
            password_hash=hash_password("Password123"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        raw1 = "tok-" + secrets.token_urlsafe(6)
        raw2 = "tok-" + secrets.token_urlsafe(6)
        t1 = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_reset_token(raw1),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        t2 = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_reset_token(raw2),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        db.session.add_all([t1, t2])
        db.session.commit()
        user_id = user.id
    resp_get = client.get(f"/reset-password/{raw1}")
    assert resp_get.status_code == 200
    with client.session_transaction() as sess:
        csrf = sess.get("csrf_token") or set_csrf(client)
    resp_post = client.post(
        f"/reset-password/{raw1}",
        data={"password": "ResetAll123", "confirm_password": "ResetAll123", "csrf_token": csrf},
    )
    assert resp_post.status_code in (200, 302)
    with app.app_context():
        tokens = PasswordResetToken.query.filter_by(user_id=user_id).all()
        assert len(tokens) == 2
        assert all(t.used_at is not None for t in tokens)


def test_admin_can_set_and_clear_email(client, app):
    login(client, "admin", "SuperSecureAdmin!")
    with app.app_context():
        user = User(username="target", password_hash=hash_password("Password123"), role="user", is_active=True)
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    res = admin_update_email(client, user_id, "NewEmail@Example.com", verified=True)
    assert res.status_code == 200
    with app.app_context():
        refreshed = db.session.get(User, user_id)
        assert refreshed.email == "newemail@example.com"
        assert refreshed.email_verified is True
        audit = AuditLog.query.filter_by(action="admin_user_email_updated", target_user_id=user_id).order_by(
            AuditLog.id.desc()
        ).first()
        assert audit and "***" in (audit.metadata_json or "")
    res_clear = admin_update_email(client, user_id, "", verified=False)
    assert res_clear.status_code == 200
    with app.app_context():
        refreshed = db.session.get(User, user_id)
        assert refreshed.email is None
        assert refreshed.email_verified is False


def test_non_admin_cannot_update_email(client, app):
    with app.app_context():
        user = User(username="simple", password_hash=hash_password("Password123"), role="user", is_active=True)
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    login(client, "admin", "SuperSecureAdmin!")
    client.post("/logout", data={"csrf_token": set_csrf(client)})
    login(client, "simple", "Password123")
    resp = admin_update_email(client, user_id, "hack@example.com")
    assert resp.status_code == 403


def test_duplicate_email_rejected(client, app):
    login(client, "admin", "SuperSecureAdmin!")
    with app.app_context():
        u1 = User(username="u1", email="dup@example.com", password_hash=hash_password("Password123"), role="user", is_active=True)
        u2 = User(username="u2", email="other@example.com", password_hash=hash_password("Password123"), role="user", is_active=True)
        db.session.add_all([u1, u2])
        db.session.commit()
        user2_id = u2.id
    resp = admin_update_email(client, user2_id, "dup@example.com")
    assert resp.status_code == 400


def test_email_change_invalidates_reset_tokens(client, app):
    login(client, "admin", "SuperSecureAdmin!")
    with app.app_context():
        user = User(username="victim", email="victim@example.com", password_hash=hash_password("Password123"), role="user", is_active=True)
        db.session.add(user)
        db.session.commit()
        raw = "raw-" + secrets.token_urlsafe(6)
        token = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_reset_token(raw),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        db.session.add(token)
        db.session.commit()
        user_id = user.id
    resp = admin_update_email(client, user_id, "victim2@example.com")
    assert resp.status_code == 200
    with app.app_context():
        tokens = PasswordResetToken.query.filter_by(user_id=user_id).all()
        assert tokens and all(t.used_at is not None for t in tokens)


def test_no_cors_header_on_login(client):
    resp = client.get("/login")
    assert "Access-Control-Allow-Origin" not in resp.headers


def test_gunicorn_default_host_loopback():
    entrypoint = Path(__file__).resolve().parent.parent / "docker" / "entrypoint.sh"
    content = entrypoint.read_text()
    assert 'GUNICORN_HOST="${GUNICORN_HOST:-127.0.0.1}"' in content
    assert "GUNICORN_BIND_LOCAL_ONLY" in content
