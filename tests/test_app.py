import io
import json
import re
from datetime import datetime

import pyotp
import pytest

from server.app import create_app
from server.models import AuditLog, RecoveryCode, User, db
from server.security import hash_password


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("ASR_WEBAPP_SKIP_AUTOAPP", "1")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "SuperSecureAdmin!")
    monkeypatch.setenv("SECRET_KEY", "testing-secret")
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "UPLOAD_FOLDER": str(upload_dir),
            "MAX_CONTENT_LENGTH": 5 * 1024 * 1024,
            "SESSION_COOKIE_SECURE": False,
        }
    )
    return app


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


def test_bootstrap_admin_created(app):
    with app.app_context():
        admin = User.query.filter_by(role="admin").first()
        assert admin is not None
        assert admin.username == "admin"


def test_health_public(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


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
    assert metadata["meeting_date"] == datetime.utcnow().date().isoformat()


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
    secret = parse_secret_from_html(setup_resp.data.decode())
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
    setup_resp2 = client.get("/admin/2fa/setup")
    codes = parse_recovery_codes_from_html(setup_resp2.data.decode())
    assert codes
    client.post("/logout", data={"csrf_token": csrf2})
    rec_login = login(client, "admin", "SuperSecureAdmin!", otp=codes[0])
    assert rec_login.status_code in (302, 200)
    client.post("/logout", data={"csrf_token": set_csrf(client)})
    rec_login_again = login(client, "admin", "SuperSecureAdmin!", otp=codes[0])
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
