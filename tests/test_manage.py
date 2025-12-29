import argparse
import sys

import pytest

from server import manage
from server.app import create_app
from server.models import User, db
from server.security import verify_password


def build_manage_app(tmp_path, monkeypatch):
    monkeypatch.setenv("ASR_WEBAPP_SKIP_AUTOAPP", "1")
    base_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "UPLOAD_FOLDER": str(tmp_path / "uploads"),
        "REPORTS_ROOT": str(tmp_path / "reports"),
        "SESSION_COOKIE_SECURE": False,
        "SKIP_BOOTSTRAP_ADMIN": True,
    }
    return create_app(base_config)


@pytest.fixture()
def manage_app(tmp_path, monkeypatch):
    return build_manage_app(tmp_path, monkeypatch)


def test_create_user_valid(manage_app):
    with manage_app.app_context():
        user = manage.create_user("alice", "Password123", "user")
        assert user.role == "user"
        assert verify_password(user.password_hash, "Password123") is True
        assert User.query.filter_by(username="alice").count() == 1


def test_create_user_invalid_role_and_password(manage_app):
    with manage_app.app_context():
        with pytest.raises(SystemExit):
            manage.create_user("bad", "Password123", "invalid")
        with pytest.raises(SystemExit):
            manage.create_user("short", "short", "user")


def test_reset_password_updates_hash(manage_app):
    with manage_app.app_context():
        manage.create_user("bob", "Password123", "user")
        manage.reset_password("bob", "NewPassword123")
        refreshed = User.query.filter_by(username="bob").first()
        assert refreshed is not None
        assert verify_password(refreshed.password_hash, "NewPassword123") is True


def test_toggle_active(manage_app):
    with manage_app.app_context():
        manage.create_user("carol", "Password123", "user")
        manage.toggle_active("carol", False)
        assert User.query.filter_by(username="carol").first().is_active is False
        manage.toggle_active("carol", True)
        assert User.query.filter_by(username="carol").first().is_active is True


def test_parse_args_create_user(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["manage.py", "create-user", "--username", "dave", "--password", "Password123"],
    )
    args = manage.parse_args()
    assert args.cmd == "create-user"
    assert args.username == "dave"
    assert args.role == "user"


def test_main_create_user_runs(monkeypatch, tmp_path, capsys):
    app = build_manage_app(tmp_path, monkeypatch)

    def fake_create_app(config):
        return app

    monkeypatch.setattr(manage, "create_app", fake_create_app)
    monkeypatch.setattr(
        manage,
        "parse_args",
        lambda: argparse.Namespace(
            cmd="create-user",
            username="erin",
            password="Password123",
            role="user",
        ),
    )
    manage.main()
    output = capsys.readouterr().out
    assert "Utilisateur créé: erin (user)" in output
    with app.app_context():
        assert User.query.filter_by(username="erin").first() is not None
