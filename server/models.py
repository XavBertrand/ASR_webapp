from __future__ import annotations

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, index=True, nullable=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # "admin" or "user"
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    totp_secret = db.Column(db.String(255))
    totp_encrypted = db.Column(db.Boolean, default=False, nullable=False)
    twofa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    last_login_at = db.Column(db.DateTime)

    recovery_codes = db.relationship("RecoveryCode", back_populates="user", cascade="all, delete-orphan")
    reset_tokens = db.relationship("PasswordResetToken", back_populates="user", cascade="all, delete-orphan")


class RecoveryCode(db.Model):
    __tablename__ = "recovery_codes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    code_hash = db.Column(db.String(255), nullable=False)
    used_at = db.Column(db.DateTime)

    user = db.relationship("User", back_populates="recovery_codes")


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    actor_username_snapshot = db.Column(db.String(80))
    action = db.Column(db.String(64), nullable=False, index=True)
    target_user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    target_username_snapshot = db.Column(db.String(80))
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(256))
    metadata_json = db.Column(db.Text)


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(128), nullable=False, unique=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    used_at = db.Column(db.DateTime)
    request_ip = db.Column(db.String(64))
    request_user_agent = db.Column(db.String(256))

    user = db.relationship("User", back_populates="reset_tokens")
