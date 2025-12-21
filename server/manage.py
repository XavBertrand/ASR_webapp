from __future__ import annotations

import argparse
import sys

import os

os.environ.setdefault("ASR_WEBAPP_SKIP_AUTOAPP", "1")

from server.app import create_app, log_action
from server.models import User, db
from server.security import hash_password


def create_user(username: str, password: str, role: str, *, activate: bool = True) -> User:
    if role not in {"admin", "user"}:
        raise SystemExit("Rôle invalide, utiliser admin ou user.")
    if (role == "admin" and len(password) < 12) or len(password) < 8:
        raise SystemExit("Mot de passe trop court (user: min 8, admin: min 12).")
    user = User(username=username.strip(), password_hash=hash_password(password), role=role, is_active=activate)
    db.session.add(user)
    db.session.commit()
    log_action(action="create_user", actor=None, target=user, metadata={"cli": True, "role": role}, ip="cli", user_agent="cli")
    return user


def reset_password(username: str, password: str) -> None:
    user = User.query.filter_by(username=username).first()
    if not user:
        raise SystemExit(f"Utilisateur introuvable: {username}")
    if (user.role == "admin" and len(password) < 12) or len(password) < 8:
        raise SystemExit("Mot de passe trop court (user: min 8, admin: min 12).")
    user.password_hash = hash_password(password)
    db.session.commit()
    log_action(action="reset_password", actor=None, target=user, metadata={"cli": True}, ip="cli", user_agent="cli")


def toggle_active(username: str, active: bool) -> None:
    user = User.query.filter_by(username=username).first()
    if not user:
        raise SystemExit(f"Utilisateur introuvable: {username}")
    user.is_active = active
    db.session.commit()
    log_action(action="toggle_active", actor=None, target=user, metadata={"cli": True, "is_active": active}, ip="cli", user_agent="cli")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gestion des utilisateurs ASR WebApp")
    sub = parser.add_subparsers(dest="cmd", required=True)

    ca = sub.add_parser("create-admin", help="Créer un administrateur")
    ca.add_argument("--username", required=True)
    ca.add_argument("--password", required=True)

    cu = sub.add_parser("create-user", help="Créer un utilisateur")
    cu.add_argument("--username", required=True)
    cu.add_argument("--password", required=True)
    cu.add_argument("--role", choices=["user", "admin"], default="user")

    rp = sub.add_parser("reset-password", help="Réinitialiser un mot de passe")
    rp.add_argument("--username", required=True)
    rp.add_argument("--password", required=True)

    du = sub.add_parser("disable-user", help="Désactiver un utilisateur")
    du.add_argument("--username", required=True)

    eu = sub.add_parser("enable-user", help="Activer un utilisateur")
    eu.add_argument("--username", required=True)

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    app = create_app({"SKIP_BOOTSTRAP_ADMIN": True})
    with app.app_context():
        if args.cmd == "create-admin":
            user = create_user(args.username, args.password, "admin")
            print(f"Admin créé: {user.username}")
            return
        if args.cmd == "create-user":
            user = create_user(args.username, args.password, args.role)
            print(f"Utilisateur créé: {user.username} ({user.role})")
            return
        if args.cmd == "reset-password":
            reset_password(args.username, args.password)
            print(f"Mot de passe réinitialisé pour {args.username}")
            return
        if args.cmd == "disable-user":
            toggle_active(args.username, False)
            print(f"Utilisateur désactivé: {args.username}")
            return
        if args.cmd == "enable-user":
            toggle_active(args.username, True)
            print(f"Utilisateur activé: {args.username}")
            return


if __name__ == "__main__":
    try:
        main()
    except SystemExit as exc:
        if exc.code not in (0, None):
            print(exc, file=sys.stderr)
            raise
