import json
from pathlib import Path

import pytest

from server.app import create_app
from server.models import User, db
from server.security import hash_password


def build_reports_app(tmp_path, monkeypatch, *, config: dict | None = None):
    monkeypatch.setenv("ASR_WEBAPP_SKIP_AUTOAPP", "1")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "SuperSecureAdmin!")
    monkeypatch.setenv("SECRET_KEY", "testing-secret")
    base_root = tmp_path / "data"
    base_root.mkdir(exist_ok=True)
    base_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "UPLOAD_FOLDER": str(base_root),
        "REPORTS_ROOT": str(base_root),
        "REPORTS_QUEUE_DIR": str(tmp_path / "queue"),
        "SESSION_COOKIE_SECURE": False,
    }
    if config:
        base_config.update(config)
    return create_app(base_config)


@pytest.fixture()
def reports_app(tmp_path, monkeypatch):
    return build_reports_app(tmp_path, monkeypatch)


@pytest.fixture()
def reports_client(reports_app):
    return reports_app.test_client()


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


def create_user(app, username, password="Password123", role="user"):
    with app.app_context():
        user = User(username=username, password_hash=hash_password(password), role=role, is_active=True)
        db.session.add(user)
        db.session.commit()
        return user


def write_run(
    base_root: Path,
    user_folder: str,
    run_id: str,
    *,
    status: str = "ready",
    case_name: str = "Case A",
    meeting_date: str = "2024-01-02",
    meeting_report_type: str = "entretien_collaborateur",
    include_pdf: bool = True,
    include_audio: bool = True,
):
    run_root = base_root / user_folder / "runs" / run_id
    run_root.mkdir(parents=True, exist_ok=True)

    artifacts = []
    if include_pdf:
        pdf_rel = f"{user_folder}/runs/{run_id}/report.pdf"
        pdf_path = base_root / pdf_rel
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        pdf_path.write_bytes(b"%PDF-1.4 test")
        artifacts.append({"path": pdf_rel, "name": "report.pdf", "category": "report"})

    audio_rel = f"{user_folder}/recordings/{run_id}.wav"
    if include_audio:
        audio_path = base_root / audio_rel
        audio_path.parent.mkdir(parents=True, exist_ok=True)
        audio_path.write_bytes(b"RIFF....WAVEfmt ")

    manifest = {
        "run_id": run_id,
        "created_at": "2024-01-01T00:00:00Z",
        "status": status,
        "audio": {
            "path": audio_rel,
            "original_filename": "original.wav",
            "saved_filename": f"{run_id}.wav",
        },
        "artifacts": artifacts,
        "meta": {
            "meeting_date": meeting_date,
            "meeting_report_type": meeting_report_type,
            "case_name": case_name,
        },
    }
    (run_root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    meta = {
        "run_id": run_id,
        "user_folder": user_folder,
        "meeting_date": meeting_date,
        "meeting_report_type": meeting_report_type,
        "case_name": case_name,
    }
    (run_root / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return run_root


def test_reports_and_runs_access_control(reports_app, reports_client):
    base_root = Path(reports_app.config["REPORTS_ROOT"])

    admin_report = base_root / "admin" / "output" / "pdf" / "admin.pdf"
    admin_report.parent.mkdir(parents=True, exist_ok=True)
    admin_report.write_bytes(b"%PDF-1.4 admin")
    admin_run_artifact = base_root / "admin" / "runs" / "run1" / "artifact.pdf"
    admin_run_artifact.parent.mkdir(parents=True, exist_ok=True)
    admin_run_artifact.write_bytes(b"%PDF-1.4 admin artifact")

    create_user(reports_app, "user1")
    user_report = base_root / "user1" / "output" / "pdf" / "user.pdf"
    user_report.parent.mkdir(parents=True, exist_ok=True)
    user_report.write_bytes(b"%PDF-1.4 user")
    user_run_artifact = base_root / "user1" / "runs" / "run1" / "artifact.pdf"
    user_run_artifact.parent.mkdir(parents=True, exist_ok=True)
    user_run_artifact.write_bytes(b"%PDF-1.4 user artifact")

    login(reports_client, "admin", "SuperSecureAdmin!")
    assert reports_client.get("/reports/admin/output/pdf/admin.pdf").status_code == 200
    assert reports_client.get("/runs/admin/runs/run1/artifact.pdf").status_code == 200
    assert reports_client.get("/reports/user1/output/pdf/user.pdf").status_code == 200

    reports_client.post("/logout", data={"csrf_token": set_csrf(reports_client)})
    login(reports_client, "user1", "Password123")
    assert reports_client.get("/reports/user1/output/pdf/user.pdf").status_code == 200
    assert reports_client.get("/runs/user1/runs/run1/artifact.pdf").status_code == 200
    assert reports_client.get("/reports/admin/output/pdf/admin.pdf").status_code == 403
    assert reports_client.get("/runs/admin/runs/run1/artifact.pdf").status_code == 403


def test_api_reports_lists_runs(reports_app, reports_client):
    base_root = Path(reports_app.config["REPORTS_ROOT"])
    run_id = "run-1"
    write_run(base_root, "admin", run_id)

    login(reports_client, "admin", "SuperSecureAdmin!")
    resp = reports_client.get("/api/reports")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)
    assert len(data) == 1
    entry = data[0]
    assert entry["run_id"] == run_id
    assert entry["status"] == "ready"
    assert entry["report_filename"] == "report.pdf"
    assert entry["download_url"] == f"/runs/admin/runs/{run_id}/report.pdf"
    assert entry["audio_url"] == f"/recordings/admin/recordings/{run_id}.wav"


def test_api_runs_rename_updates_manifest_and_meta(reports_app, reports_client):
    base_root = Path(reports_app.config["REPORTS_ROOT"])
    run_id = "run-rename"
    run_root = write_run(base_root, "admin", run_id, case_name="Old Case")

    login(reports_client, "admin", "SuperSecureAdmin!")
    csrf = set_csrf(reports_client)
    resp = reports_client.post(
        f"/api/runs/{run_id}/rename",
        json={"case_name": "New Case"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    manifest = json.loads((run_root / "manifest.json").read_text(encoding="utf-8"))
    meta = json.loads((run_root / "meta.json").read_text(encoding="utf-8"))
    assert manifest["meta"]["case_name"] == "New Case"
    assert meta["case_name"] == "New Case"

    csrf = set_csrf(reports_client)
    bad = reports_client.post(
        "/api/runs/../rename",
        json={"case_name": "Invalid"},
        headers={"X-CSRF-Token": csrf},
    )
    assert bad.status_code == 400


def test_api_runs_rerun_report_creates_queue_job(reports_app, reports_client):
    base_root = Path(reports_app.config["REPORTS_ROOT"])
    run_id = "run-ready"
    run_root = write_run(base_root, "admin", run_id, status="ready")

    login(reports_client, "admin", "SuperSecureAdmin!")
    csrf = set_csrf(reports_client)
    resp = reports_client.post(
        f"/api/runs/{run_id}/rerun-report",
        json={},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200

    pending_dir = Path(reports_app.config["REPORTS_QUEUE_DIR"]) / "pending"
    jobs = list(pending_dir.glob("*_report_meta.json"))
    assert len(jobs) == 1
    payload = json.loads(jobs[0].read_text(encoding="utf-8"))
    assert payload["run_id"] == run_id
    assert payload["report_only"] is True
    assert payload["user_folder"] == "admin"

    manifest = json.loads((run_root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "queued"


def test_api_runs_rerun_report_requires_ready_status(reports_app, reports_client):
    base_root = Path(reports_app.config["REPORTS_ROOT"])
    run_id = "run-processing"
    write_run(base_root, "admin", run_id, status="processing")

    login(reports_client, "admin", "SuperSecureAdmin!")
    csrf = set_csrf(reports_client)
    resp = reports_client.post(
        f"/api/runs/{run_id}/rerun-report",
        json={},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 409


def test_trash_restore_delete_flow(reports_app, reports_client):
    base_root = Path(reports_app.config["REPORTS_ROOT"])
    run_id = "run-trash"
    write_run(base_root, "admin", run_id, status="ready")

    login(reports_client, "admin", "SuperSecureAdmin!")
    csrf = set_csrf(reports_client)
    resp = reports_client.post(
        f"/api/runs/{run_id}/trash",
        json={},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200

    trash_root = base_root / "admin" / "trash" / run_id
    assert trash_root.is_dir()
    assert not (base_root / "admin" / "runs" / run_id).exists()

    listing = reports_client.get("/api/trash")
    assert listing.status_code == 200
    items = listing.get_json()
    assert any(item["run_id"] == run_id and item["status"] == "trashed" for item in items)

    csrf = set_csrf(reports_client)
    restore = reports_client.post(
        f"/api/trash/{run_id}/restore",
        json={},
        headers={"X-CSRF-Token": csrf},
    )
    assert restore.status_code == 200
    restored_id = restore.get_json()["run_id"]
    assert (base_root / "admin" / "runs" / restored_id).is_dir()

    csrf = set_csrf(reports_client)
    reports_client.post(
        f"/api/runs/{restored_id}/trash",
        json={},
        headers={"X-CSRF-Token": csrf},
    )
    csrf = set_csrf(reports_client)
    deleted = reports_client.post(
        f"/api/trash/{restored_id}/delete",
        json={},
        headers={"X-CSRF-Token": csrf},
    )
    assert deleted.status_code == 200
    assert not (base_root / "admin" / "trash" / restored_id).exists()
