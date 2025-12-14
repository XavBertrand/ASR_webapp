import io
import json
from datetime import datetime
import pytest
from server import app as app_module


@pytest.fixture()
def test_client(tmp_path):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    app_module.app.config.update(
        UPLOAD_FOLDER=str(upload_dir),
        TESTING=True,
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    )
    return app_module.app.test_client(), upload_dir


def test_health_endpoint(test_client):
    client, _ = test_client
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_allowed_file_validation():
    assert app_module.allowed_file("sample.wav")
    assert app_module.allowed_file("voice.WEBM")
    assert not app_module.allowed_file("readme.txt")
    assert not app_module.allowed_file("noextension")


def test_upload_missing_file(test_client):
    client, _ = test_client
    resp = client.post("/upload", data={}, content_type="multipart/form-data")
    assert resp.status_code == 400
    assert "Aucun fichier" in resp.get_json()["error"]


def test_upload_rejects_bad_extension(test_client):
    client, _ = test_client
    resp = client.post(
        "/upload",
        data={"file": (io.BytesIO(b"fake data"), "notes.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert "Extension non autorisée" in resp.get_json()["error"]


def test_upload_and_serve_recording(test_client):
    client, upload_dir = test_client
    audio_bytes = b"RIFF....WAVEfmt "  # minimal payload; content is not parsed

    upload_resp = client.post(
        "/upload",
        data={"file": (io.BytesIO(audio_bytes), "audio.wav")},
        content_type="multipart/form-data",
    )
    assert upload_resp.status_code == 201
    payload = upload_resp.get_json()
    assert payload["ok"] is True
    saved_name = payload["filename"]
    user_dir = upload_dir / payload["metadata"]["user_folder"]
    assert saved_name.startswith("audio_")
    assert saved_name.endswith(".wav")
    saved_path = user_dir / saved_name
    assert saved_path.read_bytes() == audio_bytes
    meta_path = user_dir / f"{saved_name.rsplit('.', 1)[0]}_meta.json"
    assert meta_path.exists()
    metadata = json.loads(meta_path.read_text())
    assert metadata["saved_filename"] == saved_name
    assert metadata["meeting_report_type"] == app_module.DEFAULT_MEETING_REPORT_TYPE
    assert metadata["meeting_date"] == datetime.utcnow().date().isoformat()
    dir_stat = user_dir.stat()
    file_stat = saved_path.stat()
    meta_stat = meta_path.stat()
    assert dir_stat.st_uid == upload_dir.stat().st_uid
    assert dir_stat.st_gid == upload_dir.stat().st_gid
    assert file_stat.st_gid == dir_stat.st_gid
    assert meta_stat.st_gid == dir_stat.st_gid
    assert (file_stat.st_mode & 0o666) == 0o664
    assert (meta_stat.st_mode & 0o666) == 0o664
    assert (dir_stat.st_mode & 0o2775) == 0o2775

    fetch_resp = client.get(f"/recordings/{payload['metadata']['user_folder']}/{saved_name}")
    assert fetch_resp.status_code == 200
    assert fetch_resp.data == audio_bytes


def test_upload_saves_custom_metadata(test_client):
    client, upload_dir = test_client
    audio_bytes = b"RIFF....WAVEfmt "
    meeting_date = datetime.utcnow().date().isoformat()

    upload_resp = client.post(
        "/upload",
        data={
            "file": (io.BytesIO(audio_bytes), "audio.wav"),
            "asr_prompt": "Mots cles test",
            "speaker_context": "Deux interlocuteurs",
            "meeting_date": meeting_date,
            "meeting_report_type": "entretien_client_professionnel_conseil",
        },
        content_type="multipart/form-data",
    )
    assert upload_resp.status_code == 201
    payload = upload_resp.get_json()
    saved_name = payload["filename"]
    meta_path = upload_dir / payload["metadata"]["user_folder"] / f"{saved_name.rsplit('.', 1)[0]}_meta.json"
    metadata = json.loads(meta_path.read_text())
    assert metadata["asr_prompt"] == "Mots cles test"
    assert metadata["speaker_context"] == "Deux interlocuteurs"
    assert metadata["meeting_date"] == meeting_date
    assert metadata["meeting_report_type"] == "entretien_client_professionnel_conseil"


def test_upload_rejects_bad_report_type(test_client):
    client, _ = test_client
    resp = client.post(
        "/upload",
        data={
            "file": (io.BytesIO(b"fake"), "audio.wav"),
            "meeting_report_type": "non_supporte",
        },
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert "invalide" in resp.get_json()["error"]
