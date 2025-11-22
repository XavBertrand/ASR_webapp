import io
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
    assert saved_name.startswith("audio_")
    assert saved_name.endswith(".wav")
    assert (upload_dir / saved_name).read_bytes() == audio_bytes

    fetch_resp = client.get(f"/recordings/{saved_name}")
    assert fetch_resp.status_code == 200
    assert fetch_resp.data == audio_bytes
