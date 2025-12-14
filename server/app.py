from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
import json, os, logging
from datetime import datetime
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "recordings")
ALLOWED_EXTENSIONS = {'webm', 'wav', 'mp3', 'ogg', 'm4a', 'mp4'}
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH_MB", "100")) * 1024 * 1024
DEFAULT_ASR_PROMPT = os.environ.get("DEFAULT_ASR_PROMPT", "Kleos, Pennylane, CJD, Manupro, El Moussaoui")
MEETING_REPORT_TYPES = [
    "entretien_collaborateur",
    "entretien_client_particulier_contentieux",
    "entretien_client_professionnel_conseil",
    "entretien_client_professionnel_contentieux",
]
DEFAULT_MEETING_REPORT_TYPE = MEETING_REPORT_TYPES[0]

# $2a$14$Dkt5dWAF1BjZbHWOW6ZoxO7cSvZjAKpY47pMNljXPhGThlmdkIu4.

app = Flask(__name__)
app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
    PREFERRED_URL_SCHEME='https',
    SESSION_COOKIE_SECURE=True,
    JSON_AS_ASCII=False,
)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

# Pour le test local, autorise https://localhost:8443
CORS(app, resources={r"/*": {"origins": [
        "https://localhost:8443",
        "https://ai-actionavocats.duckdns.org",
        "https://192.168.1.18:8443"   # <-- ajoute ton IP Wi-Fi ici
]}},
     supports_credentials=False, methods=["GET","POST","OPTIONS"],
     allow_headers=["Content-Type","Authorization"])

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def normalize_meeting_date(raw: str | None) -> str:
    if not raw:
        return datetime.utcnow().date().isoformat()
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date().isoformat()
    except ValueError:
        raise ValueError("meeting_date doit respecter le format YYYY-MM-DD")

def extract_metadata(req_form) -> dict:
    meeting_report_type = (req_form.get("meeting_report_type") or DEFAULT_MEETING_REPORT_TYPE).strip()
    if meeting_report_type not in MEETING_REPORT_TYPES:
        raise ValueError("meeting_report_type invalide")

    asr_prompt = (req_form.get("asr_prompt") or DEFAULT_ASR_PROMPT).strip()
    speaker_context = (req_form.get("speaker_context") or "").strip()
    meeting_date = normalize_meeting_date(req_form.get("meeting_date"))

    return {
        "asr_prompt": asr_prompt,
        "speaker_context": speaker_context,
        "meeting_date": meeting_date,
        "meeting_report_type": meeting_report_type,
    }

@app.get("/health")
def health():
    return {"status": "ok"}, 200


def current_user_folder() -> str:
    """Derive a safe folder name from the authenticated user (Basic Auth via Caddy)."""
    username = ""
    if request.authorization and request.authorization.username:
        username = request.authorization.username
    elif request.headers.get("X-Authenticated-User"):
        username = request.headers.get("X-Authenticated-User", "")
    username = username.strip() or "anonymous"
    safe = secure_filename(username).strip("._")
    return safe or "anonymous"

@app.post("/upload")
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "Aucun fichier dans la requête"}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({"error": "Nom de fichier vide"}), 400
    if not allowed_file(f.filename):
        return jsonify({"error": f"Extension non autorisée. Autorisées: {sorted(ALLOWED_EXTENSIONS)}"}), 400
    stem, ext = os.path.splitext(secure_filename(f.filename))
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_name = f"{stem}_{ts}{ext.lower()}"
    user_folder = current_user_folder()
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], user_folder)
    os.makedirs(user_dir, exist_ok=True)
    save_path = os.path.join(user_dir, safe_name)
    try:
        metadata = extract_metadata(request.form)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    f.save(save_path)
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

    logger.info("Upload OK: %s (%d bytes)", save_path, os.path.getsize(save_path))
    return jsonify({"ok": True, "filename": safe_name, "metadata": metadata}), 201

@app.get("/recordings/<path:fname>")
def serve_recording(fname):
    return send_from_directory(app.config['UPLOAD_FOLDER'], fname)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
