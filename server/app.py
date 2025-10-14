from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
import os, logging
from datetime import datetime
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "recordings")
ALLOWED_EXTENSIONS = {'webm', 'wav', 'mp3', 'ogg', 'm4a'}
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH_MB", "100")) * 1024 * 1024

# $2a$14$Dkt5dWAF1BjZbHWOW6ZoxO7cSvZjAKpY47pMNljXPhGThlmdkIu4.

app = Flask(__name__)
app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
    PREFERRED_URL_SCHEME='https',
    SESSION_COOKIE_SECURE=True,
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

@app.get("/health")
def health():
    return {"status": "ok"}, 200

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
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
    f.save(save_path)
    logger.info("Upload OK: %s (%d bytes)", save_path, os.path.getsize(save_path))
    return jsonify({"ok": True, "filename": safe_name}), 201

@app.get("/recordings/<path:fname>")
def serve_recording(fname):
    return send_from_directory(app.config['UPLOAD_FOLDER'], fname)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
