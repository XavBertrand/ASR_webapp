from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import logging
from datetime import datetime
from werkzeug.utils import secure_filename
import subprocess

app = Flask(__name__)
CORS(app)  # Permet les requêtes cross-origin

# Configuration
UPLOAD_FOLDER = 'recordings'
WEBAPP_FOLDER = '../webapp'
ALLOWED_EXTENSIONS = {'webm', 'wav', 'mp3', 'ogg', 'm4a'}
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB max

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Créer les dossiers nécessaires
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def convert_to_wav(input_path, output_path):
    """Convertit un fichier audio en WAV avec ffmpeg"""
    try:
        cmd = [
            'ffmpeg', '-i', input_path,
            '-ar', '16000',  # Sample rate 16kHz (standard pour ASR)
            '-ac', '1',  # Mono
            '-y',  # Overwrite output
            output_path
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur conversion ffmpeg: {e}")
        return False
    except FileNotFoundError:
        logger.error("ffmpeg non installé")
        return False


def mock_transcription(audio_path):
    """Simulation de transcription - remplace par ton modèle ASR"""
    import time
    time.sleep(2)  # Simule le temps de traitement
    return {
        "text": "Ceci est une transcription simulée de votre enregistrement audio.",
        "confidence": 0.95,
        "duration": 5.2,
        "language": "fr"
    }


@app.route('/')
def serve_webapp():
    """Sert la webapp principale"""
    return send_from_directory(WEBAPP_FOLDER, 'index.html')


@app.route('/health')
def health_check():
    """Endpoint de santé"""
    return jsonify({
        'status': 'OK',
        'service': 'Jetson ASR Server',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/upload-audio', methods=['POST'])
def upload_audio():
    """Endpoint pour recevoir les fichiers audio"""
    try:
        if 'audio' not in request.files:
            return jsonify({'error': 'Aucun fichier audio trouvé'}), 400

        file = request.files['audio']

        if file.filename == '':
            return jsonify({'error': 'Nom de fichier vide'}), 400

        if file and allowed_file(file.filename):
            # Générer un nom de fichier sécurisé
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            original_ext = file.filename.rsplit('.', 1)[1].lower()
            filename = f"recording_{timestamp}.{original_ext}"

            # Sauvegarder le fichier original
            original_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(original_path)

            logger.info(f"Fichier sauvegardé: {original_path}")

            # Convertir en WAV pour l'ASR
            wav_filename = f"recording_{timestamp}.wav"
            wav_path = os.path.join(app.config['UPLOAD_FOLDER'], wav_filename)

            conversion_success = convert_to_wav(original_path, wav_path)

            if conversion_success:
                logger.info(f"Conversion WAV réussie: {wav_path}")

                # Lancer la transcription (remplace par ton modèle ASR)
                transcription_result = mock_transcription(wav_path)

                return jsonify({
                    'status': 'success',
                    'original_file': filename,
                    'wav_file': wav_filename,
                    'transcription': transcription_result,
                    'message': 'Transcription terminée avec succès'
                })
            else:
                # Si la conversion échoue, on peut quand même traiter le fichier original
                logger.warning("Conversion WAV échouée, utilisation du fichier original")
                transcription_result = mock_transcription(original_path)

                return jsonify({
                    'status': 'partial_success',
                    'original_file': filename,
                    'transcription': transcription_result,
                    'message': 'Transcription réussie sans conversion WAV'
                })

        else:
            return jsonify({'error': 'Type de fichier non autorisé'}), 400

    except Exception as e:
        logger.error(f"Erreur lors du traitement: {str(e)}")
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500


@app.route('/recordings')
def list_recordings():
    """Liste tous les enregistrements"""
    try:
        files = []
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            if allowed_file(filename):
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                stat = os.stat(filepath)
                files.append({
                    'name': filename,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat()
                })

        return jsonify({'recordings': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/recordings/<filename>')
def download_recording(filename):
    """Télécharge un enregistrement"""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        return jsonify({'error': 'Fichier non trouvé'}), 404


if __name__ == '__main__':
    print("🎤 Démarrage du serveur Jetson ASR...")
    print(f"📁 Dossier d'upload: {os.path.abspath(UPLOAD_FOLDER)}")
    print(f"🌐 Interface web: http://localhost:8000")
    print(f"🏥 Health check: http://localhost:8000/health")

    app.run(
        host='0.0.0.0',  # Accessible depuis le réseau local
        port=8000,
        debug=True
    )