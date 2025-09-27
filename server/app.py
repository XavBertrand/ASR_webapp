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


def create_ssl_cert():
    """Crée un certificat SSL auto-signé pour le développement"""
    import ssl
    from datetime import datetime, timedelta
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress
        import socket

        # Générer une clé privée
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Obtenir l'IP locale
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        # Créer le certificat
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Jetson ASR Dev"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("*.localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.IPAddress(ipaddress.IPv4Address(local_ip)),
            ]),
            critical=False,
        ).sign(key, hashes.SHA256())

        # Sauvegarder les fichiers
        os.makedirs('ssl', exist_ok=True)

        with open('ssl/cert.pem', 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open('ssl/key.pem', 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        logger.info("Certificats SSL créés dans le dossier ssl/")
        return True

    except ImportError:
        logger.warning("Module cryptography non installé - HTTPS non disponible")
        logger.info("Pour installer: pip install cryptography")
        return False
    except Exception as e:
        logger.error(f"Erreur création certificat SSL: {e}")
        return False


if __name__ == '__main__':
    print("🎤 Démarrage du serveur Jetson ASR...")
    print(f"📁 Dossier d'upload: {os.path.abspath(UPLOAD_FOLDER)}")

    # Tenter de créer les certificats SSL
    ssl_available = False
    if not os.path.exists('ssl/cert.pem') or not os.path.exists('ssl/key.pem'):
        ssl_available = create_ssl_cert()
    else:
        ssl_available = True

    # Déterminer l'IP locale
    import socket

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    if ssl_available and os.path.exists('ssl/cert.pem'):
        print(f"🔒 HTTPS Interface: https://localhost:8000")
        print(f"📱 HTTPS Mobile:    https://{local_ip}:8000")
        print(f"🏥 Health check:    https://localhost:8000/health")
        print("⚠️  Accepter le certificat auto-signé dans le navigateur")

        # Lancer avec SSL
        context = ('ssl/cert.pem', 'ssl/key.pem')
        app.run(
            host='0.0.0.0',
            port=8000,
            debug=True,
            ssl_context=context
        )
    else:
        print(f"⚠️  HTTP Interface:  http://localhost:8000")
        print(f"⚠️  HTTP Mobile:     http://{local_ip}:8000")
        print(f"🏥 Health check:    http://localhost:8000/health")
        print("⚠️  ATTENTION: L'enregistrement audio ne marchera pas sur mobile sans HTTPS")

        app.run(
            host='0.0.0.0',
            port=8000,
            debug=True
        )