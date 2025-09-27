#!/bin/bash
echo "🚀 Démarrage de l'application Jetson ASR"

# Créer un environnement virtuel si il n'existe pas
if [ ! -d "venv" ]; then
    echo "📦 Création de l'environnement virtuel..."
    python3 -m venv venv
fi

# Activer l'environnement virtuel
source venv/bin/activate

# Installer les dépendances
echo "⬇️ Installation des dépendances..."
cd server
pip install -r requirements.txt

# Démarrer le serveur
echo "🌟 Lancement du serveur..."
python app.py