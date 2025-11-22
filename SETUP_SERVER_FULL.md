# ASR Web App – Full Server Setup Guide (WSL + DuckDNS + Caddy + HTTPS)

This guide walks through every step required to expose the ASR Web App securely on the internet using WSL2, DuckDNS, and Caddy.

## Overview
- WSL2 backend (Flask + Gunicorn)
- Caddy reverse proxy with HTTPS/HTTP3, compression, and static serving
- DuckDNS subdomain with automatic IP renewal
- Let’s Encrypt SSL certificates
- HTTP Basic Authentication
- Worldwide access through your home router

## 1. Requirements Summary
You need the following components prepared:
- DuckDNS domain
- Windows PC running WSL2
- Router with NAT/PAT administration access
- Repository cloned to `~/ASR_webapp`
- Python virtual environment set up
- `caddy` and `ffmpeg` installed inside WSL
- Windows `portproxy` rules configured

## 2. DuckDNS Setup
### 2.1 Create a Domain
1. Visit https://www.duckdns.org and log in.
2. Choose a subdomain, e.g. `ai-actionavocats`.
3. Resulting FQDN: `ai-actionavocats.duckdns.org`.

### 2.2 Install DuckDNS Cron Updater
```bash
mkdir -p ~/duckdns
cd ~/duckdns
echo "url=\"https://www.duckdns.org/update?domains=ai-actionavocats&token=YOURTOKEN&ip=\" " > duck.sh
chmod 700 duck.sh
(crontab -l ; echo "*/5 * * * * ~/duckdns/duck.sh >/dev/null 2>&1") | crontab -
```

### 2.3 Test DNS Resolution
```bash
ping ai-actionavocats.duckdns.org
```

## 3. Router NAT/PAT (Livebox)
Forward these ports from your router to the **Windows host** (not the WSL VM). Reserve this LAN IP in your router to stop it from changing.

| External Port | Protocol | Internal IP (Windows) | Internal Port |
| --- | --- | --- | --- |
| 80 | TCP | 192.168.1.18 | 80 |
| 443 | TCP | 192.168.1.18 | 443 |

## 4. Windows Portproxy → WSL
### 4.1 Get the Current WSL IP
`WSL_IP` is different from the Windows IP used in the router table; it is usually in the `172.x.x.x` range and **changes after each reboot**.
```powershell
wsl hostname -I
```

### 4.2 Configure Portproxy Rules
Run the commands below in **PowerShell Admin** every time the WSL IP changes. Replace `WSL_IP` with the value from step 4.1 (or reuse the snippet).
```powershell
$WSLIP = (wsl hostname -I).Trim()
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=80  connectaddress=$WSLIP connectport=80
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=443 connectaddress=$WSLIP connectport=443
```

### 4.3 Allow Traffic in Windows Firewall
```powershell
netsh advfirewall firewall add rule name="Caddy 80"  dir=in action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="Caddy 443" dir=in action=allow protocol=TCP localport=443
```

## 5. WSL Environment
### 5.1 Activate the Python Virtual Environment
```bash
cd ~/ASR_webapp
source .venv/bin/activate
```

### 5.2 Install System and Python Dependencies
```bash
sudo apt-get update
sudo apt-get install -y caddy ffmpeg
uv sync
```

## 6. Configure Caddy (HTTPS + Reverse Proxy)
### 6.1 Generate the BasicAuth Password Hash
```bash
caddy hash-password --plaintext 'MyPassword'
```

### 6.2 Create `~/Caddyfile.public`
Replace `REPLACE_WITH_HASH` below with the generated hash.

```caddyfile
{
    admin off
}

ai-actionavocats.duckdns.org {
    encode zstd gzip

    basic_auth {
        xavier $2a$14$REPLACE_WITH_HASH
    }

    @health {
        path /health
    }
    reverse_proxy @health 127.0.0.1:8000

    @uploads {
        path /upload*
    }
    reverse_proxy @uploads 127.0.0.1:8000 {
        transport http {
            read_timeout  300s
            write_timeout 300s
            dial_timeout  10s
        }
    }

    root * /home/xavier/ASR_webapp/webapp
    file_server
}
```

## 7. Running the Server
### 7.1 Start Gunicorn
> ⚠️ `server.app` must be importable, so either run the command from the repository root or pass `--chdir ~/ASR_webapp`. Otherwise Gunicorn raises `ModuleNotFoundError: No module named 'server'`.

**Option A — depuis le dossier du projet**
```bash
cd ~/ASR_webapp
source .venv/bin/activate
gunicorn -w 2 -b 127.0.0.1:8000 server.app:app
```

**Option B — depuis n'importe où**
```bash
source ~/ASR_webapp/.venv/bin/activate
gunicorn --chdir ~/ASR_webapp -w 2 -b 127.0.0.1:8000 server.app:app
```

### 7.2 Start Caddy (new terminal)
```bash
caddy fmt --overwrite ~/Caddyfile.public
sudo pkill -f 'caddy run' || true
sudo caddy run --config ~/Caddyfile.public
```

- Access the app at https://ai-actionavocats.duckdns.org/.
- Test the API:

```bash
curl -vk https://ai-actionavocats.duckdns.org/health -u xavier:MyPassword

# Test local sans passer par le routeur (utile si votre box ne supporte pas le loopback)
curl -vk --resolve ai-actionavocats.duckdns.org:443:127.0.0.1 \
     https://ai-actionavocats.duckdns.org/health -u xavier:MyPassword
```

> ℹ️ `https://localhost:8443` n'est accessible que lorsque vous lancez le mode local décrit en section 9 avec `Caddyfile.local`. Quand `Caddyfile.public` est utilisé, testez toujours avec votre domaine DuckDNS (port 443).

## 8. Manage BasicAuth Users
### Add a User
```bash
caddy hash-password --plaintext 'DelphinePassword'
```

Update the `basic_auth` block:

```caddyfile
basic_auth {
    xavier   HASH_XAV
    delphine HASH_DEL
}
```

Restart Caddy afterward. To remove a user, delete the corresponding line and restart again.

## 9. Local-only HTTPS Mode (Optional)
Create `~/Caddyfile.local`:

```caddyfile
https://localhost:8443 {
    tls internal
    basic_auth {
        xavier HASH
    }
    reverse_proxy 127.0.0.1:8000
    root * /home/xavier/ASR_webapp/webapp
    file_server
}
```

Run Caddy locally:
```bash
caddy run --config ~/Caddyfile.local
```

## 10. Quick Commands Summary
### Start Backend
```bash
cd ~/ASR_webapp
source .venv/bin/activate
gunicorn -w 2 -b 127.0.0.1:8000 server.app:app
```

### Start Caddy
```bash
sudo caddy run --config ~/Caddyfile.public
```

### Stop Everything
```bash
sudo pkill -f 'caddy run'
pkill -f "gunicorn .*server.app:app"
```

### Generate Password
```bash
caddy hash-password --plaintext 'MyPassword'
```

### Test Health Endpoint
```bash
curl -vk https://ai-actionavocats.duckdns.org/health -u xavier:MyPassword
```

### Test Health Endpoint (bypass router loopback)
```bash
curl -vk --resolve ai-actionavocats.duckdns.org:443:127.0.0.1 \
     https://ai-actionavocats.duckdns.org/health -u xavier:MyPassword
```

## 11. Dépannage si l’accès extérieur échoue
Si le site reste inaccessible depuis la 4G ou l’extérieur, effectue les vérifications suivantes :

1. **IP publique à jour** – Dans WSL, compare `curl https://icanhazip.com` avec `ping ai-actionavocats.duckdns.org`. Si ça diffère, relance `~/duckdns/duck.sh` ou corrige le token.
2. **Redirection Livebox** – Assure-toi que les ports 80/443 sont NATés vers l’adresse IP *Windows* actuelle (ex. 192.168.1.18). Réserve cette IP dans la box pour éviter tout changement.
3. **Portproxy Windows → WSL** – L’IP WSL change après un redémarrage. Dans PowerShell administrateur :
   ```powershell
   wsl hostname -I
   netsh interface portproxy show all
   ```
   Supprime/recrée les règles si `connectaddress` ne correspond plus à l’IP de WSL.
4. **Pare-feu Windows** – Vérifie que les règles `Caddy 80` et `Caddy 443` sont actives :
   ```powershell
   netsh advfirewall firewall show rule name="Caddy 443"
   ```
   Recrée-les si nécessaire.
5. **Caddy écoute sur 0.0.0.0** – Dans WSL, pendant que Caddy tourne, vérifie `sudo ss -ltnp '( sport = :443 )'` pour confirmer que le port est ouvert.
6. **Test externe** – Utilise un smartphone en 4G ou un site comme *yougetsignal.com/open-ports* pour contrôler que les ports 80/443 de ton IP publique sont visibles. Si ce n’est pas le cas, le blocage vient toujours du NAT/pare-feu.

Une fois tous ces points validés, l’accès via `https://ai-actionavocats.duckdns.org` depuis l’extérieur doit répondre `{"status":"ok"}` sur `/health`.

## 12. Déploiement automatisé via Docker
Si tu préfères éviter toutes les étapes WSL (installation Python, Caddy, cron DuckDNS, etc.), l’image Docker fournie exécute désormais exactement les mêmes actions : Gunicorn → Caddy (HTTPS/HTTP/3, BasicAuth) → DuckDNS, en supposant seulement que ta Livebox redirige 80/443 vers la machine où tourne Docker.

1. **Construis l’image** (une seule fois ou via CI) :
   ```bash
   docker build -t asr-webapp:latest .
   ```
2. **Prépare les variables sensibles** dans un fichier `.env` :
   ```bash
   cat <<'EOF' > asr.env
   CADDY_DOMAIN=ai-actionavocats.duckdns.org
   CADDY_EMAIL=you@example.com        # -> Let's Encrypt notifications (optionnel)
   BASIC_AUTH_USER=xavier
   BASIC_AUTH_PASSWORD=MotDePasseFort
   DUCKDNS_DOMAIN=ai-actionavocats
   DUCKDNS_TOKEN=TON_TOKEN_DUCKDNS
   EOF
   ```
3. **Lance le conteneur** (host network = bind direct sur 80/443/8000) :
   ```bash
   docker run -d \
     --name asr-webapp \
     --network host \
     --env-file asr.env \
     -v asr-recordings:/data/recordings \
     -v caddy-data:/root/.local/share/caddy \
     -v caddy-config:/root/.config/caddy \
     asr-webapp:latest
   ```
   Pas d’option `--network host` ? publie les ports : `-p 80:80 -p 443:443 -p 8000:8000`.

### Comportement de l’image Docker
- Installation automatique des dépendances Python, ffmpeg, Caddy.
- Lancement de Gunicorn (`server.app:app`) exactement comme la commande de la section 7.
- Démarrage de Caddy avec le même Caddyfile (HTTPS, BasicAuth, reverse proxy /upload, fichiers statiques `webapp/`).
- Mise à jour DuckDNS toutes les 5 minutes si `DUCKDNS_DOMAIN`/`DUCKDNS_TOKEN` sont fournis.
- Persistance :
  - `/data/recordings` → uploads (à monter sur un volume/host).
  - `/root/.local/share/caddy` et `/root/.config/caddy` → certificats et état TLS.

### Variables reconnues

| Variable | Rôle | Défaut |
| --- | --- | --- |
| `CADDY_DOMAIN` | Domaine public servi par Caddy (DuckDNS) | `localhost` |
| `CADDY_EMAIL` | Email ACME (Let’s Encrypt) | vide |
| `BASIC_AUTH_USER` | Utilisateur BasicAuth | `xavier` |
| `BASIC_AUTH_PASSWORD` | Mot de passe en clair (hash calculé automatiquement) | `MyPassword` |
| `BASIC_AUTH_PASSWORD_HASH` | Hash `caddy hash-password` (écrase le mot de passe en clair) | vide |
| `BASIC_AUTH_EXTRA_USERS` | Paires `user hash` séparées par `;` | vide |
| `DUCKDNS_DOMAIN` / `DUCKDNS_TOKEN` | Active l’auto-update DuckDNS | désactivé |
| `DUCKDNS_INTERVAL` | Intervalle en secondes pour DuckDNS | `300` |
| `GUNICORN_HOST/PORT/WORKERS/THREADS/TIMEOUT` | Options Gunicorn | `0.0.0.0` / `8000` / `4` / `4` / `300` |
| `UPLOAD_FOLDER` | Chemin pour les uploads | `/data/recordings` |

Ainsi l’unique intervention manuelle restante est de fournir le domaine DuckDNS, le token, les identifiants BasicAuth, puis de lancer le conteneur (et bien sûr de maintenir la redirection Livebox 80/443 vers l’hôte Docker). Toutes les étapes 5 à 10 de ce guide sont exécutées à l’intérieur de l’image.*** End Patch
