# 🛠️ Installation locale – IoMT Sentinel

## 1. Pré-requis

- Python ≥ 3.9  
- pip  
- Docker (pour Keycloak)  
- OpenSSL  
- NGINX (pour HTTPS et proxy)  

---

## 2. 📜 Génération de certificats locaux

Place un fichier cert.cnf dans server/certs/, puis exécute :

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server/certs/key.pem -out server/certs/cert.pem \
  -config server/certs/cert.cnf -extensions req_ext

---

## 3. 🔐 Lancer Keycloak

docker run -p 8080:8080 \
  -v keycloak_data:/opt/keycloak/data \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  --name keycloak quay.io/keycloak/keycloak:24.0.1 start-dev

Ou avec le script fourni :

./config/keycloak.sh

---

## 4. ⚙️ Configurer Keycloak

Accéder à http://localhost:8080

Configurer les éléments suivants :

- Realm : iot_realm
- Client : iot_backend
  - Type : Confidential
  - Protocole : OpenID Connect
  - Activer : Standard Flow + Direct Access Grants
- Rôles :
  - patient
  - doctor
  - it_admin
- Utilisateur de test : patient_user / test123
- Client Secret : à copier dans sensors/simulator_multi.py

---

## 5. 📦 Installer les dépendances Python

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

---

## 6. 🔧 Configuration NGINX

Créer un fichier /etc/nginx/sites-available/iomt.conf :

server {
    listen 80;
    server_name localhost;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate     /etc/ssl/certs/iomt_cert.pem;
    ssl_certificate_key /etc/ssl/private/iomt_key.pem;

    location / {
        proxy_pass https://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /health {
        proxy_pass https://localhost:8000/health;
    }
}

Activer et recharger :

sudo ln -s /etc/nginx/sites-available/iomt.conf /etc/nginx/sites-enabled/
sudo systemctl restart nginx

---

## 7. 🚀 Lancer le serveur FastAPI

uvicorn server.main:app --host 0.0.0.0 --port 8000 \
  --ssl-keyfile=server/certs/key.pem \
  --ssl-certfile=server/certs/cert.pem

👉 Accès : https://localhost:8000

---

## 8. 🛰️ Lancer les capteurs simulés

Remplacer CLIENT_SECRET dans sensors/simulator_multi.py avec celui généré dans Keycloak.

python sensors/simulator_multi.py

---

## 9. 🧠 Entraîner les modèles de ML

python server/ml/train_models.py

---

## 10. 🧹 Nettoyage Keycloak (optionnel)

python config/delete_all_keycloak.py

---

## ✅ Accès

- **Interface web** : [https://localhost:8000/](https://localhost:8000/)
- **Documentation API** : [https://localhost:8000/docs](https://localhost:8000/docs)

### Dashboards

| Rôle       | Lien du tableau de bord         |
|------------|----------------------------------|
| Doctor     | /dashboard/doctor                |
| IT Admin   | /dashboard/system                |
| Métriques  | /dashboard/metrics               |