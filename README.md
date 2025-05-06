# 🛡️ iomt-sentinel-platform – FastAPI + Keycloak

Ce projet met en place un serveur sécurisé avec **FastAPI** pour gérer les accès à des capteurs de santé simulés, avec authentification via **Keycloak**, des modèles de machine learning pour la détection d’anomalies, et une interface web de monitoring en temps réel.

---

## ⚙️ Prérequis

- Python ≥ 3.9
- Docker + Docker Compose
- pip

---

## 🚀 Étapes de mise en place

---

### 2. 📦 Installer les dépendances

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### 3. 🔐 Lancer Keycloak

```bash
docker run -p 8080:8080 \
-v keycloak_data:/opt/keycloak/data \
-e KEYCLOAK_ADMIN=admin \
-e KEYCLOAK_ADMIN_PASSWORD=admin \
quay.io/keycloak/keycloak:24.0.1 start-dev
```

Ou sinon lancer direct :

```bash
./keycloack.sh
```

---

### 4. ⚙️ Configurer Keycloak (http://localhost:8080)

Les éléments doivent être crées :
- **Realm** : `iot_realm`
- **Client** : `iot_backend` (Confidential, OpenID Connect)
- **Activé** : Standard Flow, Direct Access Grants
- **Rôle** : `device`, `doctor`, `it_admin`
- **Utilisateur** : `role_user` / `test123` (mot de passe non temporaire)
- **Client Secret** : à copier dans `simulator_multi.py`

---

### 5. 🚀 Lancer le serveur FastAPI

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000 \
  --ssl-keyfile=certs/key.pem --ssl-certfile=certs/cert.pem
```

Accès Swagger : [https://localhost:8000/docs](https://localhost:8000/docs)

---

### 6. 🛰️ Lancer le simulateur de capteur

```bash
python simulator_multi.py
```

---

## ✅ Résultat

- Les capteurs envoient des données au backend toutes les Xs
- Le serveur vérifie les tokens et stocke les données
- Il y a différents dashboard accessible depuis https://localhost:8000/

---
