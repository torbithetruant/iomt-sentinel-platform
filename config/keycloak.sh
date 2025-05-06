#!/bin/bash

# 📁 Créer le dossier de logs s'il n'existe pas
mkdir -p ./logs

# 🐳 Lancer Keycloak avec volume persistant + log fichier
docker run -d \
  --name keycloak \
  -p 8080:8080 \
  -v keycloak_data:/opt/keycloak/data \
  -v "$(pwd)/logs:/opt/keycloak/logs" \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:24.0.1 \
  start-dev --log=file --log-file=/opt/keycloak/logs/keycloak.log

echo "✅ Keycloak lancé sur http://localhost:8080"
echo "📁 Logs écrits dans ./logs/keycloak.log"
