#!/bin/bash

# Make a directory for Keycloak data
mkdir -p ./logs

# Launch Keycloak in a Docker container
# The container will be named "keycloak"
# The Keycloak admin user will be created with username "admin" and password "admin"
# The Keycloak server will be accessible at http://localhost:8080
# The Keycloak data will be stored in a Docker volume named "keycloak_data"
# The Keycloak logs will be written to ./logs/keycloak.log
docker run -d \
  --name keycloak \
  -p 8080:8080 \
  -v keycloak_data:/opt/keycloak/data \
  -v "$(pwd)/logs:/opt/keycloak/logs" \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:24.0.1 \
  start-dev --log=file --log-file=/opt/keycloak/logs/keycloak.log

echo "Keycloak launch : http://localhost:8080"
echo "Logs written in ./logs/keycloak.log"
