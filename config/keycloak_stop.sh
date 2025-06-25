#!/bin/bash

echo "⏹️  Arrêt du conteneur Keycloak..."
docker stop keycloak

echo "🧽 Suppression du conteneur Keycloak..."
docker rm keycloak

echo "Keycloak docker has been stopped and removed. You can restart it with the start script."