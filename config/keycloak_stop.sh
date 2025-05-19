#!/bin/bash

# Stop the Keycloak container
echo "⏹️  Arrêt du conteneur Keycloak..."
docker stop keycloak

# Delete the Keycloak container but keep the volume
echo "🧽 Suppression du conteneur Keycloak..."
docker rm keycloak

echo "Keycloak docker has been stopped and removed. You can restart it with the start script."