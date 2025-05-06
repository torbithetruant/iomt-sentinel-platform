#!/bin/bash

# 🛑 Stopper le conteneur
echo "⏹️  Arrêt du conteneur Keycloak..."
docker stop keycloak

# 🧹 Supprimer le conteneur (mais pas le volume de données)
echo "🧽 Suppression du conteneur Keycloak..."
docker rm keycloak

echo "✅ Conteneur Keycloak arrêté et supprimé. Le volume 'keycloak_data' est conservé."