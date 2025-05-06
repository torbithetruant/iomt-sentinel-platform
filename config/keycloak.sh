docker run -p 8080:8080 \
-v keycloak_data:/opt/keycloak/data \
-e KEYCLOAK_ADMIN=admin \
-e KEYCLOAK_ADMIN_PASSWORD=admin \
quay.io/keycloak/keycloak:24.0.1 start-dev
