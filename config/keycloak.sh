#!/bin/bash

mkdir -p ./logs

docker run -d --name keycloak -p 8080:8080 -v keycloak_data:/opt/keycloak/data -v "${PWD}/logs:/opt/keycloak/logs" -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:24.0.1 start-dev --log=file --log-file=/opt/keycloak/logs/keycloak.log