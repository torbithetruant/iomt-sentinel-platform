######################################################################
# Récupération des logs Keycloak pour l'instant ça ne marche pas
######################################################################

import asyncio
import os
from datetime import datetime

KEYCLOAK_LOG_FILE = "../config/logs/keycloak.log"
AUTH_LOG = "logs/auth_keycloak.log"
ADMIN_LOG = "logs/admin_keycloak.log"
os.makedirs("logs", exist_ok=True)

def parse_log_line(line: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if "LOGIN_" in line:
        with open(AUTH_LOG, "a") as f:
            f.write(f"[{timestamp}] {line.strip()}\n")
    elif "Admin event" in line or "operationType" in line:
        with open(ADMIN_LOG, "a") as f:
            f.write(f"[{timestamp}] {line.strip()}\n")

async def monitor_keycloak_log():
    last_size = 0

    while True:
        try:
            if not os.path.exists(KEYCLOAK_LOG_FILE):
                print("Fichier de log Keycloak introuvable.")
            else:
                current_size = os.path.getsize(KEYCLOAK_LOG_FILE)
                if current_size > last_size:
                    with open(KEYCLOAK_LOG_FILE, "r") as f:
                        f.seek(last_size)
                        new_lines = f.readlines()
                        for line in new_lines:
                            parse_log_line(line)
                    last_size = current_size

        except Exception as e:
            print(f"Erreur surveillance log Keycloak : {e}")

        await asyncio.sleep(60)
