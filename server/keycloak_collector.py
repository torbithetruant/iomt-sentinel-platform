import requests
import os
from datetime import datetime
import urllib3
import asyncio

urllib3.disable_warnings()

KEYCLOAK_URL = "http://localhost:8080"
REALM = "iot_realm"
USERNAME = "admin"
PASSWORD = "admin"
CLIENT_ID = "admin-cli"
CERT_PATH = "certs/cert.pem"
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

def get_admin_token():
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "username": USERNAME,
        "password": PASSWORD
    }
    r = requests.post(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data=data,
        verify=CERT_PATH
    )
    r.raise_for_status()
    return r.json()["access_token"]

def get_events(url, token, limit=100):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers, verify=CERT_PATH)
    r.raise_for_status()
    return r.json()

def write_log(file_path, entries):
    with open(file_path, "a") as f:
        for e in entries:
            ts = datetime.fromtimestamp(e["time"] / 1000).strftime("%Y-%m-%d %H:%M:%S")
            if "type" in e:
                log = f"[{ts}] {e['type']} – {e.get('ipAddress', '-')}"
                if e.get("error"):
                    log += f" ❌ {e['error']}"
                f.write(log + "\n")
            elif "operationType" in e:
                log = f"[{ts}] {e['operationType']} – {e.get('resourcePath', '-')}"
                f.write(log + "\n")

async def collect_keycloak_logs_periodically():
    while True:
        try:
            token = get_admin_token()
            auth_events = get_events(f"{KEYCLOAK_URL}/admin/realms/{REALM}/events?max=100", token)
            admin_events = get_events(f"{KEYCLOAK_URL}/admin/realms/{REALM}/admin-events?max=100", token)

            write_log(os.path.join(LOG_DIR, "auth_keycloak.log"), auth_events)
            write_log(os.path.join(LOG_DIR, "admin_keycloak.log"), admin_events)

            print("📥 [Keycloak Logs] Collectés et enregistrés.")
        except Exception as e:
            print(f"❌ [Keycloak Logs] Erreur de collecte : {e}")
        
        await asyncio.sleep(300)  # 5 minutes
