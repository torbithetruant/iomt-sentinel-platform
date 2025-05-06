import requests
import random
import time
from datetime import datetime
import threading

# --- Configuration globale ---
KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/iot_realm/protocol/openid-connect/token"
API_URL = "https://localhost:8000/api/sensor"
CLIENT_ID = "iot_backend"
CLIENT_SECRET = "VGNth5jUVhXhCx9qmgarzKPwcdhtwsF6"

# --- Liste des patients/capteurs ---
CAPTEURS = [
    {"username": "patient_user", "device_id": "raspi_001"},
    {"username": "patient_002", "device_id": "raspi_002"},
    {"username": "patient_003", "device_id": "raspi_003"}
]

# --- Générer une donnée simulée ---
def generate_data(capteur):
    return {
        "device_id": capteur["device_id"],
        "heart_rate": random.randint(60, 100),
        "spo2": round(random.uniform(95.0, 99.5), 1),
        "timestamp": datetime.now().isoformat()
    }

# --- Générer une donnée simulée (anomalie)---
def generate_anomaly_data(capteur):
    return {
        "device_id": capteur["device_id"],
        "heart_rate": random.randint(101, 120),  # Anomalie
        "spo2": round(random.uniform(90.0, 94.9), 1),  # Anomalie
        "timestamp": datetime.now().isoformat()
    }

def get_token(username, password="test123"):
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "username": username,
        "password": password
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(KEYCLOAK_TOKEN_URL, data=data, headers=headers, verify="../server/certs/cert.pem")
    if resp.status_code == 200:
        token = resp.json()["access_token"]
        return token
    else:
        print(f"❌ Token fail for {username}:", resp.text)
        return None

def check_system_request(device_id, headers):
    url = f"https://localhost:8000/api/system-request?device_id={device_id}"
    resp = requests.get(url, headers=headers, verify="../server/certs/cert.pem")
    return resp.status_code == 200 and resp.json().get("request") == True

def send_system_status(device_id, headers):
    system_payload = {
        "device_id": device_id,
        "checksum_valid": True,  # ou random/system check
        "os_version": "Raspbian 12",
        "update_required": random.choice([True, False]),
        "disk_free_percent": round(random.uniform(20.0, 80.0), 2),
        "timestamp": datetime.now().isoformat()
    }
    r = requests.post("https://localhost:8000/api/system-status", json=system_payload, headers=headers, verify="../server/certs/cert.pem")

    print(f"[{device_id}] ↪️ Infos système envoyées → {r.status_code}")


def simulate_sensor(capteur):
    token = get_token(capteur["username"])
    if not token:
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    while True:
        if check_system_request(capteur['device_id'], headers):
            send_system_status(capteur['device_id'], headers)

        data = generate_data(capteur)
        if random.random() < 0.5:
            data = generate_anomaly_data(capteur)
        response = requests.post(API_URL, json=data, headers=headers, verify="../server/certs/cert.pem")
        status = response.status_code
        print(f"[{capteur['device_id']}] Sent: {data} → {status}")
        
        if status in [401, 403]:
            print(f"🔁 {capteur['device_id']} → Renewing token...")
            token = get_token(capteur["username"])
            if token:
                headers["Authorization"] = f"Bearer {token}"
        time.sleep(random.randint(10, 20))  # envoie aléatoire

# Lancer un thread par capteur
for capteur in CAPTEURS:
    threading.Thread(target=simulate_sensor, args=(capteur,), daemon=True).start()

# Garder le script en vie
while True:
    time.sleep(60)
