import random
import threading
import time
import requests
from datetime import datetime
import ipaddress

# === CONFIGURATION ===
CAPTEURS = [{"username": f"patient_{str(i).zfill(3)}", "device_id": f"raspi_{str(i).zfill(3)}"} for i in range(1, 10)]
CERT_PATH = "../server/certs/cert.pem"
API_SENSOR_URL = "https://localhost:8000/api/sensor"
API_SYSTEM_URL = "https://localhost:8000/api/system-status"
API_URL = "https://localhost:8000/"
KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/iot_realm/protocol/openid-connect/token"
CLIENT_ID = "iot_backend"
CLIENT_SECRET = "q1nMXKR6EKwafhEcDkeugyvgmbhGpbSp"

def random_ip():
    return str(ipaddress.IPv4Address(random.randint(0xC0A80001, 0xC0A8FFFF)))  # 192.168.x.x

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

def generate_system_data(device_id, ip, username, anomaly=False):
    data = {
        "device_id": device_id,
        "username": username,
        "sensor_type": random.choice(["cardio", "thermique", "multi"]),
        "ip_address": ip,
        "firmware_version": f"v{random.randint(1,3)}.{random.randint(0,9)}.{random.randint(0,9)}",
        "status": 1,
        "data_frequency_seconds": random.randint(10, 30),
        "timestamp": datetime.now().isoformat(),
        "checksum_valid": True,
        "os_version": "Raspbian 12",
        "update_required": False,
        "disk_free_percent": round(random.uniform(30.0, 80.0), 1)
    }

    if anomaly or random.random() < 0.2:  # 20% chance of anomaly per request
        # Inject abnormal endpoint
        data["sensor_type"] = "/admin"  # Suspicious endpoint

        # Simulate other system anomalies
        data["checksum_valid"] = False if random.random() < 0.5 else True
        data["disk_free_percent"] = round(random.uniform(4.0, 9.9), 1)

    return data

def simulate_capteur(capteur):
    ip = random_ip()
    token = get_token(capteur["username"])
    if not token:
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Forwarded-For": ip
    }

    while True:
        anomaly = random.random() < 0.2 or capteur["device_id"] == "raspi_007" or capteur["device_id"] == "raspi_004" # Moderate anomaly chance
        system_data = generate_system_data(capteur["device_id"], ip, capteur["username"], anomaly)

        try:
            if anomaly and (capteur["device_id"] == "raspi_007" or capteur["device_id"] == "raspi_004"):
                r = requests.post(API_URL + "dashboard/system", json=system_data, headers=headers, verify=CERT_PATH, timeout=5)
            else:
                r = requests.post(API_SYSTEM_URL, json=system_data, headers=headers, verify=CERT_PATH, timeout=5)
            print(f"[{capteur['device_id']}] SYSTEM → {r.status_code} | Endpoint: {system_data['sensor_type']}")

            if r.status_code in [401, 403, 500]:
                print(f"🔁 Refreshing token for {capteur['device_id']}")
                token = get_token(capteur["username"])
                if token:
                    headers["Authorization"] = f"Bearer {token}"

        except Exception as e:
            print(f"❌ Network error for {capteur['device_id']}: {e}")

        time.sleep(random.randint(5, 15))  # Faster rate for testing

# Lancer les capteurs
for capteur in CAPTEURS:
    threading.Thread(target=simulate_capteur, args=(capteur,), daemon=True).start()

# Boucle infinie
while True:
    time.sleep(60)
