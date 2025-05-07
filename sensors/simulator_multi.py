import random
import threading
import time
import requests
from datetime import datetime
import uuid
import ipaddress

# === CONFIGURATION GLOBALE ===
KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/iot_realm/protocol/openid-connect/token"
API_SENSOR_URL = "https://localhost:8000/api/sensor"
API_SYSTEM_URL = "https://localhost:8000/api/system-status"
CERT_PATH = "../server/certs/cert.pem"
CLIENT_ID = "iot_backend"
CLIENT_SECRET = "VGNth5jUVhXhCx9qmgarzKPwcdhtwsF6"

# === SIMULATION PARAMS ===
CAPTEURS = [{"username": f"patient_{str(i).zfill(3)}", "device_id": f"raspi_{str(i).zfill(3)}"} for i in range(1, 101)]

def random_ip():
    return str(ipaddress.IPv4Address(random.randint(0xC0A80001, 0xC0A8FFFF)))  # 192.168.0.1 - 192.168.255.255

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

def generate_sensor_data(device_id, anomaly=False):
    data = {
        "device_id": device_id,
        "timestamp": datetime.now().isoformat(),
        "heart_rate": random.randint(60, 100),
        "spo2": round(random.uniform(95.0, 99.5), 1),
        "temperature": round(random.uniform(36.0, 38.0), 1),
        "systolic_bp": random.randint(110, 130),
        "diastolic_bp": random.randint(70, 85),
        "respiration_rate": random.randint(12, 18),
        "glucose_level": round(random.uniform(4.5, 6.5), 1),
        "ecg_summary": "Normal sinus rhythm"
    }

    if anomaly:
        features = ["heart_rate", "spo2", "systolic_bp", "diastolic_bp", "respiration_rate", "glucose_level"]
        selected = random.sample(features, k=random.randint(1, 3))

        if "heart_rate" in selected:
            data["heart_rate"] = random.randint(120, 180)
            # 30% de chance que l’ECG montre aussi une anomalie si la FC est anormale
            if random.random() < 0.3:
                data["ecg_summary"] = "Anomalous pattern"

        if "spo2" in selected:
            data["spo2"] = round(random.uniform(90.0, 94.5), 1)

        if "systolic_bp" in selected:
            data["systolic_bp"] = random.randint(140, 160)

        if "diastolic_bp" in selected:
            data["diastolic_bp"] = random.randint(90, 100)

        if "respiration_rate" in selected:
            data["respiration_rate"] = random.randint(20, 25)

        if "glucose_level" in selected:
            data["glucose_level"] = round(random.uniform(7.5, 11.0), 1)

        # 10% de chance d’avoir une anomalie ECG même sans heart_rate anormal
        if data["ecg_summary"] == "Normal sinus rhythm" and random.random() < 0.1:
            data["ecg_summary"] = "Anomalous pattern"

    return data

def generate_system_data(device_id, anomaly=False):
    data = {
        "device_id": device_id,
        "sensor_type": random.choice(["cardio", "thermique", "multi"]),
        "ip_address": random_ip(),
        "firmware_version": f"v{random.randint(1,3)}.{random.randint(0,9)}.{random.randint(0,9)}",
        "status": 1,  # Actif par défaut
        "data_frequency_seconds": random.randint(10, 30),
        "timestamp": datetime.now().isoformat(),
        "checksum_valid": True,
        "os_version": "Raspbian 12",
        "update_required": False,
        "disk_free_percent": round(random.uniform(30.0, 80.0), 1)
    }

    if anomaly:
        features = ["checksum", "disk", "status", "update"]
        selected = random.sample(features, k=random.randint(1, 2))

        if "checksum" in selected:
            data["checksum_valid"] = False

        if "disk" in selected:
            data["disk_free_percent"] = round(random.uniform(4.0, 9.9), 1)

        if "status" in selected:
            # 50% chance d’être en erreur (0), sinon inactif (2)
            data["status"] = 0 if random.random() < 0.5 else 2

        if "update" in selected:
            data["update_required"] = True

    return data

def simulate_capteur(capteur):
    token = get_token(capteur["username"])
    if not token:
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    while True:
        anomaly = random.random() < 0.1  # 10% anomalie
        sensor_data = generate_sensor_data(capteur["device_id"], anomaly)
        system_data = generate_system_data(capteur["device_id"], anomaly)

        try:
            r1 = requests.post(API_SENSOR_URL, json=sensor_data, headers=headers, verify=CERT_PATH, timeout=5)
            r2 = requests.post(API_SYSTEM_URL, json=system_data, headers=headers, verify=CERT_PATH, timeout=5)

            print(f"[{capteur['device_id']}] SENSOR → {r1.status_code} | SYSTEM → {r2.status_code}")

            if r1.status_code in [401, 403] or r2.status_code in [401, 403]:
                print(f"🔁 Refreshing token for {capteur['device_id']}")
                token = get_token(capteur["username"])
                if token:
                    headers["Authorization"] = f"Bearer {token}"

        except Exception as e:
            print(f"❌ Network error for {capteur['device_id']}: {e}")

        time.sleep(random.randint(10, 30))

# Lancer tous les capteurs en threads
for i, capteur in enumerate(CAPTEURS):
    time.sleep(0.2 * i)  # délai croissant
    threading.Thread(target=simulate_capteur, args=(capteur,), daemon=True).start()


# Boucle infinie principale
while True:
    time.sleep(60)
