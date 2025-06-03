import json
import random
import time
import threading
import requests
import numpy as np
from datetime import datetime
import ipaddress
import fed_detection

# === Lecture de la configuration ===
with open("config.json") as f:
    config = json.load(f)

USERNAME = config["username"]
DEVICE_ID = config["device_id"]
KEYCLOAK_TOKEN_URL = config["keycloak_url"]
API_SENSOR_URL = config["api_sensor_url"]
API_SYSTEM_URL = config["api_system_url"]
CERT_PATH = config["cert_path"]
CLIENT_ID = config["client_id"]
CLIENT_SECRET = config["client_secret"]

def random_ip():
    return str(ipaddress.IPv4Address(random.randint(0xC0A80001, 0xC0A8FFFF)))

def get_token():
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "username": USERNAME,
        "password": "test123"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        resp = requests.post(KEYCLOAK_TOKEN_URL, data=data, headers=headers, verify=CERT_PATH, timeout=10)
        if resp.status_code == 200:
            return resp.json()["access_token"]
        else:
            print(f"❌ Token error: {resp.text}")
            return None
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return None

def generate_data(ip, anomaly=False):
    base_hr = 75
    base_spo2 = 97
    base_temp = 36.7

    sensor_data = {
        "device_id": DEVICE_ID,
        "timestamp": datetime.now().isoformat(),
        "heart_rate": random.randint(base_hr - 5, base_hr + 10),
        "spo2": round(random.uniform(base_spo2 - 1, base_spo2 + 1.5), 1),
        "temperature": round(random.uniform(base_temp - 0.3, base_temp + 0.4), 1),
        "systolic_bp": random.randint(110, 135),
        "diastolic_bp": random.randint(70, 90),
        "respiration_rate": random.randint(12, 20),
        "glucose_level": round(random.uniform(4.5, 7.0), 1),
        "ecg_summary": "Normal sinus rhythm",
        "label": 0
    }

    system_data = {
        "device_id": DEVICE_ID,
        "username": USERNAME,
        "sensor_type": "multi",
        "ip_address": ip,
        "firmware_version": "v1.0.3",
        "status": 1,
        "data_frequency_seconds": 20,
        "timestamp": datetime.now().isoformat(),
        "checksum_valid": True,
        "os_version": "Raspbian 12",
        "update_required": False,
        "disk_free_percent": round(random.uniform(30.0, 80.0), 1)
    }

    if anomaly:
        anomaly_types = ["tachy", "hypoxie", "hyperBP", "hypoBP", "glycémie", "resp"]
        selected = random.sample(anomaly_types, k=random.randint(1, 2))
        sensor_data["label"] = 1

        if "tachy" in selected:
            sensor_data["heart_rate"] = random.randint(110, 150)
            if random.random() < 0.5:
                sensor_data["ecg_summary"] = "Anomalous pattern"

        if "hypoxie" in selected:
            sensor_data["spo2"] = round(random.uniform(90.0, 94.5), 1)

        if "hyperBP" in selected:
            sensor_data["systolic_bp"] = random.randint(140, 160)
            sensor_data["diastolic_bp"] = random.randint(90, 100)

        if "hypoBP" in selected:
            sensor_data["systolic_bp"] = random.randint(90, 105)
            sensor_data["diastolic_bp"] = random.randint(60, 70)

        if "glycémie" in selected:
            sensor_data["glucose_level"] = round(random.uniform(7.5, 10.5), 1)

        if "resp" in selected:
            sensor_data["respiration_rate"] = random.randint(22, 28)

        # Faux positifs ECG
        if sensor_data["ecg_summary"] == "Normal sinus rhythm" and random.random() < 0.1:
            sensor_data["ecg_summary"] = "Anomalous pattern"

        features = ["checksum", "disk", "status", "update"]
        selected = random.sample(features, k=random.randint(1, 2))

        if "checksum" in selected:
            system_data["checksum_valid"] = False

        if "disk" in selected:
            system_data["disk_free_percent"] = round(random.uniform(4.0, 9.9), 1)

        if "status" in selected:
            # 50% chance d’être en erreur (0), sinon inactif (2)
            system_data["status"] = 0 if random.random() < 0.5 else 2

        if "update" in selected:
            system_data["update_required"] = True

    return sensor_data, system_data

def simulate(token):

    ip = random_ip()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Forwarded-For": ip
    }

    while True:
        anomaly = random.random() < 0.01  # Probabilité d'anomalie simulée
        sensor_data, system_data = generate_data(ip, anomaly)

        # === Détection autoencoder ===
        features = np.array([[sensor_data['heart_rate'], sensor_data['spo2'], sensor_data['temperature'],
                              sensor_data['systolic_bp'], sensor_data['diastolic_bp'],
                              sensor_data['glucose_level'], sensor_data['respiration_rate']]])
        features_scaled = fed_detection.scaler.transform(features)
        reconstruction = fed_detection.model.predict(features_scaled)
        score = np.mean((features_scaled - reconstruction)**2)

        print(f"[Detection] MSE = {score:.5f}")
        if score > fed_detection.ANOMALY_THRESHOLD:
            print(f"[Anomaly] Autoencoder detected anomaly: {score:.5f}")
            sensor_data["label"] = 1  # Ajouter le flag d’anomalie dans le payload
        else:
            sensor_data["label"] = 0

        try:
            r1 = requests.post(API_SENSOR_URL, json=sensor_data, headers=headers, verify=CERT_PATH, timeout=5)
            r2 = requests.post(API_SYSTEM_URL, json=system_data, headers=headers, verify=CERT_PATH, timeout=5)
            print(f"[{DEVICE_ID}] SENSOR → {r1.status_code} | SYSTEM → {r2.status_code}")

            if r1.status_code in [401, 403] or r2.status_code in [401, 403]:
                print(f"🔁 Token expired, refreshing...")
                token = get_token()
                if token:
                    headers["Authorization"] = f"Bearer {token}"

        except Exception as e:
            print(f"❌ Network error: {e}")

        time.sleep(20)

# === Lancer les deux threads ===
if __name__ == "__main__":
    token = get_token()
    if not token:
        print("❌ Impossible d'obtenir un token, arrêt du programme.")
    else:
        threading.Thread(target=fed_detection.fl_loop, args=(DEVICE_ID, token), daemon=True).start()
        threading.Thread(target=simulate, args=(token,), daemon=True).start()

        # Garder le process actif
        while True:
            time.sleep(1)