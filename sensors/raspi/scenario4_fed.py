import json
import random
import time
import threading
import requests
import numpy as np
import ipaddress
import psutil
from datetime import datetime
import fed_detection

# === Capteur definitions ===
SENSORS = [
    {"username": "patient_001", "device_id": "raspi_001", "is_target": False},
    {"username": "patient_002", "device_id": "raspi_002", "is_target": True},   # 🎯 DoS-like
    {"username": "patient_003", "device_id": "raspi_003", "is_target": True},
    {"username": "patient_004", "device_id": "raspi_004", "is_target": False},
    {"username": "patient_005", "device_id": "raspi_005", "is_target": True},   # 🎯 DoS-like
    {"username": "patient_006", "device_id": "raspi_006", "is_target": True},
]

# === Shared config ===
with open("config.json") as f:
    config = json.load(f)

KEYCLOAK_TOKEN_URL = config["keycloak_url"]
API_SENSOR_URL = config["api_sensor_url"]
API_SYSTEM_URL = config["api_system_url"]
CERT_PATH = config["cert_path"]
CLIENT_ID = config["client_id"]
CLIENT_SECRET = config["client_secret"]

def random_ip():
    return str(ipaddress.IPv4Address(random.randint(0xC0A80001, 0xC0A8FFFF)))  # 192.168.0.x

def get_token(username):
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "username": username,
        "password": "test123"
    }
    try:
        resp = requests.post(KEYCLOAK_TOKEN_URL, data=data, verify=CERT_PATH, timeout=10)
        if resp.status_code == 200:
            return resp.json()["access_token"]
        else:
            print(f"❌ Token error for {username}: {resp.text}")
            return None
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return None

def generate_data(device_id, username, ip, anomaly=False):
    base_hr = 75
    base_spo2 = 97
    base_temp = 36.7

    sensor = {
        "device_id": device_id,
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

    system = {
        "device_id": device_id,
        "username": username,
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
        sensor["label"] = 1
        sensor["heart_rate"] = random.randint(110, 150)
        sensor["spo2"] = round(random.uniform(90.0, 94.5), 1)
        sensor["ecg_summary"] = "Anomalous pattern"
        system["checksum_valid"] = False
        system["disk_free_percent"] = round(random.uniform(4.0, 10.0), 1)
        system["status"] = 0
        system["update_required"] = True

    return sensor, system

def simulate_device(sensor_info):
    username = sensor_info["username"]
    device_id = sensor_info["device_id"]
    is_target = sensor_info["is_target"]
    token = get_token(username)

    if not token:
        return

    ip = random_ip()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Forwarded-For": ip
    }

    iteration = 0
    while True:
        iteration += 1
        anomaly = random.random() < (0.8 if is_target else 0.01)
        sensor_data, system_data = generate_data(device_id, username, ip, anomaly)

        features = np.array([[sensor_data['heart_rate'], sensor_data['spo2'], sensor_data['temperature'],
                              sensor_data['systolic_bp'], sensor_data['diastolic_bp'],
                              sensor_data['glucose_level'], sensor_data['respiration_rate']]])
        start = time.time()
        features_scaled = fed_detection.scaler.transform(features)
        reconstruction = fed_detection.model.predict(features_scaled)
        score = np.mean((features_scaled - reconstruction) ** 2)
        latency_local = time.time() - start

        print(f"[{device_id}] AE Inference = {latency_local*1000:.2f} ms | MSE = {score:.4f}")

        if score > fed_detection.ANOMALY_THRESHOLD:
            print(f"[{device_id}] 🚨 Local anomaly detected")

        sensor_data["label"] = int(score > fed_detection.ANOMALY_THRESHOLD)

        try:
            r1 = requests.post(API_SENSOR_URL, json=sensor_data, headers=headers, verify=CERT_PATH, timeout=5)
            r2 = requests.post(API_SYSTEM_URL, json=system_data, headers=headers, verify=CERT_PATH, timeout=5)
            print(f"[{device_id}] SENSOR → {r1.status_code} | SYSTEM → {r2.status_code}")
        except Exception as e:
            print(f"[{device_id}] ❌ Network error: {e}")

        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().used / (1024*1024)
        print(f"[{device_id}] 🧠 CPU: {cpu}% | MEM: {mem:.2f} MB")

        time.sleep(random.uniform(10, 15) if is_target else random.uniform(15, 20))

# === Launch all sensor threads ===
if __name__ == "__main__":
    for sensor in SENSORS:
        threading.Thread(target=fed_detection.fl_loop, args=(sensor["device_id"], get_token(sensor["username"])), daemon=True).start()
        threading.Thread(target=simulate_device, args=(sensor,), daemon=True).start()

    while True:
        time.sleep(60)
