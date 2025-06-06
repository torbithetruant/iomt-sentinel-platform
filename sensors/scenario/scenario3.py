import random
import threading
import time
import requests
from datetime import datetime
import ipaddress
import psutil

# === CONFIGURATION GLOBALE ===
KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/iot_realm/protocol/openid-connect/token"
API_SENSOR_URL = "https://localhost:8000/api/sensor"
API_SYSTEM_URL = "https://localhost:8000/api/system-status"
CERT_PATH = "../raspi/cert.pem"
CLIENT_ID = "iot_backend"
CLIENT_SECRET = "q1nMXKR6EKwafhEcDkeugyvgmbhGpbSp"

# === SIMULATION PARAMS ===
CAPTEURS = [{"username": f"patient_{str(i).zfill(3)}", "device_id": f"raspi_{str(i).zfill(3)}"} for i in range(1, 4)]

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
        "spo2": round(random.uniform(95, 98), 1),
        "temperature": round(random.uniform(36.0, 37.0), 1),
        "systolic_bp": random.randint(110, 130),
        "diastolic_bp": random.randint(70, 85),
        "respiration_rate": random.randint(12, 20),
        "glucose_level": round(random.uniform(4.5, 7.0), 1),
        "ecg_summary": "Normal sinus rhythm",
        "label": 0
    }
    if anomaly:
        data["heart_rate"] = random.randint(110, 150)
        data["spo2"] = round(random.uniform(88, 94), 1)
        data["ecg_summary"] = "Anomalous pattern"
    return data

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
        "disk_free_percent": round(random.uniform(40.0, 70.0), 1)
    }
    if anomaly:
        data["checksum_valid"] = False
        data["disk_free_percent"] = round(random.uniform(5.0, 10.0), 1)
        data["status"] = 0
        data["update_required"] = True
    return data

def simulate_capteur(capteur, is_target=False):
    token = get_token(capteur["username"])
    if not token:
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Forwarded-For": random_ip()
    }

    while True:
        if is_target:
            anomaly = random.random() < 0.8  # 80% anomalies for target device
            sleep_time = random.uniform(2, 5)  # Faster loop = DoS effect
        else:
            anomaly = random.random() < 0.01  # 1% anomalies for normal devices
            sleep_time = random.uniform(6, 11)

        sensor_data = generate_sensor_data(capteur["device_id"], anomaly)
        system_data = generate_system_data(capteur["device_id"], headers["X-Forwarded-For"], capteur["username"], anomaly)

        try:
            r1 = requests.post(API_SENSOR_URL, json=sensor_data, headers=headers, verify=CERT_PATH, timeout=5)
            r2 = requests.post(API_SYSTEM_URL, json=system_data, headers=headers, verify=CERT_PATH, timeout=5)

            print(f"[{capteur['device_id']}] SENSOR → {r1.status_code} | SYSTEM → {r2.status_code}")

            if r1.status_code in [401, 403, 500] or r2.status_code in [401, 403, 500]:
                print(f"🔁 Refreshing token for {capteur['device_id']}")
                token = get_token(capteur["username"])
                if token:
                    headers["Authorization"] = f"Bearer {token}"

        except Exception as e:
            print(f"❌ Network error for {capteur['device_id']}: {e}")

        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().used / (1024*1024)
        print(f"[{capteur['device_id']}] 🧠 CPU: {cpu}% | MEM: {mem:.2f} MB")

        time.sleep(sleep_time)

# Lancer les capteurs
for capteur in CAPTEURS:
    is_target = (capteur["device_id"] == "raspi_002")  # 🎯 Target device for DoS
    threading.Thread(target=simulate_capteur, args=(capteur, is_target), daemon=True).start()

# Boucle infinie principale
while True:
    time.sleep(60)
