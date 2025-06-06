import random
import threading
import time
import requests
from datetime import datetime
import ipaddress
import psutil

# === CONFIGURATION ===
KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/iot_realm/protocol/openid-connect/token"
API_SENSOR_URL = "https://localhost:8000/api/sensor"
API_SYSTEM_URL = "https://localhost:8000/api/system-status"
CERT_PATH = "../raspi/cert.pem"
CLIENT_ID = "iot_backend"
CLIENT_SECRET = "q1nMXKR6EKwafhEcDkeugyvgmbhGpbSp"

CAPTEURS = [{"username": f"patient_{str(i).zfill(3)}", "device_id": f"raspi_{str(i).zfill(3)}"} for i in range(1, 7)]

PATIENT_PROFILES = [
    {"type": "sportif", "base_hr": 60, "base_spo2": 98, "base_temp": 36.3, "risk": 0.05},
    {"type": "standard", "base_hr": 75, "base_spo2": 97, "base_temp": 36.8, "risk": 0.1},
    {"type": "senior", "base_hr": 85, "base_spo2": 95, "base_temp": 37.0, "risk": 0.2},
    {"type": "diabétique", "base_hr": 80, "base_spo2": 96, "base_temp": 36.7, "risk": 0.25}
]

def random_ip():
    return str(ipaddress.IPv4Address(random.randint(0xC0A80001, 0xC0A8FFFF)))  # 192.168.0.x

def random_ip_public():
    return str(ipaddress.IPv4Address(random.randint(0x0B000001, 0xDF0000FF)))  # Random public IP range

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

def generate_sensor_data(device_id, anomaly=False, profile=None):
    base = profile
    data = {
        "device_id": device_id,
        "timestamp": datetime.now().isoformat(),
        "heart_rate": random.randint(base["base_hr"] - 5, base["base_hr"] + 10),
        "spo2": round(random.uniform(base["base_spo2"] - 1, base["base_spo2"] + 1.5), 1),
        "temperature": round(random.uniform(base["base_temp"] - 0.3, base["base_temp"] + 0.4), 1),
        "systolic_bp": random.randint(110, 135),
        "diastolic_bp": random.randint(70, 90),
        "respiration_rate": random.randint(12, 20),
        "glucose_level": round(random.uniform(4.5, 7.0), 1),
        "ecg_summary": "Normal sinus rhythm",
        "label": 0
    }

    if anomaly:
        anomaly_types = ["tachy", "hypoxie", "hyperBP", "hypoBP", "glycémie", "resp"]
        selected = random.sample(anomaly_types, k=random.randint(1, 2))

        if "tachy" in selected:
            data["heart_rate"] = random.randint(110, 150)
            data["ecg_summary"] = "Anomalous pattern"
        if "hypoxie" in selected:
            data["spo2"] = round(random.uniform(90.0, 94.5), 1)
        if "hyperBP" in selected:
            data["systolic_bp"] = random.randint(140, 160)
            data["diastolic_bp"] = random.randint(90, 100)
        if "hypoBP" in selected:
            data["systolic_bp"] = random.randint(90, 105)
            data["diastolic_bp"] = random.randint(60, 70)
        if "glycémie" in selected:
            data["glucose_level"] = round(random.uniform(7.5, 10.5), 1)
        if "resp" in selected:
            data["respiration_rate"] = random.randint(22, 28)

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
        "disk_free_percent": round(random.uniform(30.0, 80.0), 1)
    }

    if anomaly:
        data["checksum_valid"] = random.choice([False, True])
        data["disk_free_percent"] = round(random.uniform(5.0, 15.0), 1)
        data["update_required"] = random.choice([True, False])
        data["status"] = random.choice([0, 2])

    return data

def simulate_device_botnet(capteur):
    profile = random.choice(PATIENT_PROFILES)
    token = get_token(capteur["username"])
    if not token:
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    ip = random_ip()

    while True:
        if capteur["device_id"] == "raspi_002" or capteur["device_id"] == "raspi_003" or capteur["device_id"] == "raspi_005" or capteur["device_id"] == "raspi_006":
            anomaly = random.random() < 0.8  # Moderate anomaly rate
            ip = random_ip_public()  # Change IP for each request
            time_sleep = random.uniform(10, 15)
        else:
            anomaly =  random.random() < 0.05
            time_sleep = random.uniform(15, 20)

        sensor_data = generate_sensor_data(capteur["device_id"], anomaly, profile)
        system_data = generate_system_data(capteur["device_id"], ip, capteur["username"], anomaly)

        try:
            headers["X-Forwarded-For"] = ip
            r1 = requests.post(API_SENSOR_URL, json=sensor_data, headers=headers, verify=CERT_PATH, timeout=5)
            r2 = requests.post(API_SYSTEM_URL, json=system_data, headers=headers, verify=CERT_PATH, timeout=5)

            print(f"[{capteur['device_id']}] IP: {ip} | SENSOR → {r1.status_code} | SYSTEM → {r2.status_code}")

        except Exception as e:
            print(f"❌ Network error for {capteur['device_id']}: {e}")
        
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().used / (1024*1024)
        print(f"[{capteur['device_id']}] 🧠 CPU: {cpu}% | MEM: {mem:.2f} MB")

        time.sleep(time_sleep)

# === Launch all devices ===
for capteur in CAPTEURS:
    threading.Thread(target=simulate_device_botnet, args=(capteur,), daemon=True).start()

# Keep main thread alive
while True:
    time.sleep(60)
