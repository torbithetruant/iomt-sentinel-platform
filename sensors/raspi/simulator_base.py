import json
import random
import time
import requests
from datetime import datetime
import ipaddress

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
        sensor_data["heart_rate"] = random.randint(110, 150)
        sensor_data["spo2"] = round(random.uniform(90.0, 94.5), 1)
        sensor_data["ecg_summary"] = "Anomalous pattern"
        sensor_data["label"] = 1

        system_data["checksum_valid"] = False
        system_data["disk_free_percent"] = round(random.uniform(5.0, 10.0), 1)
        system_data["status"] = 0
        system_data["update_required"] = True

    return sensor_data, system_data

def simulate():
    token = get_token()
    if not token:
        return

    ip = random_ip()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Forwarded-For": ip
    }

    while True:
        anomaly = random.random() < 0.01
        sensor_data, system_data = generate_data(ip, anomaly)

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

if __name__ == "__main__":
    simulate()