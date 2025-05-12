import requests
import random
import time
from datetime import datetime

API_URL = "https://localhost:8000/api/sensor"
SYSTEM_URL = "https://localhost:8000/api/system-status"
CERT_PATH = "../server/certs/cert.pem"
USERNAME = "patient_001"
PASSWORD = "test123"
CLIENT_ID = "iot_backend"
CLIENT_SECRET = "VGNth5jUVhXhCx9qmgarzKPwcdhtwsF6"

KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/iot_realm/protocol/openid-connect/token"

def get_token():
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "username": USERNAME,
        "password": PASSWORD
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(KEYCLOAK_TOKEN_URL, data=data, headers=headers, verify=CERT_PATH)
    if r.status_code == 200:
        return r.json()["access_token"]
    else:
        print("❌ Token fetch failed:", r.text)
        return None

def generate_fake_ip():
    return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"

def generate_malicious_data():
    return {
        "device_id": "raspi_001",
        "timestamp": datetime.now().isoformat(),
        "heart_rate": random.randint(140, 200),
        "spo2": round(random.uniform(85.0, 94.0), 1),
        "temperature": round(random.uniform(38.5, 41.0), 1),
        "systolic_bp": random.randint(160, 190),
        "diastolic_bp": random.randint(100, 120),
        "respiration_rate": random.randint(26, 40),
        "glucose_level": round(random.uniform(11.0, 16.0), 1),
        "ecg_summary": "Anomalous pattern",
        "label": random.randint(0, 1)  # 1 for anomaly
    }

def generate_system_data():
    return {
        "device_id": "raspi_001",
        "username": USERNAME,
        "timestamp": datetime.now().isoformat(),
        "sensor_type": "health_monitor",
        "ip_address": generate_fake_ip(),
        "firmware_version": "1.0.0",
        "status": 1,
        "data_frequency_seconds": 5,
        "checksum_valid": True,
        "os_version": "Linux 5.4.0",
        "update_required": False,
        "disk_free_percent": random.uniform(10, 50)
    }

def simulate():
    token = get_token()
    if not token:
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    while True:
        data = generate_malicious_data()
        system_data = generate_system_data()
        fake_ip = generate_fake_ip()
        headers["X-Forwarded-For"] = fake_ip

        try:
            r = requests.post(API_URL, json=data, headers=headers, verify=CERT_PATH, timeout=5)
            r2 = requests.post(SYSTEM_URL, json=system_data, headers=headers, verify=CERT_PATH, timeout=5)
            print(f"[{fake_ip}] Sent malicious data → {r.status_code}")
        except Exception as e:
            print("❌ Error sending data:", e)

        time.sleep(10)

if __name__ == "__main__":
    simulate()
