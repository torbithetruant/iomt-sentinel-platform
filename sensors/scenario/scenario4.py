import random
import threading
import time
import requests
from datetime import datetime
import ipaddress

# === CONFIGURATION GLOBALE ===
KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/iot_realm/protocol/openid-connect/token"
API_SENSOR_URL = "https://localhost:8000/api/sensor"
API_SYSTEM_URL = "https://localhost:8000/api/system-status"
CERT_PATH = "../server/certs/cert.pem"
CLIENT_ID = "iot_backend"
CLIENT_SECRET = "q1nMXKR6EKwafhEcDkeugyvgmbhGpbSp"

# === SIMULATION PARAMS ===
DEVICE_ID = "raspi_002"
USERS = [f"patient_{str(i).zfill(3)}" for i in range(10, 16)]  # Simulate 6 users

LOCATIONS = ["France", "Germany", "Netherlands", "USA", "Canada", "Singapore"]

def random_ip():
    return str(ipaddress.IPv4Address(random.randint(0x0B000000, 0xDF000000)))  # Random global IPs

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

def generate_sensor_data(device_id):
    return {
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

def generate_system_data(device_id, ip, username):
    return {
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

def simulate_user_on_device(username):
    ip = random_ip()
    location = random.choice(LOCATIONS)
    token = get_token(username)
    if not token:
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Forwarded-For": ip,
        "X-Geo-Location": location  # Optional, for future location handling
    }

    while True:
        sensor_data = generate_sensor_data(DEVICE_ID)
        system_data = generate_system_data(DEVICE_ID, ip, username)

        try:
            r1 = requests.post(API_SENSOR_URL, json=sensor_data, headers=headers, verify=CERT_PATH, timeout=5)
            r2 = requests.post(API_SYSTEM_URL, json=system_data, headers=headers, verify=CERT_PATH, timeout=5)

            print(f"[{DEVICE_ID}] User: {username} from {ip} ({location}) → SENSOR {r1.status_code} | SYSTEM {r2.status_code}")

            if r1.status_code in [401, 403, 500] or r2.status_code in [401, 403, 500]:
                print(f"🔁 Refreshing token for {username}")
                token = get_token(username)
                if token:
                    headers["Authorization"] = f"Bearer {token}"

        except Exception as e:
            print(f"❌ Network error for {username}: {e}")

        time.sleep(random.uniform(5, 15))  # Each user sends data every 5-15 seconds

# === Lancer les threads ===
for user in USERS:
    threading.Thread(target=simulate_user_on_device, args=(user,), daemon=True).start()

# Boucle infinie principale
while True:
    time.sleep(60)
