from collections import defaultdict
from datetime import datetime, timedelta
import time

# === États globaux ===

user_to_devices = defaultdict(set)
user_to_ips = defaultdict(set)
user_to_locations = defaultdict(set)

device_to_users = defaultdict(set)
device_to_ips = defaultdict(set)

user_device_ip_history = defaultdict(list)
anomaly_count_last_hour = defaultdict(list)

# Get user from device_id
def get_user_from_device(device_id):
    """
    Retourne l'utilisateur associé à un device_id.
    """
    for username, devices in user_to_devices.items():
        if device_id in devices:
            return username
    return "unknown_user"

# === Enregistrement d'une anomalie ===

def register_anomaly_event(device_id, username, ip, location):
    """
    Met à jour les états pour un événement d'anomalie.
    """
    now = datetime.now()

    user_to_devices[username].add(device_id)
    user_to_ips[username].add(ip)
    user_to_locations[username].add(location)

    device_to_users[device_id].add(username)
    device_to_ips[device_id].add(ip)

    user_device_ip_history[(username, device_id)].append((now, ip, location))
    anomaly_count_last_hour[device_id].append(time.time())

# === Nombre d'anomalies récentes ===

def get_anomaly_count(device_id, time_window=3600):
    """
    Nombre d'anomalies pour un device dans la dernière 'time_window' (en secondes).
    """
    now = time.time()
    timestamps = anomaly_count_last_hour.get(device_id, [])
    recent = [t for t in timestamps if now - t <= time_window]
    anomaly_count_last_hour[device_id] = recent  # Nettoyage

    print(f"🔍 Counting anomalies for {device_id}... Found: {len(recent)}")
    return len(recent)

# === IP Drift : L'utilisateur utilise-t-il plusieurs IPs ? ===

def get_ip_drift_score(username):
    ip_count = len(user_to_ips.get(username, []))
    return min(1.0, ip_count / 5)  # Exemple : >5 IPs = score max 1.0

# === Device Drift : L'utilisateur utilise-t-il plusieurs devices ? ===

def get_device_drift_score(username):
    if username == "unknown_user":
        return 1.0
    device_count = len(user_to_devices.get(username, []))
    return min(1.0, device_count / 5)

# === User Drift : Le device est-il utilisé par plusieurs utilisateurs ? ===

def get_user_drift_score(device_id):
    user_count = len(device_to_users.get(device_id, []))
    return min(1.0, user_count / 5)

# === Endpoint Unusual : L'utilisateur accède-t-il à des endpoints rares ? ===

def is_endpoint_unusual(context):
    rare_keywords = ["dashboard/system", "/admin", "/api/debug"]
    return any(keyword in context for keyword in rare_keywords)

# === Synthèse complète pour un device ===

def get_full_anomaly_metrics(device_id, username, context):
    metrics = {
        "num_anomalies_last_hour": get_anomaly_count(device_id),
        "failed_auth_ratio": 0.0,  # Placeholder si besoin
        "ip_drift_score": get_ip_drift_score(username),
        "device_drift_score": get_device_drift_score(username),
        "user_drift_score": get_user_drift_score(device_id),
        "endpoint_unusual": is_endpoint_unusual(context),
        "system_alert": "System alert" in context
    }
    return metrics
