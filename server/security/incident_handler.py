import logging
import asyncio
import requests
import math
import time
import httpx
import os
import uuid
from sqlalchemy import select, update
from datetime import datetime, timezone
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from collections import defaultdict

import security.anomaly_state
from database.models import AsyncSessionLocal, DeviceTrust
from security.anomaly_state import get_user_from_device, get_full_anomaly_metrics
from security.log_utils import parse_last_logs_from_raw_file, build_context_from_logs, extract_anomaly_causes

last_inode = None
file_offset = 0
last_line_number = 0
llm_metrics = defaultdict(int)  # llm_metrics["TP"], llm_metrics["FP"]

logger = logging.getLogger("detection")

# Keycloak API
CLIENT_ID = "admin-cli"
CLIENT_SECRET = "q1nMXKR6EKwafhEcDkeugyvgmbhGpbSp"
KEYCLOAK_URL = "http://localhost:8080"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"

LLM_API_URL = "http://localhost:8001/infer"  # Update with your LLM server address
seen_contexts = set()
incident_queue = asyncio.Queue()
anomaly_timestamps = {}

THRESHOLD_REVOKE = 0.5
THRESHOLD_IPS = 3

class TrustUpdateRequest(BaseModel):
    device_id: str
    num_anomalies_last_hour: int = 0
    fed_ano_detected: int = 0
    failed_auth_ratio: float = 0.0       # between 0 and 1
    ip_drift_score: float = 0.0          # between 0 and 1
    device_drift_score: float = 0.0
    endpoint_unusual: bool = False
    system_alert: bool = False           # ex: checksum error or disk alert

async def get_admin_token():
    url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "username": ADMIN_USER,
        "password": ADMIN_PASS
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient() as client:
        r = await client.post(url, data=data, headers=headers)
        r.raise_for_status()
        return r.json()["access_token"]

def calculate_trust_score(data: TrustUpdateRequest) -> float:
    # Base score
    score = 1.0

    # Impact progressif des anomalies (logarithmique)
    anomaly_factor = min(0.7, 0.2 * math.log1p(data.num_anomalies_last_hour)) if data.num_anomalies_last_hour != 0 else 0  # max 0.7 penalty
    score -= anomaly_factor

    # Anomalies détectées par le capteur
    score -= 0.1 * data.fed_ano_detected

    # IP Drift : plus d'IPs = plus risqué, mais atténué
    score -= 0.1 * data.ip_drift_score

    # Device Drift : idem, si on le souhaite
    score -= 0.1 * data.device_drift_score

    # Failed Auth Ratio : atténué aussi
    score -= 0.15 * data.failed_auth_ratio

    # Endpoint usage : binaire, on garde
    if data.endpoint_unusual:
        score -= 0.1

    return max(0.0, min(1.0, score))  # Ne jamais descendre en dessous de 0.2

async def update_trust_score_for_device(device_id: str, db_session: AsyncSession):
    start_time = time.monotonic()
    username = get_user_from_device(device_id)
    metrics = get_full_anomaly_metrics(device_id, username, "")

    features = TrustUpdateRequest(
        device_id=device_id,
        num_anomalies_last_hour=metrics["num_anomalies_last_hour"],
        fed_ano_detected=metrics["fed_ano_detected"],
        failed_auth_ratio=metrics["failed_auth_ratio"],
        ip_drift_score=metrics["ip_drift_score"],
        device_drift_score=metrics["device_drift_score"],
        endpoint_unusual=metrics["endpoint_unusual"],
        system_alert=metrics["system_alert"]
    )
    new_score = calculate_trust_score(features)

    if new_score < THRESHOLD_REVOKE:
        print(f"🚨 Low trust score ({new_score:.2f}) for {device_id} - taking actions!")
        if username != "unknown_user":
            # await revoke_user_token(username)
            print("Account disabled !")
        ip_list = security.anomaly_state.device_to_ips.get(device_id, set())
        if len(ip_list) >= THRESHOLD_IPS:
            for ip in ip_list:
                # await denylist_ip(ip)
                print(f"IP : {ip} blocked !")

    existing = await db_session.execute(select(DeviceTrust).where(DeviceTrust.device_id == device_id))
    row = existing.scalar_one_or_none()

    if not row:
        db_session.add(DeviceTrust(device_id=device_id, trust_score=new_score, updated_at=datetime.now(timezone.utc)))
        print(f"🆕 Added new trust score for {device_id}: {new_score:.2f}")
        logger.info(f"[!] New Score for {device_id} = {new_score}")
    elif abs(row.trust_score - new_score) >= 0.01:
        await db_session.execute(update(DeviceTrust).where(DeviceTrust.device_id == device_id).values(
            trust_score=new_score,
            updated_at=datetime.now(timezone.utc)
        ))
        print(f"🔄 Updated trust score for {device_id}: {new_score:.2f}")
        logger.info(f"[!] New Score for {device_id} = {new_score}")
    else:
        print(f"✅ No update needed for {device_id}: {new_score:.2f}")

    await db_session.commit()
    duration = time.monotonic() - start_time
    logger.info(f"⏱️ Trust Score Update Time for {device_id}: {duration:.3f} sec")

async def detect_anomalies_remotely(context: str):
    start_time = time.monotonic()
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(LLM_API_URL, json={"context": context})
            response.raise_for_status()
            data = response.json()
            duration = time.monotonic() - start_time
            logger.info(f"⏱️ LLM Inference Time: {duration:.3f} sec")
            return data["prediction"], data["score"]
    except Exception as e:
        duration = time.monotonic() - start_time
        print(f"LLM API error: {e} (after {duration:.3f} sec)")
        return 0, 0.0

async def monitor_logs_with_llm(log_path="server.log", chunk_size=10, delay=5):
    global last_inode, last_line_number

    while True:
        try:
            # Handle log rotation (by checking inode)
            current_inode = os.stat(log_path).st_ino
            if last_inode is None:
                last_inode = current_inode
            elif current_inode != last_inode:
                print("🔄 Log file rotation detected! Resetting counters.")
                last_inode = current_inode
                last_line_number = 0

            # Read file
            with open(log_path, "r") as f:
                lines = f.readlines()

            total_lines = len(lines)

            # Check if there are at least 10 new lines
            while total_lines - last_line_number >= chunk_size:
                new_block = lines[last_line_number:last_line_number + chunk_size]
                last_line_number += chunk_size  # Update pointer

                # === Parse & process block ===
                parsed_block = parse_last_logs_from_raw_file(new_block)
                if not parsed_block:
                    continue

                extended_context = build_context_from_logs(parsed_block)
                context_hash = hash(extended_context)

                if context_hash in seen_contexts:
                    continue
                seen_contexts.add(context_hash)

                pred, score = await detect_anomalies_remotely(extended_context)

                if pred == 1:
                    detection_id = str(uuid.uuid4())  # Unique ID per detection
                    anomaly_timestamps[detection_id] = time.monotonic()
                    logger.info(f"🚨 Anomaly detected! Score: {score:.2f}")
                    await incident_queue.put((extended_context, score, detection_id))

            await asyncio.sleep(delay)

        except FileNotFoundError:
            print(f"Log file not found: {log_path}")
            await asyncio.sleep(delay)
            continue

# Revoke Keycloak Token
async def revoke_user_token(username):
    try:
        token = await get_admin_token()
        url_users = f"{KEYCLOAK_URL}/admin/realms/iot_realm/users"
        headers = {"Authorization": f"Bearer {token}"}

        async with httpx.AsyncClient() as client:
            # Get user details
            response = await client.get(url_users, headers=headers, params={"username": username})
            response.raise_for_status()
            users = response.json()

            if not users:
                print(f"❌ No user found for {username}")
                return False

            user_info = users[0]
            user_id = user_info["id"]

            if not user_info.get("enabled", True):
                print(f"⚠️ User {username} is already disabled. No action taken.")
                return False

            # Optionally disable the user (if you want to enforce disable)
            url_disable = f"{KEYCLOAK_URL}/admin/realms/iot_realm/users/{user_id}"
            payload = {"enabled": False}
            await client.put(url_disable, headers=headers, json=payload)

            # Logout the user to revoke their token
            url_revoke = f"{KEYCLOAK_URL}/admin/realms/iot_realm/users/{user_id}/logout"
            resp = await client.post(url_revoke, headers=headers)
            resp.raise_for_status()

            print(f"✅ Token revoked for user {username}")
            return True

    except Exception as e:
        print(f"❌ Error revoking token for {username}: {e}")
        return False


# Denylist an IP
def denylist_ip(ip_address):
    logger.warning(f"Adding IP {ip_address} to iptables denylist.")
    if ip_address in security.anomaly_state.ip_denylist:
        print(f"⚠️ IP {ip_address} is already denylisted. No action taken.")
        return False
    
    # Register the IP in the denylist
    security.anomaly_state.ip_denylist.add(ip_address)
    print(f"🚫 IP {ip_address} added to denylist.")

async def handle_detected_threat(context, score, detection_id, db):
    start_time = time.monotonic()

    # Lookup detection time
    detection_start = anomaly_timestamps.pop(detection_id, None)
    if detection_start:
        detection_latency = start_time - detection_start
        logger.info(f"⏳ Time from Detection to Handling: {detection_latency:.3f} sec")
    else:
        detection_latency = None

    results = extract_anomaly_causes(context)

    for result in results:
        causes = result["causes"]
        metadata = result["metadata"]
        line = result["line"]

        print(f"🚨 Threat detected! Score: {score:.2f}")
        print(f"Line: {line}")
        print(f"Causes: {', '.join(causes)}")
        print(f"Device: {metadata['device']}")
        print(f"User: {metadata['username']}")
        print(f"IP: {metadata['ip']}")
        print(f"Location: {metadata['location']}")
        print("-" * 80)

        if len(causes) == 0:
            llm_metrics["FP"] += 1
            continue
        else:
            llm_metrics["TP"] += 1

        if metadata['device'] == "unknown_device":
            continue

        # Enregistrement uniquement si causes détectées
        security.anomaly_state.register_anomaly_event(
            device_id=metadata['device'],
            username=metadata['username'],
            ip=metadata['ip'],
            location=metadata['location']
        )
        
        await update_trust_score_for_device(metadata['device'], db)

    duration = time.monotonic() - start_time
    logger.info(f"⏱️ Total Threat Handling Time: {duration:.3f} sec")

    total = llm_metrics["TP"] + llm_metrics["FP"]
    if total > 0 and total % 10 == 0:
        precision = llm_metrics["TP"] / (llm_metrics["TP"] + llm_metrics["FP"] + 1e-8)
        logger.info(f"📊 LLM Metrics — TP: {llm_metrics['TP']} | FP: {llm_metrics['FP']} | Precision: {precision:.2f}")

        

async def incident_responder():
    async with AsyncSessionLocal() as db:
        while True:
            context, score, detection_id = await incident_queue.get()
            await handle_detected_threat(context, score, detection_id, db)
