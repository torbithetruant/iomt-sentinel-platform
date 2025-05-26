import logging
import asyncio
import httpx
import security.anomaly_state
from security.log_utils import parse_last_logs_from_raw_file, build_context_from_logs, extract_anomaly_causes
# server
import os

last_inode = None
file_offset = 0
last_line_number = 0

logger = logging.getLogger(__name__)

LLM_API_URL = "http://localhost:8001/infer"  # Update with your LLM server address
seen_contexts = set()
incident_queue = asyncio.Queue()

async def detect_anomalies_remotely(context: str):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(LLM_API_URL, json={"context": context})
            response.raise_for_status()
            data = response.json()
            return data["prediction"], data["score"]
    except Exception as e:
        print(f"LLM API error: {e}")
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
                    await incident_queue.put((extended_context, score))

            await asyncio.sleep(delay)

        except FileNotFoundError:
            print(f"Log file not found: {log_path}")
            await asyncio.sleep(delay)
            continue

# Example: Revoke Keycloak Token (placeholder)
def revoke_user_token(user_id):
    logger.info(f"Revoking token for user {user_id}")
    # Placeholder for actual API call to Keycloak
    # e.g., requests.post("http://keycloak/revoke", ...)
    return True

# Example: Denylist an IP (placeholder)
def denylist_ip(ip_address):
    logger.warning(f"Adding IP {ip_address} to denylist.")
    # Placeholder: Add logic to denylist the IP
    return True

# Example: Send alert (placeholder)
def send_alert(context, score):
    logger.info(f"Sending alert: Score={score}, Context={context}")
    # Placeholder for sending email, webhook, etc.
    return True

async def handle_detected_threat(context, score):
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

        if metadata['device'] == "unknown_device":
            print("⚠️ Device is unknown, skipping further actions.")
            continue
        else:
            security.anomaly_state.register_anomaly_event(
                device_id=metadata['device'],
                username=metadata['username'],
                ip=metadata['ip'],
                location=metadata['location']
            )

        

async def incident_responder():
    while True:
        context, score = await incident_queue.get()
        await handle_detected_threat(context, score)