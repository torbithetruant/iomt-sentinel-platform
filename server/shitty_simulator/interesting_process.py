import re
import pandas as pd
from collections import Counter

def extract_features_from_block(block_texts):
    features = {}
    
    users = [entry["user"] for entry in block_texts]
    devices = [entry["device"] for entry in block_texts]
    endpoints = [entry["endpoint"] for entry in block_texts]
    status_codes = [entry["status"] for entry in block_texts]
    detections = [entry["detection"] for entry in block_texts if entry["detection"]]
    alerts = [entry["status_tag"] for entry in block_texts if entry["status_tag"]]

    features["unique_users"] = len(set(users))
    features["unique_devices"] = len(set(devices))
    features["num_requests"] = len(endpoints)
    features["num_alerts"] = len(alerts)
    
    # Count specific detection types
    detection_counts = Counter(detections)
    for det_type in ["Alert", "Login Failed", "Access Failed", "Invalid Token", "Wrong User's Device"]:
        features[f"detection_{det_type.replace(' ', '_').lower()}"] = detection_counts.get(det_type, 0)
    
    # Count status codes
    error_codes = [code for code in status_codes if code.startswith("4") or code.startswith("5")]
    features["error_status_fraction"] = len(error_codes) / len(status_codes) if status_codes else 0

    return features

def group_logs_by_context_features(log_lines, block_size=10, first_file=True):
    feature_rows = []
    
    for i in range(0, len(log_lines), block_size):
        block = log_lines[i:i+block_size]
        block_texts = []
        anomaly_detected = False
        
        if first_file:
            if i > 4882 and i < 5275:
                anomaly_detected = True
        else:
            if i > 2119 and i < 3671:
                anomaly_detected = True

        for line in block:
            try:
                timestamp = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line).group()
                ip = re.search(r"\d+\.\d+\.\d+\.\d+", line).group()
                user_device_match = re.search(r"- (\S+) (\S+)", line)
                user = user_device_match.group(1) if user_device_match else "random_user"
                if user == "-": user = "random_user"
                device = user_device_match.group(2) if user_device_match else "unknown_device"
                if device == "-": device = "unknown_device"
                request_match = re.search(r"\"(GET|POST|PUT|DELETE) [^\"]+\"", line)
                request = request_match.group() if request_match else "UNKNOWN"
                status_code = re.search(r"\s(\d{3})\s", line)
                status_code = status_code.group(1) if status_code else "000"

                alert = ""
                detection = ""
                if "Alert" in line:
                    alert = "Alert"
                elif "Login Failed" in line:
                    detection = "Login Failed"
                elif "Access Failed" in line:
                    detection = "Access Failed"
                elif "Invalid Token" in line:
                    detection = "Invalid Token"
                elif "Wrong User's Device" in line:
                    detection = "Wrong User's Device"

                summary = {
                    "timestamp": timestamp,
                    "ip": ip,
                    "user": user,
                    "device": device,
                    "endpoint": request,
                    "status": status_code,
                    "status_tag": alert,
                    "detection": detection
                }
                block_texts.append(summary)

            except Exception as e:
                continue

        if block_texts:
            features = extract_features_from_block(block_texts)
            features["label"] = int(anomaly_detected)
            feature_rows.append(features)

    return pd.DataFrame(feature_rows)

with open("logs/server.log.1", "r") as f:
    logs = f.readlines()

df_blocks = group_logs_by_context_features(logs, block_size=10, first_file=True)

with open("logs/server.log", "r") as f:
    logs = f.readlines()

df_blocks2 = group_logs_by_context_features(logs, block_size=10, first_file=False)

# concatener les deux DataFrames
df_blocks = pd.concat([df_blocks, df_blocks2], ignore_index=True)

# enregistrer le DataFrame dans un fichier CSV
df_blocks.to_csv("logs/baseline_logs.csv", index=False)

print(df_blocks.head())