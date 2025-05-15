import re
import pandas as pd
import random

def extract_features_from_log(line, is_anomalous=False):
    try:
        timestamp = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line).group()
        ip = re.search(r"\d+\.\d+\.\d+\.\d+", line).group()
        user_device_match = re.search(r"- (\S+) (\S+)", line)
        user = user_device_match.group(1) if user_device_match else "random_user"
        if user == "-": user = "random_user"
        device = user_device_match.group(2) if user_device_match else "unknown_device"
        if device == "-": device = "unknown_device"
        request_match = re.search(r"\"(GET|POST|PUT|DELETE) [^\"]+\"", line)
        request = request_match.group(0) if request_match else "UNKNOWN"
        status_code = re.search(r"\s(\d{3})\s", line)
        status_code = status_code.group(1) if status_code else "000"

        alert = "No Alert"
        detection = "No Detection"
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
            "status_code": int(status_code),
            "status_tag": alert,
            "detection": detection,
            "label": int(is_anomalous)
        }
        return summary
    except Exception:
        return None

def process_logs_one_by_one(log_lines, first_file=True):
    processed_logs = []
    for i, line in enumerate(log_lines):
        # Label based on position in log
        if first_file:
            is_anomalous = 4882 < i < 5275
        else:
            is_anomalous = 2119 < i < 3671

        if not is_anomalous and random.random() < 0.12:
            is_anomalous = True

        if is_anomalous and random.random() < 0.14:
            is_anomalous = False
        
        features = extract_features_from_log(line, is_anomalous)
        if features:
            processed_logs.append(features)
    return pd.DataFrame(processed_logs)

with open("logs/server.log.1", "r") as f:
    logs = f.readlines()

df_blocks = process_logs_one_by_one(logs, first_file=True)

with open("logs/server.log", "r") as f:
    logs = f.readlines()

df_blocks2 = process_logs_one_by_one(logs, first_file=False)

# concatener les deux DataFrames
df_blocks = pd.concat([df_blocks, df_blocks2], ignore_index=True)

# enregistrer le DataFrame dans un fichier CSV
df_blocks.to_csv("logs/baseline_logs.csv", index=False)

print(df_blocks.head())