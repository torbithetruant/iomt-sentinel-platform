import os
import csv
import re

# This function takes a list of log entries and builds a context string for each entry.
def build_context_from_logs(log_group):
    context = []

    for log in log_group:
        timestamp = log.get("timestamp", "")
        ip = log.get("ip", "no IP")
        location = log.get("location", "unknown location")
        user = log.get("user", "unknown user")
        device = log.get("device", "")
        endpoint = log.get("endpoint", "/")
        status = log.get("status", "")
        status_tag = log.get("status_tag", "")
        detection = log.get("detection", "")
        action = log.get("action", "unknown_action")
        rate = log.get("rate", "?/min")

        sentence = f"At {timestamp} — From {location}, IP {ip} "

        if "GET" in endpoint:
            if status == "200":
                sentence += f"{user} accessed the interface {endpoint}. "
            else:
                sentence += f"{user} attempted to access {endpoint} and failed. "
        elif "/api/sensor" in endpoint:
            sentence += f"{user} uploaded medical data using device {device}. "
            if status_tag == "Alert":
                sentence += "Medical anomaly detected in the data. "
            if detection == "Wrong User's Device":
                sentence += "Device not registered to this user — possible attack. "
        elif "/api/system-status" in endpoint:
            sentence += f"{user} sent system status for device {device}. "
            if status_tag == "Alert":
                sentence += "System alert reported. "
            if detection == "Wrong User's Device":
                sentence += "Device not registered to this user — possible attack. "
        elif "/login" in endpoint:
            if detection == "Login Failed":
                sentence += f"{user} failed to log in — possible brute force. "
            else:
                sentence += f"{user} successfully logged in. "
        elif "/dashboard" in endpoint:
            if detection == "Access Failed":
                sentence += f"{user} failed to access dashboard. "
            else:
                sentence += f"{user} accessed the dashboard. "
        elif "Invalid Token" in detection:
            sentence += f"{user} attempted access with an invalid token. "
        else:
            sentence += f"{user} made a request to {endpoint} with device {device}. "

        sentence += f"(Rate: {rate})\n"
        context.append(sentence)

    return " ".join(context)



# This function takes a log file path and reads the last 'block_size' lines from it.
# It parses each line to extract relevant information and returns a list of dictionaries.
# Each dictionary contains the parsed information from a log entry.
import re

def parse_last_logs_from_raw_file(log_path, block_size=10):
    with open(log_path, "r") as f:
        lines = f.readlines()[-block_size:]

    block_texts = []
    for line in lines:
        try:
            timestamp = re.search(r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
            timestamp = timestamp.group()[1:] if timestamp else ""

            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            ip = ip_match.group(1) if ip_match else "unknown_ip"

            location_match = re.search(r"\(([^)]+)\)", line)
            location = location_match.group(1) if location_match else "unknown_location"

            user_device_match = re.search(r"- (\S+) (\S+)", line)
            user = user_device_match.group(1) if user_device_match else "unknown_user"
            device = user_device_match.group(2) if user_device_match else "unknown_device"

            request_match = re.search(r"\"(GET|POST|PUT|DELETE) [^\"]+\"", line)
            request = request_match.group() if request_match else "UNKNOWN"

            status_code = re.search(r"\s(\d{3})\s", line)
            status_code = status_code.group(1) if status_code else "000"

            action_match = re.search(r"\[Action\s*:\s*(.*?)\]", line)
            action = action_match.group(1) if action_match else "unknown_action"

            rate_match = re.search(r"\[Request rate:\s*([^\]]+)\]", line)
            request_rate = rate_match.group(1) if rate_match else "0/min"

            alert = "Alert" if "Alert" in line else ""
            detection = ""
            if "Login Failed" in line:
                detection = "Login Failed"
            elif "Access Failed" in line:
                detection = "Access Failed"
            elif "Invalid Token" in line:
                detection = "Invalid Token"
            elif "New Device" in line:
                detection = "Wrong User's Device"

            block_texts.append({
                "timestamp": timestamp,
                "ip": ip,
                "location": location,
                "user": user,
                "device": device,
                "endpoint": request,
                "status": status_code,
                "status_tag": alert,
                "detection": detection,
                "action": action,
                "rate": request_rate
            })

        except Exception:
            continue

    return block_texts

def convert_log_to_dataset(log_path: str, output_csv: str, block_size: int = 10):
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"Fichier introuvable : {log_path}")

    with open(log_path, "r", encoding="utf-8") as f:
        all_lines = [line.strip() for line in f if line.strip()]  # ignore lignes vides

    num_blocks = len(all_lines) // block_size
    dataset = []
    skipped_blocks = 0

    for i in range(num_blocks):
        block = all_lines[i * block_size:(i + 1) * block_size]
        label = 0
        cleaned_lines = []

        for line in block:
            match = re.match(r"#LABEL:(\d)(.*)", line)
            if match:
                label_candidate = int(match.group(1))
                if label_candidate == 1:
                    label = 1
                line = match.group(2).strip()
            cleaned_lines.append(line)

        with open("tmp_block.log", "w", encoding="utf-8") as tmp:
            tmp.write("\n".join(cleaned_lines))

        parsed_logs = parse_last_logs_from_raw_file("tmp_block.log", block_size=len(cleaned_lines))
        context = build_context_from_logs(parsed_logs)

        if context.strip():
            dataset.append({"context": context.strip(), "label": label})
        else:
            skipped_blocks += 1

    os.remove("tmp_block.log")

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["context", "label"])
        writer.writeheader()
        writer.writerows(dataset)

    print(f"✅ Dataset sauvegardé : {output_csv}")
    print(f"💡 Nombre total de blocs : {num_blocks}")
    print(f"✔️ Blocs valides : {len(dataset)}")
    print(f"🚫 Blocs ignorés (vides ou invalides) : {skipped_blocks}")

# Exemple d'utilisation
if __name__ == "__main__":
    convert_log_to_dataset("datasets/iomt_realistic.log", "datasets/bert_finetune_dataset.csv", block_size=10)
