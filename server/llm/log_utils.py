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

        sentence += f"(Rate: {rate})"
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


def extract_features_from_line_detailed(line: str) -> dict:
    features = {
        "hour": 0,
        "ip_is_private": 1,
        "country": "unknown",
        "user_is_patient": 0,
        "user_is_doctor": 0,
        "user_is_itadmin": 0,
        "endpoint_sensor": 0,
        "endpoint_status": 0,
        "endpoint_login": 0,
        "endpoint_dashboard": 0,
        "method_post": 0,
        "method_get": 0,
        "status_code": 0,
        "rate": 0,
        "tag_alert": 0,
        "tag_wrong_device": 0,
        "tag_login_failed": 0,
        "tag_invalid_token": 0,
        "user_agent_type": "unknown"
    }

    try:
        # Timestamp & heure
        match = re.search(r"\[(\d{4}-\d{2}-\d{2} \d{2}):(\d{2}):(\d{2})", line)
        if match:
            features["hour"] = int(match.group(1).split(" ")[1])

        # IP & localisation
        if "Private IP" in line:
            features["ip_is_private"] = 1
            features["country"] = "private"
        else:
            loc_match = re.search(r"\(([^)]+)\)", line)
            features["ip_is_private"] = 0
            features["country"] = loc_match.group(1) if loc_match else "unknown"

        # Utilisateur
        user_match = re.search(r"- (\S+)", line)
        user = user_match.group(1) if user_match else "-"
        if user.startswith("patient"):
            features["user_is_patient"] = 1
        elif user.startswith("doctor"):
            features["user_is_doctor"] = 1
        elif user.startswith("it_admin"):
            features["user_is_itadmin"] = 1

        # Endpoint
        if "/api/sensor" in line:
            features["endpoint_sensor"] = 1
        if "/api/system-status" in line:
            features["endpoint_status"] = 1
        if "/login" in line:
            features["endpoint_login"] = 1
        if "/dashboard" in line:
            features["endpoint_dashboard"] = 1

        # Méthode
        if "POST" in line:
            features["method_post"] = 1
        if "GET" in line:
            features["method_get"] = 1

        # Status
        status_match = re.search(r"\s(\d{3})\s", line)
        if status_match:
            features["status_code"] = int(status_match.group(1))

        # Request rate
        rate_match = re.search(r"\[Request rate:\s*([^\]]+)\]", line)
        if rate_match:
            features["rate"] = int(rate_match.group(1).split("/")[0])

        # Tags
        features["tag_alert"] = int("Alert" in line)
        features["tag_wrong_device"] = int("New Device" in line)
        features["tag_login_failed"] = int("Login Failed" in line)
        features["tag_invalid_token"] = int("Invalid Token" in line)

        # User-Agent
        if "sqlmap" in line.lower():
            features["user_agent_type"] = "sqlmap"
        elif "python-requests" in line.lower():
            features["user_agent_type"] = "python"
        elif "mozilla" in line.lower():
            features["user_agent_type"] = "browser"

    except Exception as e:
        print("Error parsing line:", e)

    return features

def encode_features_dict_to_vector(features: dict) -> list:
    vector = [
        features["hour"],
        features["ip_is_private"],
        features["user_is_patient"],
        features["user_is_doctor"],
        features["user_is_itadmin"],
        features["endpoint_sensor"],
        features["endpoint_status"],
        features["endpoint_login"],
        features["endpoint_dashboard"],
        features["method_post"],
        features["method_get"],
        features["status_code"],
        features["rate"],
        features["tag_alert"],
        features["tag_wrong_device"],
        features["tag_login_failed"],
        features["tag_invalid_token"]
    ]

    # Encodage simple de user_agent_type
    agent_map = {"python": 0, "browser": 1, "sqlmap": 2, "unknown": 3}
    vector.append(agent_map.get(features["user_agent_type"], 3))

    return vector
