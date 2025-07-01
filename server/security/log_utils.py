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
        user_agent = log.get("user_agent", "unknown")
        log_warn = log.get("log_warn","")

        # Only keep the hour of timestamp
        timestamp = timestamp.split(" ")[1] if timestamp else "unknown_time"
        
        hour = int(timestamp.split(":")[0])
        if 7 <= hour <= 23:
            sentence = f"At {timestamp}, "
        else:
            sentence = f"At {timestamp} (outside of normal hours), "

        if location == "Private IP":
            sentence += f" normal location, IP {ip}, "
        else:
            sentence += f" suspicious location, IP {ip}, "

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
        elif "/api/fl-update" in endpoint:
            if detection == "ZKP Fail":
                sentence += "The device is not trusted. "
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

        if user_agent != "browser" and user_agent != "python":
            sentence += f"Suspicious user agent detected: {user_agent}. "

        if rate != "?/min":
            # if rate is more than 5 requests per minute, flag it as suspicious
            if int(rate.split("/")[0]) > 8:
                sentence += f"This request rate is suspicious ({rate})."
            else:
                sentence += f"Request rate is normal ({rate})."
        
        if log_warn:
            sentence += f"This log was as warning."

        context.append(sentence)

    return " ".join(context)



# This function takes a log file path and reads the last 'block_size' lines from it.
# It parses each line to extract relevant information and returns a list of dictionaries.
# Each dictionary contains the parsed information from a log entry.

def parse_last_logs_from_raw_file(log_source, block_size=10):
    # Determine if log_source is a path or a list of strings
    if isinstance(log_source, str):
        with open(log_source, "r") as f:
            lines = f.readlines()[-block_size:]
    elif isinstance(log_source, list):
        lines = log_source[-block_size:]
    else:
        raise ValueError("log_source must be a filepath (str) or a list of log lines.")

    block_texts = []
    for line in lines:
        try:
            timestamp = re.search(r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
            timestamp = timestamp.group()[1:] if timestamp else ""

            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            ip = ip_match.group(1) if ip_match else "unknown_ip"

            location_match = re.search(r"\(([^)]+)\)", line)
            location = location_match.group(1) if location_match else "unknown_location"

            user_device_match = re.search(r"- (\S+) (\S+) (\S+)", line)
            user = user_device_match.group(1) if user_device_match else "unknown_user"
            device = user_device_match.group(2) if user_device_match else "unknown_device"
            role = user_device_match.group(3) if user_device_match else "unknown_role"

            request_match = re.search(r"\"(GET|POST|PUT|DELETE) [^\"]+\"", line)
            request = request_match.group() if request_match else "UNKNOWN"

            status_code = re.search(r"\s(\d{3})\s", line)
            status_code = status_code.group(1) if status_code else "000"

            user_agent = "browser" if "Mozilla" in line else "python" if "python-requests" in line else "suspicious"

            action_match = re.search(r"\[Action\s*:\s*(.*?)\]", line)
            action = action_match.group(1) if action_match else "unknown_action"

            rate_match = re.search(r"\[Request rate:\s*([^\]]+)\]", line)
            request_rate = rate_match.group(1) if rate_match else "0/min"

            log_warn = "WARNING" in line

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
            elif "ZKP Fail" in line:
                detection = "ZKP Fail"

            block_texts.append({
                "timestamp": timestamp,
                "ip": ip,
                "location": location,
                "user": user,
                "device": device,
                "role": role,
                "endpoint": request,
                "status": status_code,
                "status_tag": alert,
                "user_agent": user_agent,
                "detection": detection,
                "warn": log_warn,
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


def extract_anomaly_causes(context: str):
    anomalies = []

    # Split lines based on your /min) pattern (inclusive)
    lines = re.findall(r"At .*?/min\)", context)

    for line in lines:
        line = line.strip()
        if not line:
            continue

        metadata = {
            "device": "unknown_device",
            "username": "unknown_user",
            "ip": "unknown_ip",
            "location": "unknown_location"
        }

        # Extract device
        device_match = re.search(r"device (\S+)", line)
        if device_match:
            metadata["device"] = device_match.group(1).rstrip(".")

        # Extract username
        user_match = re.search(r"IP \S+ (\S+) (accessed|attempted|uploaded|sent|made)", line)
        if user_match:
            metadata["username"] = user_match.group(1)

        # Extract IP
        ip_match = re.search(r"IP (\d+\.\d+\.\d+\.\d+)", line)
        if ip_match:
            metadata["ip"] = ip_match.group(1)

        # Extract location
        loc_match = re.search(r"From ([^,]+)", line)
        if loc_match:
            metadata["location"] = loc_match.group(1)

        # Detect causes
        causes = []
        if "outside of normal hours" in line:
            causes.append("Access at night (time anomaly)")
        if "Suspicious user agent detected" in line:
            causes.append("Suspicious user agent")
        if "request rate is suspicious" in line:
            causes.append("High request rate")
        if "possible brute force" in line:
            causes.append("Brute-force login attempt")
        if "Medical anomaly detected" in line:
            causes.append("Medical anomaly in data")
        if "System alert reported" in line:
            causes.append("System alert")
        if "Device not registered to this user" in line:
            causes.append("Device mismatch (wrong device)")
        if "suspicious location" in line:
            causes.append("External IP or suspicious location")

        anomalies.append({
            "causes": causes,
            "metadata": metadata,
            "line": line
        })

    return anomalies


def detect_behavioral_patterns(logs):
    """Detect behavioral patterns from logs."""
    
    patterns = []
    
    # Count different types of activities
    failed_logins = sum(1 for log in logs if "Login Failed" in log.get("detection", ""))
    successful_logins = sum(1 for log in logs if "/login" in log.get("endpoint", "") and "Login Failed" not in log.get("detection", ""))
    device_mismatches = sum(1 for log in logs if "Wrong User's Device" in log.get("detection", ""))
    high_rate_requests = sum(1 for log in logs if is_high_rate(log.get("rate", "")))
    data_uploads = sum(1 for log in logs if "/api/sensor" in log.get("endpoint", ""))
    external_access = sum(1 for log in logs if log.get("location", "") != "Private IP")
    
    # Pattern detection
    if failed_logins >= 3:
        patterns.append("repeated login failures")
    elif failed_logins >= 1 and successful_logins == 0:
        patterns.append("login attempts without success")
    
    if device_mismatches > 0:
        patterns.append("device identity mismatch")
    
    if high_rate_requests > 0:
        patterns.append("high frequency requests")
    
    if external_access > 0 and failed_logins > 0:
        patterns.append("external access with authentication issues")
    
    if data_uploads > 0 and device_mismatches > 0:
        patterns.append("suspicious data upload activity")
    
    # Check for scanning patterns
    unique_endpoints = len(set(log.get("endpoint", "/") for log in logs))
    if unique_endpoints >= 5:
        patterns.append("endpoint reconnaissance")
    
    # Check for normal activity
    if not patterns and successful_logins > 0 and failed_logins == 0:
        patterns.append("normal user activity")
    
    return patterns


def format_log_activity(log, include_user=False):
    """Format a single log entry as activity description."""
    
    endpoint = log.get("endpoint", "/")
    status = log.get("status", "")
    detection = log.get("detection", "")
    device = log.get("device", "")
    rate = log.get("rate", "")
    
    # Build activity description
    activity = ""
    
    if "/login" in endpoint:
        if "Login Failed" in detection:
            activity = "Login failed"
        else:
            activity = "Successfully logged in"
    
    elif "/dashboard" in endpoint:
        if "Access Failed" in detection:
            activity = "Dashboard access denied"
        else:
            activity = "Accessed dashboard"
    
    elif "/api/sensor" in endpoint:
        activity = f"Uploaded medical data"
        if device:
            activity += f" from device {device}"
    
    elif "/api/system-status" in endpoint:
        activity = f"Sent system status"
        if device:
            activity += f" from device {device}"
    
    elif "/api/fl-update" in endpoint:
        activity = "Attempted system update"
    
    elif "GET" in endpoint and endpoint != "/":
        if status == "200":
            activity = f"Accessed {endpoint.split('/')[-1]} page"
        else:
            activity = f"Failed to access {endpoint.split('/')[-1]} page"
    
    elif endpoint == "/" or "home" in endpoint:
        activity = "Accessed home page"
    
    else:
        activity = f"Made request to {endpoint}"
    
    # Add additional context
    context_items = []
    
    if detection and detection not in ["Login Failed", "Access Failed"]:
        context_items.append(f"Alert: {detection}")
    
    if rate and is_high_rate(rate):
        context_items.append(f"{rate}")
    
    if context_items:
        activity += f" ({', '.join(context_items)})"
    
    return activity



def calculate_time_span(logs):
    """Calculate time span of session."""
    
    timestamps = [log.get("timestamp", "") for log in logs if log.get("timestamp", "")]
    if len(timestamps) < 2:
        return None
    
    try:
        # Extract time parts and calculate span
        times = []
        for ts in timestamps:
            if " " in ts:
                time_part = ts.split(" ")[1]
                if ":" in time_part:
                    hour, minute, second = map(int, time_part.split(":"))
                    total_seconds = hour * 3600 + minute * 60 + second
                    times.append(total_seconds)
        
        if len(times) >= 2:
            span_seconds = max(times) - min(times)
            if span_seconds < 60:
                return f"{span_seconds} seconds"
            elif span_seconds < 3600:
                return f"{span_seconds // 60} minutes"
            else:
                return f"{span_seconds // 3600} hours {(span_seconds % 3600) // 60} minutes"
    
    except (ValueError, IndexError):
        pass
    
    return None

def extract_time(timestamp):
    """Extract time portion from timestamp."""
    if not timestamp:
        return "unknown"
    
    if " " in timestamp:
        return timestamp.split(" ")[1]
    elif ":" in timestamp:
        return timestamp
    else:
        return timestamp


def is_high_rate(rate_str):
    """Check if request rate is suspicious."""
    if not rate_str or rate_str == "?/min":
        return False
    try:
        rate_num = int(rate_str.split("/")[0])
        return rate_num > 5
    except (ValueError, IndexError):
        return False


def build_user_session_summary(user, logs):
    """Build session summary for a specific user."""
    
    if not logs:
        return ""
    
    # Extract session metadata
    ips = list(set(log.get("ip", "unknown") for log in logs))
    locations = list(set(log.get("location", "unknown") for log in logs if log.get("location", "unknown") != "unknown"))
    user_agents = list(set(log.get("user_agent", "unknown") for log in logs if log.get("user_agent", "unknown") != "unknown"))
    devices = list(set(log.get("device", "") for log in logs if log.get("device", "")))
    roles = list(set(log.get("role", "unknown") for log in logs if log.get("role", "unknown") != "unknown"))
    
    # Calculate request rate
    total_requests = len(logs)
    time_span = calculate_time_span(logs)
    request_rate = f"{total_requests} requests" + (f" in {time_span}" if time_span else "")
    
    # Detect behavioral patterns
    patterns = detect_behavioral_patterns(logs)
    
    # Build header
    primary_ip = ips[0] if ips else "unknown"
    primary_location = locations[0] if locations else "Unknown"
    primary_agent = user_agents[0] if user_agents else "Unknown"
    
    header = f"Session Summary - User: {user}\n"
    header += f"IP: {primary_ip}"
    if len(ips) > 1:
        header += f" (+{len(ips)-1} others)"
    
    header += f" | Browser: {primary_agent} | Location: {primary_location}"
    if len(locations) > 1:
        header += f" (+{len(locations)-1} others)"
    
    header += f" | {request_rate}"
    
    if devices:
        header += f" | Devices: {', '.join(devices[:2])}"
        if len(devices) > 2:
            header += f" (+{len(devices)-2} more)"
    
    # Add behavioral patterns
    if patterns:
        header += f"\nBehavioral pattern: {', '.join(patterns)}"
    
    # Build activity log
    header += "\nLog Activity:"
    
    activities = []
    for log in logs:
        time_str = extract_time(log.get("timestamp", ""))
        activity = format_log_activity(log)
        if activity:
            activities.append(f"- [{time_str}] {activity}")
    
    return header + "\n" + "\n".join(activities)


def build_session_summaries(log_group, max_users=5, max_logs_per_user=10):
    """
    Build session summaries for each user from log group.
    Groups logs by user and creates structured summaries.
    """
    
    # Group logs by user
    user_logs = {}
    unknown_user_logs = []
    
    for log in log_group:
        user = log.get("user", "").strip()
        if user and user not in ["unknown_user", "unknown", ""]:
            if user not in user_logs:
                user_logs[user] = []
            user_logs[user].append(log)
        else:
            unknown_user_logs.append(log)
    
    summaries = []
    
    # Create summary for each identified user
    for user, logs in list(user_logs.items())[:max_users]:
        # Sort by timestamp and take last N logs
        sorted_logs = sorted(logs, key=lambda x: x.get("timestamp", ""))[-max_logs_per_user:]
        summary = build_user_session_summary(user, sorted_logs)
        summaries.append(summary)
    
    # Aggregate unknown users if any
    if unknown_user_logs:
        sorted_unknown = sorted(unknown_user_logs, key=lambda x: x.get("timestamp", ""))[-max_logs_per_user:]
        summary = build_aggregate_session_summary(sorted_unknown)
        summaries.append(summary)
    
    return "\n\n".join(summaries)


def build_user_session_summary(user, logs):
    """Build session summary for a specific user."""
    
    if not logs:
        return ""
    
    # Extract session metadata
    ips = list(set(log.get("ip", "unknown") for log in logs))
    locations = list(set(log.get("location", "unknown") for log in logs if log.get("location", "unknown") != "unknown"))
    user_agents = list(set(log.get("user_agent", "unknown") for log in logs if log.get("user_agent", "unknown") != "unknown"))
    devices = list(set(log.get("device", "") for log in logs if log.get("device", "")))
    
    # Calculate request rate
    total_requests = len(logs)
    time_span = calculate_time_span(logs)
    request_rate = f"{total_requests} requests" + (f" in {time_span}" if time_span else "")
    
    # Detect behavioral patterns
    patterns = detect_behavioral_patterns(logs)
    
    # Build header
    primary_ip = ips[0] if ips else "unknown"
    primary_location = locations[0] if locations else "Unknown"
    primary_agent = user_agents[0] if user_agents else "Unknown"
    
    header = f"Session Summary - User: {user}\n"
    header += f"IP: {primary_ip}"
    if len(ips) > 1:
        header += f" (+{len(ips)-1} others)"
    
    header += f" | Browser: {primary_agent} | Location: {primary_location}"
    if len(locations) > 1:
        header += f" (+{len(locations)-1} others)"
    
    header += f" | {request_rate}"
    
    if devices:
        header += f" | Devices: {', '.join(devices[:2])}"
        if len(devices) > 2:
            header += f" (+{len(devices)-2} more)"
    
    # Add behavioral patterns
    if patterns:
        header += f"\nBehavioral pattern: {', '.join(patterns)}"
    
    # Build activity log
    header += "\nLog Activity:"
    
    activities = []
    for log in logs:
        time_str = extract_time(log.get("timestamp", ""))
        activity = format_log_activity(log)
        if activity:
            activities.append(f"- [{time_str}] {activity}")
    
    return header + "\n" + "\n".join(activities)


def build_aggregate_session_summary(logs):
    """Build aggregated summary for unknown/mixed users."""
    
    if not logs:
        return ""
    
    # Extract session metadata
    ips = list(set(log.get("ip", "unknown") for log in logs))
    locations = list(set(log.get("location", "unknown") for log in logs if log.get("location", "unknown") != "unknown"))
    user_agents = list(set(log.get("user_agent", "unknown") for log in logs if log.get("user_agent", "unknown") != "unknown"))
    
    # Calculate request rate
    total_requests = len(logs)
    time_span = calculate_time_span(logs)
    request_rate = f"{total_requests} requests" + (f" in {time_span}" if time_span else "")
    
    # Detect behavioral patterns
    patterns = detect_behavioral_patterns(logs)
    
    # Build header
    header = f"Session Summary - Mixed/Unknown Users\n"
    header += f"IPs: {len(ips)} unique ({', '.join(ips[:3])}{'...' if len(ips) > 3 else ''})"
    header += f" | Locations: {len(locations)} unique"
    header += f" | {request_rate}"
    
    # Add behavioral patterns
    if patterns:
        header += f"\nBehavioral pattern: {', '.join(patterns)}"
    
    # Build activity log
    header += "\nLog Activity:"
    
    activities = []
    for log in logs:
        time_str = extract_time(log.get("timestamp", ""))
        user = log.get("user", "unknown")
        activity = format_log_activity(log, include_user=True)
        if activity:
            activities.append(f"- [{time_str}] {user}: {activity}")
    
    return header + "\n" + "\n".join(activities)