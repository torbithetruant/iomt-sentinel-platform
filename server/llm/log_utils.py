import re

def build_context_from_logs(log_group):
    context = []
    last_ip_per_user = {}

    for log in log_group:
        timestamp = log.get("timestamp", "")
        ip = log.get("ip", "pas d’IP")
        user = log.get("user", "pas de user")
        device = log.get("device", "")
        endpoint = log.get("endpoint", "/")
        status = log.get("status", "")
        status_tag = log.get("status_tag", "")
        detection = log.get("detection", "")

        if endpoint.startswith("POST") and user != "unknown user":
            previous_ip = last_ip_per_user.get(user)
            if previous_ip and previous_ip != ip:
                context.append(
                    f"Alerte : l’utilisateur {user} a changé d’adresse IP, passant de {previous_ip} à {ip} pour une requête POST."
                )
            last_ip_per_user[user] = ip

        sentence = f"{timestamp} : "
        if "GET" in endpoint:
            if status == "200":
                sentence += f"{user} a accédé à l’interface {endpoint} via depuis l’adresse IP {ip}.\n"
            else:
                sentence += f"{user} a tenté d’accéder à l’interface {endpoint} depuis l’adresse IP {ip}.\n"
        elif "/api/sensor" in endpoint:
            sentence += f"{user} a envoyé des données médicales avec le capteur {device} depuis {ip}.\n"
            if status_tag == "Alert":
                sentence += f" Une alerte médicale a été détectée dans les données envoyées.\n"
            if detection == "Wrong User's Device":
                sentence += f" (Capteur {device} non associé à {user} — potentielle attaque).\n"
        elif "/api/system-status" in endpoint:
            sentence += f"{user} a transmis l’état système du dispositif {device} via {ip}.\n"
            if status_tag == "Alert":
                sentence += f" Une alerte système a été détectée.\n"
            if detection == "Wrong User's Device":
                sentence += f" (Capteur {device} non associé à {user} — potentielle attaque).\n"
        elif "/login" in endpoint:
            if detection == "Login Failed":
                sentence += f"{user} a échoué à se connecter depuis {ip} (possiblement attaque brute force).\n"
            else:
                sentence += f"{user} a réussi à se connecter depuis {ip}.\n"
        elif "/dashboard" in endpoint:
            if detection == "Access Failed":
                sentence += f"{user} a tenté d’accéder à l’interface depuis {ip} mais a échoué.\n"
            else:
                sentence += f"{user} a accédé à l’interface depuis {ip}.\n"
        elif "Invalid Token" in detection:
            sentence += f"{user} a tenté d’accéder à l’interface avec un token invalide depuis {ip}.\n"
        else:
            sentence += f"{user} a effectué une requête {endpoint} avec {device} depuis {ip}."

        context.append(sentence)

    return " ".join(context)

def parse_last_logs_from_raw_file(log_path, block_size=10):
    with open(log_path, "r") as f:
        lines = f.readlines()[-block_size:]

    block_texts = []
    for line in lines:
        try:
            timestamp = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line).group()
            ip = re.search(r"\d+\.\d+\.\d+\.\d+", line).group()
            user_device_match = re.search(r"- (\S+) (\S+)", line)
            user = user_device_match.group(1) if user_device_match else "random user"
            if user == "-":
                user = "random user"
            device = user_device_match.group(2) if user_device_match else "unknown_device"
            if device == "-":
                device = ""
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

        except:
            continue

    return block_texts
