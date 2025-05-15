import re
import pandas as pd

def build_context_from_logs(log_group):
    """
    Construit une phrase de contexte à partir d’un groupe de logs (max 10).
    Détecte si l’IP change pour un même utilisateur dans des requêtes POST.
    """
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

        # Détection de changement d’IP pour un même utilisateur (dans les requêtes POST uniquement)
        if endpoint.startswith("POST") and user != "unknown user":
            previous_ip = last_ip_per_user.get(user)
            if previous_ip and previous_ip != ip:
                context.append(
                    f"Alerte : l’utilisateur {user} a changé d’adresse IP, passant de {previous_ip} à {ip} pour une requête POST."
                )
            last_ip_per_user[user] = ip

        # Phrase naturelle selon le endpoint
        sentence = f"{timestamp} : "
        if "GET" in endpoint:
            if status == "200":
                sentence += f"{user} a accédé à l’interface {endpoint} via depuis l’adresse IP {ip}.\n"
            else:
                sentence += f"{user} a tenté d’accéder à l’interface {endpoint} depuis l’adresse IP {ip}.\n"
        elif "/api/sensor" in endpoint:
            sentence += f"{user} a envoyé des données médicales avec le capteur {device} depuis {ip}.\n"
            if status_tag == "Alert":
                sentence += f" Une alerte médicale a été détectée dans les données envoyées. (Le médecin doit être informé)\n"
            if detection == "Wrong User's Device":
                sentence += f" (Le capteur {device} n'est pas associé à l'utilisateur {user}. Possiblement une attaque sauf si le capteur vient d'être branché.)\n"
        elif "/api/system-status" in endpoint:
            sentence += f"{user} a transmis l’état système du dispositif {device} via {ip}.\n"
            if status_tag == "Alert":
                sentence += f" Une alerte système a été détectée dans les données envoyées. (L'admin doit être informé)\n"
            if detection == "Wrong User's Device":
                sentence += f" (Le capteur {device} n'est pas associé à l'utilisateur {user}. Possiblement une attaque sauf si le capteur vient d'être branché.)\n"
        elif "/login" in endpoint:
            if detection == "Login Failed":
                sentence += f"{user} a échoué à se connecter depuis {ip}. Si cette phrase est répétée plusieurs fois, avec le meme user, c'est possiblement une attaque par force brute.\n"
            else:
                sentence += f"{user} a réussi à se connecter depuis {ip}.\n"
        elif "/dashboard" in endpoint:
            if detection == "Access Failed":
                sentence += f"{user} a tenté d’accéder à l’interface depuis {ip} mais a échoué. (Peut-être une attaque si l'utilisateur est un patient)\n"
            else:
                sentence += f"{user} a accédé à l’interface depuis {ip}.\n"
        elif "Invalid Token" in detection:
            sentence += f"{user} a tenté d’accéder à l’interface avec un token invalide depuis {ip}.\n"
        else:
            sentence += f"{user} a effectué une requête {endpoint} avec {device} depuis {ip}."

        context.append(sentence)

    return " ".join(context)

def group_logs_by_context(log_lines, block_size=10, first_file=True):
    context_blocks = []
    
    for i in range(0, len(log_lines), block_size):
        block = log_lines[i:i+block_size]
        block_texts = []
        anomaly_detected = False
        if first_file:
            if i > 4882 and i < 5275:
                anomaly_detected = True
        # end of server.log.1
        else:
            if i > 2119 and i < 3671:
                anomaly_detected = True
        # begin of server.log
        # i > 2119

        for line in block:
            try:
                # Date/heure
                timestamp = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line).group()

                # IP + user
                ip = re.search(r"\d+\.\d+\.\d+\.\d+", line).group()
                user_device_match = re.search(r"- (\S+) (\S+)", line)
                user = user_device_match.group(1) if user_device_match else "random user"
                if user == "-":
                    user = "random user"
                device = user_device_match.group(2) if user_device_match else "unknown_device"
                if device == "-":
                    device = ""

                # Requête
                request_match = re.search(r"\"(GET|POST|PUT|DELETE) [^\"]+\"", line)
                request = request_match.group() if request_match else "UNKNOWN"

                # État
                status_code = re.search(r"\s(\d{3})\s", line)
                status_code = status_code.group(1) if status_code else "000"

                # Anomalie ?
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

                # Résumé ligne
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

        # Concaténer 10 événements en un seul bloc de contexte
        context = build_context_from_logs(block_texts)
        context_blocks.append({
            "context": context,
            "label": int(anomaly_detected)
        })

    return pd.DataFrame(context_blocks)

with open("logs/server.log.1", "r") as f:
    logs = f.readlines()

df_blocks = group_logs_by_context(logs, block_size=10, first_file=True)

with open("logs/server.log", "r") as f:
    logs = f.readlines()

df_blocks2 = group_logs_by_context(logs, block_size=10, first_file=False)

# concatener les deux DataFrames
df_blocks = pd.concat([df_blocks, df_blocks2], ignore_index=True)

# enregistrer le DataFrame dans un fichier CSV
df_blocks.to_csv("logs/processed_logs.csv", index=False)

print(df_blocks.head())
