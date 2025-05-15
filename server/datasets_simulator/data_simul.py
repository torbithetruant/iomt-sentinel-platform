import random
import datetime
import pandas as pd

def generate_ip():
    return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"

def random_time(start_time, seconds_offset=0):
    return start_time + datetime.timedelta(seconds=seconds_offset)

def generate_normal_patient_block(user_id, base_time):
    user = f"patient_{user_id:03d}"
    device = f"raspi_{user_id:03d}"
    ip = generate_ip()

    log1 = f"{base_time.strftime('%Y-%m-%d %H:%M:%S')} : {user} a envoyé des données médicales avec le capteur {device} depuis {ip}."
    log2 = f"{base_time.strftime('%Y-%m-%d %H:%M:%S')} : {user} a transmis l’état système du dispositif {device} via {ip}."
    return [log1, log2]

def generate_alert_loop_block(user_id, base_time):
    user = f"patient_{user_id:03d}"
    device = f"raspi_{user_id:03d}"
    ip = generate_ip()
    lines = []
    for i in range(5):
        t = base_time + datetime.timedelta(seconds=i*15)
        log1 = f"{t.strftime('%Y-%m-%d %H:%M:%S')} : {user} a envoyé des données médicales avec le capteur {device} depuis {ip}."
        log1 += " Une alerte médicale a été détectée dans les données envoyées. (Le médecin doit être informé)"
        log2 = f"{t.strftime('%Y-%m-%d %H:%M:%S')} : {user} a transmis l’état système du dispositif {device} via {ip}."
        lines.extend([log1, log2])
    return lines

def generate_brute_force_block(base_time):
    lines = []
    ip = generate_ip()
    for i in range(5):
        t = base_time + datetime.timedelta(seconds=i*8)
        lines.append(
            f"{t.strftime('%Y-%m-%d %H:%M:%S')} : random user a échoué à se connecter depuis {ip}. "
            "Si cette phrase est répétée plusieurs fois, avec le meme user, c'est possiblement une attaque par force brute."
        )
    return lines

def generate_suspicious_access_block(base_time):
    ip = "10.0.2.2"
    return [
        f"{(base_time).strftime('%Y-%m-%d %H:%M:%S')} : doctor_user a tenté d’accéder à l’interface \"GET /.well-known/appspecific/com.chrome.devtools.json\" depuis l’adresse IP {ip}.",
        f"{(base_time + datetime.timedelta(seconds=5)).strftime('%Y-%m-%d %H:%M:%S')} : random user a accédé à l’interface \"GET /login\" via depuis l’adresse IP {ip}.",
        f"{(base_time + datetime.timedelta(seconds=10)).strftime('%Y-%m-%d %H:%M:%S')} : random user a tenté d’accéder à l’interface \"GET /\" depuis l’adresse IP {ip}.",
        f"{(base_time + datetime.timedelta(seconds=15)).strftime('%Y-%m-%d %H:%M:%S')} : random user a réussi à se connecter depuis {ip}.",
        f"{(base_time + datetime.timedelta(seconds=20)).strftime('%Y-%m-%d %H:%M:%S')} : random user a accédé à l’interface \"GET /dashboard\" via depuis l’adresse IP {ip}.",
    ]

def generate_wrong_device_block(user_id, base_time):
    user = f"patient_{user_id:03d}"
    device = f"raspi_{user_id + 100:03d}"  # Capteur non associé
    ip = generate_ip()
    log1 = f"{base_time.strftime('%Y-%m-%d %H:%M:%S')} : {user} a envoyé des données médicales avec le capteur {device} depuis {ip}.\n (Le capteur {device} n'est pas associé à l'utilisateur {user}. Possiblement une attaque sauf si le capteur vient d'être branché.)"
    log2 = f"{base_time.strftime('%Y-%m-%d %H:%M:%S')} : {user} a transmis l’état système du dispositif {device} via {ip}."
    return [log1, log2] * 5  # 10 lignes

def generate_context_block(user_index, label, base_time):
    if label == 0:
        lines = []
        for i in range(5):
            lines += generate_normal_patient_block(user_index + i, base_time + datetime.timedelta(seconds=i*2))
        return " ".join(lines)
    else:
        anomaly_type = random.choice(["alert_loop", "brute_force", "access", "wrong_device"])
        if anomaly_type == "alert_loop":
            return " ".join(generate_alert_loop_block(user_index, base_time))
        elif anomaly_type == "brute_force":
            return " ".join(generate_brute_force_block(base_time))
        elif anomaly_type == "access":
            return " ".join(generate_suspicious_access_block(base_time))
        elif anomaly_type == "wrong_device":
            return " ".join(generate_wrong_device_block(user_index, base_time))

def generate_dataset(num_blocks=1000, anomaly_ratio=0.1, output_csv="iomt_logs_dataset.csv"):
    normal_blocks = int(num_blocks * (1 - anomaly_ratio))
    anomaly_blocks = num_blocks - normal_blocks

    all_data = []
    base_time = datetime.datetime(2025, 5, 14, 13, 0, 0)

    for i in range(normal_blocks):
        context = generate_context_block(i * 10, label=0, base_time=base_time + datetime.timedelta(minutes=i))  
        all_data.append({"context": context, "label": 0})

    for i in range(anomaly_blocks):
        context = generate_context_block(i * 10 + 5000, label=1, base_time=base_time + datetime.timedelta(minutes=i + 2000))
        all_data.append({"context": context, "label": 1})

    df = pd.DataFrame(all_data)
    df.to_csv(output_csv, index=False, quoting=1)  # quoting=1 => csv.QUOTE_ALL
    print(f"✅ Fichier généré : {output_csv} ({len(df)} blocs — {anomaly_blocks} anomalies)")

# Exemple d’utilisation
generate_dataset(num_blocks=10000, anomaly_ratio=0.2)
