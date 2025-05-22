import random
import datetime
import os

# === Générateur de logs IoMT réalistes (fichier .log brut) ===
def generate_ip():
    return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_log_line(timestamp, action, ip, location, user, device, endpoint, status, rate, context_tags, user_agent="python-requests/2.32.3"):
    tag_str = " ".join([f"[{tag}]" for tag in context_tags])
    return f"[{timestamp}] INFO [iomt] [Action : {action}] {ip} ({location}) - {user} {device} \"{endpoint}\" {status} [Request rate: {rate}] {tag_str} {user_agent}\n"

def generate_normal_block(user_id, base_time):
    lines = ["#LABEL:0"]
    user = f"patient_{user_id:03d}"
    device = f"raspi_{user_id:03d}"
    ip = generate_ip()
    timestamp = base_time.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]

    lines.append(generate_log_line(timestamp, "sensor_upload", ip, "Private IP", user, device, "POST /api/sensor", 200, f"{random.randint(2,4)}/min", ["Normal Device", "Safe"]))
    lines.append("#LABEL:0")
    lines.append(generate_log_line(timestamp, "system_check", ip, "Private IP", user, device, "POST /api/system-status", 200, f"{random.randint(2,4)}/min", ["Normal Device", "Safe"]))
    return lines

def generate_alert_block(user_id, base_time):
    lines = ["#LABEL:1"]
    user = f"patient_{user_id:03d}"
    device = f"raspi_{user_id:03d}"
    ip = generate_ip()
    timestamp = base_time.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]

    lines.append(generate_log_line(timestamp, "sensor_upload", ip, "Private IP", user, device, "POST /api/sensor", 200, "4/min", ["Normal Device", "Alert"]))
    lines.append("#LABEL:1")
    lines.append(generate_log_line(timestamp, "system_check", ip, "Private IP", user, device, "POST /api/system-status", 200, "4/min", ["Normal Device", "Alert"]))
    return lines

def generate_wrong_device_block(user_id, base_time):
    lines = ["#LABEL:1"]
    user = f"patient_{user_id:03d}"
    device = f"raspi_{user_id + 100:03d}"
    ip = generate_ip()
    timestamp = base_time.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]

    lines.append(generate_log_line(timestamp, "sensor_upload", ip, "Private IP", user, device, "POST /api/sensor", 200, "3/min", ["New Device Used", "Safe"]))
    return lines

def generate_brute_force_block(base_time):
    lines = ["#LABEL:1"]
    ip = generate_ip()
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    for i in range(5):
        t = (base_time + datetime.timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
        lines.append(generate_log_line(t, "login_attempt", ip, "Private IP", "-", "-", "POST /login", 403, "4/min", ["Login Failed"], user_agent))
        if i < 4 : 
            lines.append("#LABEL:1")
    return lines

def generate_fp_block(user_id, base_time):
    lines = ["#LABEL:0"]
    user = f"patient_{user_id:03d}"
    device = f"raspi_{user_id:03d}"
    ip = generate_ip()
    timestamp = base_time.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    lines.append(generate_log_line(timestamp, "sensor_upload", ip, "Private IP", user, device, "POST /api/sensor", 200, "3/min", ["Normal Device", "Alert"]))
    return lines

def generate_fn_block(user_id, base_time):
    lines = ["#LABEL:1"]
    user = f"patient_{user_id:03d}"
    device = f"raspi_{user_id:03d}"
    ip = generate_ip()
    timestamp = base_time.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    lines.append(generate_log_line(timestamp, "sensor_upload", ip, "Private IP", user, device, "POST /api/sensor", 200, "3/min", ["Normal Device", "Safe"]))
    return lines

def generate_high_rate_block(user_id, base_time):
    lines = ["#LABEL:1"]
    user = f"patient_{user_id:03d}"
    device = f"raspi_{user_id:03d}"
    ip = generate_ip()
    timestamp = base_time.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    for i in range(5):
        lines.append(generate_log_line(timestamp, "sensor_upload", ip, "Private IP", user, device, "POST /api/sensor", 200, "20/min", ["Normal Device", "Safe"]))
        if i < 4:
            lines.append("#LABEL:1")
    return lines

def generate_location_anomaly_block(user_id, base_time):
    lines = ["#LABEL:1"]
    user = f"patient_{user_id:03d}"
    device = f"raspi_{user_id:03d}"
    ip = "212.47.240.12"  # Externe IP simulée (ex. pays étranger)
    timestamp = base_time.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    lines.append(generate_log_line(timestamp, "sensor_upload", ip, "Germany", user, device, "POST /api/sensor", 200, "3/min", ["Normal Device", "Safe"]))
    return lines

def generate_user_agent_anomaly_block(user_id, base_time):
    lines = ["#LABEL:1"]
    user = f"patient_{user_id:03d}"
    device = f"raspi_{user_id:03d}"
    ip = generate_ip()
    timestamp = base_time.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    ua = "sqlmap/1.5.2#stable (http://sqlmap.org)"
    lines.append(generate_log_line(timestamp, "sensor_upload", ip, "Private IP", user, device, "POST /api/sensor", 200, "3/min", ["Normal Device", "Safe"], ua))
    return lines

def generate_fp_block_night_login(user_id, base_time):
    user = "doctor_user"
    device = f"laptop_{user_id:03d}"
    ip = "88.198.55.76"
    timestamp = base_time.replace(hour=3).strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4)"

    lines = ["#LABEL:0"]
    lines.append(generate_log_line(timestamp, "login_attempt", ip, "Netherlands", user, device, "POST /login", 302, "1/min", ["Login Success"], ua))
    lines.append("#LABEL:0")
    lines.append(generate_log_line(timestamp, "dashboard_access", ip, "Netherlands", user, device, "GET /dashboard/doctor", 200, "1/min", ["Dashboard Access"], ua))
    return lines

def generate_fp_block_new_device(user_id, base_time):
    user = "doctor_user"
    device = f"tablet_{user_id:03d}"
    ip = "185.199.108.153"
    timestamp = base_time.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    ua = "Mozilla/5.0 (iPad; CPU OS 15_2 like Mac OS X)"

    lines = ["#LABEL:0"]
    lines.append(generate_log_line(timestamp, "login_attempt", ip, "France", user, device, "POST /login", 302, "1/min", ["Login Success"], ua))
    lines.append("#LABEL:0")
    lines.append(generate_log_line(timestamp, "dashboard_access", ip, "France", user, device, "GET /dashboard/doctor/alerts", 200, "1/min", ["Dashboard Access"], ua))
    return lines

def generate_admin_doctor_normal_block(user_type: str, user_id: int, base_time: datetime.datetime):
    """
    Génère un bloc de logs normal pour un utilisateur `doctor_user` ou `it_admin_user`
    """
    lines = []
    user = f"{user_type}_{user_id:03d}"
    device = f"workstation_{user_id:03d}"
    ip = generate_ip()
    location = "France"
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    timestamp_login = base_time.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    timestamp_dash = (base_time + datetime.timedelta(seconds=3)).strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]

    lines.append("#LABEL:0")  # comportement normal
    lines.append(generate_log_line(timestamp_login, "login_attempt", ip, location, user, device, "POST /login", 302, "1/min", ["Login Success"], user_agent))

    lines.append("#LABEL:0")
    if user_type == "doctor":
        lines.append(generate_log_line(timestamp_dash, "dashboard_access", ip, location, user, device, "GET /dashboard/doctor", 200, "1/min", ["Dashboard Access"], user_agent))
    else:
        lines.append(generate_log_line(timestamp_dash, "dashboard_access", ip, location, user, device, "GET /dashboard/system", 200, "1/min", ["Dashboard Access"], user_agent))

    return lines


def generate_log_file(output_log="datasets/iomt_realistic.log", num_blocks=1000, anomaly_ratio=0.1):
    os.makedirs(os.path.dirname(output_log), exist_ok=True)
    base_time = datetime.datetime(2025, 5, 21, 13, 30, 0)

    # Wrappers pour harmoniser les signatures
    def brute_force_wrapper(user_id, base_time):
        return generate_brute_force_block(base_time)

    def fp_night_login_wrapper(user_id, base_time):
        return generate_fp_block_night_login(user_id, base_time)

    def fp_new_device_wrapper(user_id, base_time):
        return generate_fp_block_new_device(user_id, base_time)

    anomaly_generators = [
        generate_alert_block,
        generate_wrong_device_block,
        brute_force_wrapper,
        generate_fn_block,
        generate_high_rate_block,
        generate_location_anomaly_block,
        generate_user_agent_anomaly_block,
        fp_night_login_wrapper,
        fp_new_device_wrapper
    ]

    normal_generators = [
        generate_normal_block,
        generate_fp_block,
        lambda i, t: generate_admin_doctor_normal_block("doctor", i, t),
        lambda i, t: generate_admin_doctor_normal_block("it_admin", i, t)
    ]

    num_anomalies = int(num_blocks * anomaly_ratio)
    num_normals = num_blocks - num_anomalies

    blocks = []

    for i in range(num_anomalies):
        gen_func = random.choice(anomaly_generators)
        block = gen_func(i, base_time + datetime.timedelta(seconds=i * 5))
        blocks.append(block)

    for i in range(num_normals):
        gen_func = random.choice(normal_generators)
        block = gen_func(i + num_anomalies, base_time + datetime.timedelta(seconds=(i + num_anomalies) * 5))
        blocks.append(block)

    random.shuffle(blocks)

    label_counts = {0: 0, 1: 0}
    with open(output_log, "w", encoding="utf-8") as f:
        for block in blocks:
            block_label = 0  # Default

            for line in block:
                if line.strip() == "#LABEL:1":
                    block_label = 1  # Si au moins une ligne est une anomalie

            label_counts[block_label] += 1

            # On écrit toutes les lignes dans le fichier, y compris le label
            for line in block:
                f.write(line)

    print(f"✅ Fichier généré : {output_log} ({num_blocks} blocs)")
    print(f"📊 Répartition des labels : Normal = {label_counts[0]}, Anomalie = {label_counts[1]}")

# Exemple d'appel
generate_log_file("datasets/iomt_realistic.log", num_blocks=100000)