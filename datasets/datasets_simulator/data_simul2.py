import random
import datetime

# Pools
EXTERNAL_IPS = ["212.47.240.12", "88.198.55.76", "185.199.108.153"]
SUSPICIOUS_UAS = ["sqlmap/1.5.2#stable (http://sqlmap.org)", "curl/7.68.0", "UnknownAgent/1.0"]

def generate_ip(anomalous=False):
    return random.choice(EXTERNAL_IPS) if anomalous else f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_user_agent(anomalous=False):
    return random.choice(SUSPICIOUS_UAS) if anomalous else "python-requests/2.32.3"

def generate_log_line(ts, action, ip, location, user, device, endpoint, status, rate, tags, ua):
    tag_str = " ".join([f"[{tag}]" for tag in tags])
    return f"[{ts}] INFO [iomt] [Action : {action}] {ip} ({location}) - {user} {device} \"{endpoint}\" {status} [Request rate: {rate}] {tag_str} {ua}"

def generate_normal_log(user_id, ts):
    user = f"patient_{user_id:03d}"
    device = f"raspi_{user_id:03d}"
    return generate_log_line(ts, "sensor_upload", generate_ip(), "Private IP", user, device, "POST /api/sensor", 200, f"{random.randint(2,4)}/min", ["Normal Device", "Safe"], generate_user_agent())

def generate_anomaly_log(user_id, ts):
    anomaly_types = [
        lambda: generate_log_line(ts, "sensor_upload", generate_ip(), "Private IP", f"patient_{user_id:03d}", f"raspi_{user_id:03d}", "POST /api/sensor", 200, "4/min", ["Normal Device", "Alert"], generate_user_agent()),
        lambda: generate_log_line(ts, "sensor_upload", generate_ip(anomalous=True), "Germany", f"patient_{user_id:03d}", f"raspi_{user_id:03d}", "POST /api/sensor", 200, "3/min", ["Normal Device", "Safe"], generate_user_agent()),
        lambda: generate_log_line(ts, "sensor_upload", generate_ip(), "Private IP", f"patient_{user_id:03d}", f"raspi_{user_id:03d}", "POST /api/sensor", 200, "15/min", ["Normal Device", "Safe"], generate_user_agent()),
        lambda: generate_log_line(ts, "sensor_upload", generate_ip(), "Private IP", f"patient_{user_id:03d}", f"raspi_{user_id:03d}", "POST /api/sensor", 200, "3/min", ["Normal Device", "Safe"], random.choice(SUSPICIOUS_UAS)),
    ]
    return random.choice(anomaly_types)()

def generate_brute_force_block(ts):
    ip = generate_ip(anomalous=True)
    ua = random.choice(SUSPICIOUS_UAS)
    logs = []
    for i in range(10):
        rate = f"{random.randint(10, 50)}/min"
        status = 200 if i < 5 else 429
        logs.append(generate_log_line((ts + datetime.timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S,%f")[:-3], "login_attempt", ip, "Unknown", "-", "-", "POST /login", status, rate, ["Login Failed"], ua))
    return logs

def generate_block(is_anomaly, user_id, ts):
    logs = []
    if not is_anomaly:
        for _ in range(10):
            logs.append(generate_normal_log(user_id, ts.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]))
            ts += datetime.timedelta(seconds=random.randint(1, 3))
    else:
        if random.random() < 0.3:
            logs = generate_brute_force_block(ts)
        else:
            num_anomalies = random.randint(8, 10)
            for _ in range(10):
                log = generate_anomaly_log(user_id, ts.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]) if num_anomalies > 0 else generate_normal_log(user_id, ts.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3])
                logs.append(log)
                ts += datetime.timedelta(seconds=random.randint(1, 3))
                num_anomalies -= 1
    return logs

# Generate file
with open("iomt_logs.log", "w") as f:
    ts = datetime.datetime.now()
    for _ in range(20000):  # 200 blocks = 2000 logs
        is_anomaly = random.random() < 0.3
        user_id = random.randint(1, 50)
        block = generate_block(is_anomaly, user_id, ts)
        for log in block:
            f.write(log + "\n")
        ts += datetime.timedelta(seconds=random.randint(10, 20))

print("✅ Log file 'iomt_logs.log' generated!")
