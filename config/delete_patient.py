import requests

KEYCLOAK_URL = "http://localhost:8080"
REALM = "iot_realm"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
CLIENT_ID = "admin-cli"

# Authentification admin
def get_admin_token():
    url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "username": ADMIN_USER,
        "password": ADMIN_PASS
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(url, data=data, headers=headers)
    r.raise_for_status()
    return r.json()["access_token"]

# Delete patient users
def delete_patient_users(token):
    headers = {"Authorization": f"Bearer {token}"}
    base_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"

    # Take all users
    # Note: The max limit is 1000, but we can use pagination to get all users
    r = requests.get(f"{base_url}?max=2000", headers=headers)
    r.raise_for_status()
    users = r.json()

    deleted = 0
    for user in users:
        if user.get("username", "").startswith("patient_"):
            user_id = user["id"]
            username = user["username"]
            delete_url = f"{base_url}/{user_id}"
            resp = requests.delete(delete_url, headers=headers)
            if resp.status_code == 204:
                print(f"🗑️  Supprimé : {username}")
                deleted += 1
            else:
                print(f"Error deletion {username}: {resp.status_code} {resp.text}")

    print(f"\n✅ {deleted} users 'patient_' deleted.")

# === MAIN ===
if __name__ == "__main__":
    token = get_admin_token()
    delete_patient_users(token)
