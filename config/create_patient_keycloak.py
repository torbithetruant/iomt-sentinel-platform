import requests
import random
import time

KEYCLOAK_URL = "http://localhost:8080"
REALM = "iot_realm"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
CLIENT_ID = "admin-cli"

FIRST_NAMES = ["Liam", "Emma", "Noah", "Olivia", "Ava", "Ethan", "Sophia", "Lucas", "Mia", "Amelia", "Leo", "Julia"]
LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Andrews", "Miller", "Martin", "Lee"]

# Get admin token
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

def get_user_id(username, headers):
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users?username={username}"
    for attempt in range(3):  # retry up to 3 times
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            users = response.json()
            if users:
                return users[0]["id"]
        time.sleep(1)
    return None

# Get patient role
def get_patient_role(token):
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/roles/patient"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    return r.json()

# Create users
def create_users(token, role_obj):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    for i in range(1, 4):
        username = f"patient_{str(i).zfill(3)}"
        first_name = random.choice(FIRST_NAMES)
        last_name = random.choice(LAST_NAMES)
        email = f"{username}@medsim.io"

        user_data = {
            "username": username,
            "enabled": True,
            "email": email,
            "emailVerified": True,
            "firstName": first_name,
            "lastName": last_name,
            "credentials": [{
                "type": "password",
                "value": "test123",
                "temporary": False
            }]
        }

        # Create user
        r = requests.post(f"{KEYCLOAK_URL}/admin/realms/{REALM}/users", json=user_data, headers=headers)
        if r.status_code == 201:
            print(f"Created {username} ({email}) - {first_name} {last_name}")
        elif r.status_code == 409:
            print(f"{username} already exists")
        else:
            print(f"Error creating {username}: {r.status_code} {r.text}")
            continue

        # Get user ID
        user_id = get_user_id(username, headers)
        if not user_id:
            print(f"Failed to retrieve ID for {username}")
            continue

        # Assign patient role
        role_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm"
        r = requests.post(role_url, json=[role_obj], headers=headers)
        if r.status_code == 204:
            print(f"Role assigned to {username}")
        else:
            print(f"Error assigning role to {username}: {r.status_code} {r.text}")

# === RUN ===
if __name__ == "__main__":
    token = get_admin_token()
    role = get_patient_role(token)
    create_users(token, role)
