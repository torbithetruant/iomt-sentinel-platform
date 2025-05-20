import requests
import asyncio
from database.models import AsyncSessionLocal, UserAccount
from sqlalchemy import delete

# === CONFIGURATION ===
KEYCLOAK_URL = "http://localhost:8080"
REALM = "iot_realm"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
CLIENT_ID = "admin-cli"

VALID_ROLES = ["patient", "doctor", "it_admin"]

# === Get admin token ===
def get_admin_token():
    url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "username": ADMIN_USER,
        "password": ADMIN_PASS
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(url, data=data, headers=headers)
    response.raise_for_status()
    return response.json()["access_token"]

# === Get all users in the realm ===
def get_all_users(token):
    headers = {"Authorization": f"Bearer {token}"}
    all_users = []
    first = 0
    max_users = 100

    while True:
        url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users?max={max_users}&first={first}"
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            print(f"Failed to get all users : {response.text}")
            break

        users = response.json()
        if not users:
            break

        all_users.extend(users)
        print(f"Getting {len(users)} users (total : {len(all_users)})")
        first += max_users

    return all_users

# === Get roles for a user ===
def get_user_roles(token, user_id):
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Impossible to get roles for user_id={user_id}: {response.text}")
        return []

# === Sync users to async DB ===
async def sync_users():
    token = get_admin_token()
    print("✔️ Admin token acquired")

    users = get_all_users(token)
    print(f"🔍 {len(users)} users found in realm '{REALM}'")

    async with AsyncSessionLocal() as session:
        await session.execute(delete(UserAccount))

        for user in users:
            user_id = user["id"]
            username = user["username"]
            email = user.get("email", None)

            roles = get_user_roles(token, user_id)
            for role in roles:
                if role["name"] not in VALID_ROLES:
                    print(f"⚠️  Invalid role for {username}: {role['name']}")
                    continue
                role_name = role["name"]
                db_user = UserAccount(username=username, email=email, role=role_name)
                session.add(db_user)
                print(f"👤 {username} → role : {role_name}")

        await session.commit()
    print("✅ All users synced with the async PostgreSQL database.")

if __name__ == "__main__":
    asyncio.run(sync_users())