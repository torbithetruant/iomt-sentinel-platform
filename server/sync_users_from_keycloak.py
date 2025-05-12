import requests
from models import SessionLocal, UserAccount  # Adapte selon ton modèle

# === CONFIGURATION ===
KEYCLOAK_URL = "http://localhost:8080"
REALM = "iot_realm"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
CLIENT_ID = "admin-cli"

VALID_ROLES = ["patient", "doctor", "it_admin"]  # Liste des rôles valides

# === 1. Obtenir un token admin ===
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

# === 2. Récupérer tous les utilisateurs du realm ===
def get_all_users(token):
    headers = {"Authorization": f"Bearer {token}"}
    all_users = []
    first = 0
    max_users = 100  # Tu peux monter jusqu'à 1000 selon config Keycloak

    while True:
        url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users?max={max_users}&first={first}"
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            print(f"❌ Échec de récupération des utilisateurs : {response.text}")
            break

        users = response.json()
        if not users:
            break

        all_users.extend(users)
        print(f"📄 Récupérés {len(users)} utilisateurs (total : {len(all_users)})")
        first += max_users

    return all_users

# === 3. Récupérer les rôles d'un utilisateur ===
def get_user_roles(token, user_id):
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"❌ Impossible de récupérer les rôles pour user_id={user_id}: {response.text}")
        return []

# === PRINCIPAL ===
if __name__ == "__main__":
    # Connexion à la base de données
    db = SessionLocal()
    db.query(UserAccount).delete()  # Optionnel : nettoyer avant synchro

    # Authentification
    token = get_admin_token()
    print("✅ Token admin obtenu")

    # Récupération des utilisateurs
    users = get_all_users(token)
    print(f"🔍 {len(users)} utilisateurs trouvés dans le realm '{REALM}'")

    for user in users:
        user_id = user["id"]
        username = user["username"]
        email = user.get("email", None)

        roles = get_user_roles(token, user_id)
        for role in roles:
            if role["name"] not in VALID_ROLES:
                print(f"⚠️ Rôle invalide pour {username}: {role['name']}")
                continue
            role_name = role["name"]
            db_user = UserAccount(username=username, email=email, role=role_name)
            db.add(db_user)
            print(f"👤 {username} → rôle : {role_name}")

    db.commit()
    db.close()
    print("✅ Synchronisation terminée : Tous les utilisateurs ont été sauvegardés dans la base")