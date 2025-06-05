import time
import numpy as np
import requests
import json
import os

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

from tensorflow import keras
import joblib
import hashlib
from Cryptodome.Signature import pkcs1_15
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256

# === CONFIGURATION ===
SERVER_URL = "https://localhost:8000"
BUFFER = []
ANOMALY_THRESHOLD = 1.74  # Seuil ajusté selon évaluation

# === Modèle et scaler ===
model = keras.models.load_model("autoencoder_model.h5")
scaler = joblib.load("scaler.pkl")

# === Clé privée pour signature ===
PRIVATE_KEY_PATH = "private_key.pem"
with open(PRIVATE_KEY_PATH, "rb") as f:
    PRIVATE_KEY = RSA.import_key(f.read())

# === Hash + Signature des gradients + ZKP ===
def sign_gradients_and_zkp(gradients, private_key):
    g_bytes = json.dumps(gradients).encode()
    g_hash = hashlib.sha256(g_bytes).digest()
    hash_hex = g_hash.hex()
    
    h = SHA256.new(g_hash)
    signature = pkcs1_15.new(private_key).sign(h).hex()
    
    # ZKP simplifié : challenge aléatoire + signature
    challenge = str(np.random.randint(100000, 999999))
    zkp_proof = hashlib.sha256((hash_hex + challenge).encode()).hexdigest()
    
    return hash_hex, signature, zkp_proof, challenge


# === Federated Learning Loop ===
def fl_loop(device_id, token):
    while True:
        # Télécharger le modèle global
        resp = requests.get(f"{SERVER_URL}/api/fl-model", headers={"Authorization": f"Bearer {token}"}, verify=False)
        if resp.status_code == 200:
            weights = resp.json()["weights"]
            model.set_weights([np.array(w) for w in weights])
            print("[FL] Modèle global mis à jour")

        # Fine-tuning sur données locales
        if len(BUFFER) >= 50:
            X_local = np.array(BUFFER)
            model.fit(X_local, X_local, epochs=3, batch_size=16, verbose=0)
            print("[FL] Fine-tuning local terminé")

            # Signature des gradients
            flat_weights = np.concatenate([w.flatten() for w in model.get_weights()]).tolist()
            hash_grad, signature, zkp_proof, challenge = sign_gradients_and_zkp(flat_weights, PRIVATE_KEY)

            payload = {
                "device_id": device_id,
                "gradients": flat_weights,
                "hash_gradients": hash_grad,
                "signature": signature,
                "zkp_proof": zkp_proof,
                "challenge": challenge
            }
            requests.post(f"{SERVER_URL}/api/fl-update", json=payload, headers={"Authorization": f"Bearer {token}"}, verify=False)
            print("[FL] Update envoyé au serveur avec signature et ZKP")

        time.sleep(600)  # 10 min
