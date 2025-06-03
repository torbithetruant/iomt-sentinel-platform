import threading
import time
import numpy as np
import requests
import json
import tensorflow as tf
from tensorflow import keras
import joblib
import hashlib
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

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

# === Hash + Signature des gradients ===
def sign_gradients(gradients, private_key):
    g_bytes = json.dumps(gradients).encode()
    g_hash = hashlib.sha256(g_bytes).digest()
    h = SHA256.new(g_hash)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature.hex()

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
            signature = sign_gradients(flat_weights, PRIVATE_KEY)

            payload = {
                "device_id": device_id,
                "gradients": flat_weights,
                "signature": signature
            }
            requests.post(f"{SERVER_URL}/api/fl-update", json=payload, headers={"Authorization": f"Bearer {token}"}, verify=False)
            print("[FL] Update envoyé au serveur avec signature")

        time.sleep(600)  # 10 min
