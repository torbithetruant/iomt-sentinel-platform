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

SERVER_URL = "https://your_server_ip"
DEVICE_ID = "raspi_001"
TOKEN = "eyJ..."  # JWT
BUFFER = []
ANOMALY_THRESHOLD = 0.05

model = keras.models.load_model("autoencoder_model.h5")
scaler = joblib.load("scaler.pkl")

# Hash + Signature
def sign_gradients(gradients, private_key):
    g_bytes = json.dumps(gradients).encode()
    g_hash = hashlib.sha256(g_bytes).digest()
    h = SHA256.new(g_hash)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature.hex()

def fl_loop():
    while True:
        # Télécharger le modèle global
        resp = requests.get(f"{SERVER_URL}/api/fl-model", headers={"Authorization": f"Bearer {TOKEN}"}, verify=False)
        if resp.status_code == 200:
            weights = resp.json()["weights"]
            model.set_weights([np.array(w) for w in weights])
            print("[FL] Modèle global mis à jour")

        # Fine-tuning sur données locales (déjà normalisées)
        if len(BUFFER) >= 50:
            X_local = np.array(BUFFER)
            model.fit(X_local, X_local, epochs=3, batch_size=16, verbose=0)
            print("[FL] Fine-tuning local terminé")

            # Extraire les poids et envoyer au serveur
            flat_weights = np.concatenate([w.flatten() for w in model.get_weights()]).tolist()
            payload = {"device_id": DEVICE_ID, "gradients": flat_weights, "signature": "dummy_signature"}
            requests.post(f"{SERVER_URL}/api/fl-update", json=payload, headers={"Authorization": f"Bearer {TOKEN}"}, verify=False)
            print("[FL] Update envoyé au serveur")

        time.sleep(600)  # 10 min
