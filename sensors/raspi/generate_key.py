# generate_keys.py
from Cryptodome.PublicKey import RSA

DEVICE_ID = "raspi_001"           # adjust per device
KEY_SIZE  = 2048                  # 3072 or 4096 for higher security
PRIV_FILE = "private_key.pem"
PUB_FILE  = f"{DEVICE_ID}_pub.pem"

# 1. generate key pair
key = RSA.generate(KEY_SIZE)

# 2. export / write private key (PKCS#8, PEM)
with open(PRIV_FILE, "wb") as f:
    f.write(key.export_key(format="PEM", pkcs=8))

# 3. export / write public key
with open(PUB_FILE, "wb") as f:
    f.write(key.publickey().export_key(format="PEM"))

print(f"✅  Keys generated:\n  • {PRIV_FILE}\n  • {PUB_FILE}")
