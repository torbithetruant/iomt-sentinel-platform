# log.py
import logging
from logging.handlers import RotatingFileHandler
import os

# 📁 Dossier des logs
os.makedirs("logs", exist_ok=True)

# 📄 Fichier de log
LOG_FILE = "logs/server.log"
LOG_FORMAT = "[%(asctime)s] %(levelname)s [%(name)s] %(message)s"

# 📦 Niveau de log configurable (par défaut : INFO)
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format=LOG_FORMAT,
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("iomt")