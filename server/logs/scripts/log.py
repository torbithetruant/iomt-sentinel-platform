import logging
from logging.handlers import RotatingFileHandler, QueueHandler, QueueListener
from queue import SimpleQueue
import os

# Create log directory if needed
os.makedirs("logs", exist_ok=True)

# Log file paths
APP_LOG_FILE = "logs/server.log"
SQL_LOG_FILE = "logs/sql.log"
DET_LOG_FILE = "logs/anomalies.log"

# Log format
LOG_FORMAT = "[%(asctime)s] %(levelname)s [%(name)s] %(message)s"

# Queue for async-safe logging
log_queue = SimpleQueue()

# === Handlers ===
# App handler
app_handler = RotatingFileHandler(APP_LOG_FILE, maxBytes=1_000_000, backupCount=5)
app_handler.setFormatter(logging.Formatter(LOG_FORMAT))

# SQL handler (separate file)
sql_handler = RotatingFileHandler(SQL_LOG_FILE, maxBytes=1_000_000, backupCount=3)
sql_handler.setFormatter(logging.Formatter(LOG_FORMAT))

det_handler = RotatingFileHandler(DET_LOG_FILE, maxBytes=1_000_000, backupCount=3)
det_handler.setFormatter(logging.Formatter(LOG_FORMAT))

# === Queue Listener ===
listener = QueueListener(log_queue, app_handler)
listener.start()

# === Main App Logger ===
logger = logging.getLogger("iomt")
logger.setLevel(logging.INFO)
logger.addHandler(QueueHandler(log_queue))

# === Silence unwanted logs ===
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
logging.getLogger("sqlalchemy").setLevel(logging.ERROR)
logging.getLogger("asyncpg").setLevel(logging.WARNING)

# Optional: log SQL errors in a dedicated file
sql_logger = logging.getLogger("sqlalchemy.engine")
sql_logger.addHandler(sql_handler)

logging.getLogger("detection").setLevel(logging.INFO)
det_logger = logging.getLogger("detection")
det_logger.addHandler(det_handler)
