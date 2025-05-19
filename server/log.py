# log.py
import logging
from logging.handlers import RotatingFileHandler
import os

# Make sure the logs directory exists
os.makedirs("logs", exist_ok=True)

# Path to the log file and log format
# Note: You can change the log file path and format as needed
LOG_FILE = "logs/server.log"
LOG_FORMAT = "[%(asctime)s] %(levelname)s [%(name)s] %(message)s"

# Set the log level from environment variable or default to INFO
# Note: You can change the default log level as needed
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format=LOG_FORMAT,
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5),
        logging.StreamHandler()
    ]
)

# Create a logger instance
logger = logging.getLogger("iomt")