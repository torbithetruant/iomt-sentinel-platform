from collections import defaultdict, deque
import time

# This script tracks the rate of specific user actions on a web server.
# Global memory (simple)
request_history = defaultdict(lambda: deque(maxlen=1000))

# Cleanup older than 60s
def get_action_rate(user: str, action: str, window: int = 60) -> int:
    now = time.time()
    key = f"{user}:{action}"
    history = request_history[key]

    # Remove old entries
    while history and now - history[0] > window:
        history.popleft()

    # Return number of recent actions
    return len(history)

def get_user_action_and_rate(username: str, path: str) -> tuple:
    # Définis l'action
    if path.startswith("/login"):
        action = "login_attempt"
    elif path.startswith("/api/sensor"):
        action = "sensor_upload"
    elif path.startswith("/api/system-status") or path.startswith("/api/system-request"):
        action = "system_check"
    elif path.startswith("/dashboard"):
        action = "dashboard_access"
    else:
        action = "other"

    # Mémorise l'action
    key = f"{username}:{action}"
    request_history[key].append(time.time())

    # Taux par minute
    rate = get_action_rate(username, action)

    return (action, rate)