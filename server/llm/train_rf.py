import re
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from log_utils import extract_features_from_line_detailed, encode_features_dict_to_vector

# === Step 1: Load and parse logs ===

def load_labeled_logs(file_path):
    logs = []
    labels = []
    with open(file_path, "r") as f:
        for line in f:
            match = re.match(r"#LABEL:(\d+)(.+)", line)
            if match:
                label = int(match.group(1))
                log = match.group(2).strip()
                labels.append(label)
                logs.append(log)
    return logs, labels

log_file = "datasets/iomt_realistic.log"  # Update to your log path
logs, labels = load_labeled_logs(log_file)

# === Step 2: Extract features ===

X_dicts = [extract_features_from_line_detailed(log) for log in logs]
X = [encode_features_dict_to_vector(f) for f in X_dicts]
X = np.array(X)
y = np.array(labels)

# === Step 3: Train/test split and training ===

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# === Step 4: Evaluate ===

y_pred = rf_model.predict(X_test)
print(classification_report(y_test, y_pred))

# === Step 5: Save model ===

joblib.dump(rf_model, "random_forest_detector.pkl")
print("✅ Model saved to random_forest_detector.pkl")
