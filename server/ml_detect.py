from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sqlalchemy.orm import Session
from models import SessionLocal, SensorRecord, SystemStatus
import pandas as pd
import joblib

def train_health_model():
    db: Session = SessionLocal()
    records = db.query(SensorRecord).all()
    db.close()

    if not records:
        print("⚠️ Aucun enregistrement SensorRecord")
        return

    data = pd.DataFrame([{
        "device_id": r.device_id,
        "timestamp": r.timestamp,
        "heart_rate": r.heart_rate,
        "spo2": r.spo2,
        "temperature": r.temperature,
        "systolic_bp": r.systolic_bp,
        "diastolic_bp": r.diastolic_bp,
        "respiration_rate": r.respiration_rate,
        "glucose_level": r.glucose_level,
        "ecg_summary": r.ecg_summary
    } for r in records])

    def is_anomalous(row):
        return (
            row["heart_rate"] > 100 or row["heart_rate"] < 60 or
            row["ecg_summary"] == "Anomalous pattern" or
            row["temperature"] > 38.0 or row["temperature"] < 36.0 or
            row["spo2"] < 95.0 or row["spo2"] > 99.5 or
            row["systolic_bp"] > 140 or row["systolic_bp"] < 110 or
            row["diastolic_bp"] < 70 or row["diastolic_bp"] > 90 or
            row["respiration_rate"] > 20 or row["respiration_rate"] < 12 or
            row["glucose_level"] > 7.0 or row["glucose_level"] < 4.5
        )

    data["label"] = data.apply(is_anomalous, axis=1)

    # Enregistrer en csv sous ../datasets/
    data.to_csv("../datasets/sensor_data.csv", index=False)

    cat_cols = ['device_id', 'timestamp', 'ecg_summary']
    num_cols = ['heart_rate', 'spo2', 'temperature', 'systolic_bp', 'diastolic_bp', 'respiration_rate', 'glucose_level']

    # Encodage
    le_dict = {col: LabelEncoder().fit(data[col]) for col in cat_cols}
    for col, le in le_dict.items():
        data[col] = le.transform(data[col])

    X = data[cat_cols + num_cols]
    y = data["label"]

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    joblib.dump(model, "../models/rf_health.pkl")
    print(f"✅ Modèle santé entraîné — {len(data)} entrées, anomalies : {y.sum()}")

def train_system_model():
    db: Session = SessionLocal()
    records = db.query(SystemStatus).all()
    db.close()

    if not records:
        print("⚠️ Aucun enregistrement SystemStatus")
        return

    data = pd.DataFrame([{
        "device_id": r.device_id,
        "timestamp": r.timestamp,
        "sensor_type": r.sensor_type,
        "ip_address": r.ip_address,
        "firmware_version": r.firmware_version,
        "data_frequency_seconds": r.data_frequency_seconds,
        "disk_free_percent": r.disk_free_percent,
        "update_required": int(r.update_required),
        "checksum_valid": int(r.checksum_valid),
        "status": r.status
    } for r in records])

    def is_system_anomaly(row):
        return (
            row["disk_free_percent"] < 10 or
            row["update_required"] == 1 or
            row["checksum_valid"] == 0 or
            row["status"] != 1
        )

    data["label"] = data.apply(is_system_anomaly, axis=1)

    # Enregistrer en csv sous ../datasets/
    data.to_csv("../datasets/system_status.csv", index=False)

    cat_cols = ['device_id', 'timestamp', 'sensor_type', 'ip_address', 'firmware_version']
    num_cols = ['data_frequency_seconds', 'disk_free_percent', 'update_required', 'checksum_valid', 'status']

    # Encodage
    le_dict = {col: LabelEncoder().fit(data[col]) for col in cat_cols}
    for col, le in le_dict.items():
        data[col] = le.transform(data[col])

    X = data[cat_cols + num_cols]
    y = data["label"]

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    joblib.dump(model, "../models/rf_system.pkl")
    print(f"✅ Modèle système entraîné — {len(data)} entrées, anomalies : {y.sum()}")

if __name__ == "__main__":
    train_health_model()
    train_system_model()
