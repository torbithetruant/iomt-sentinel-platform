import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_selection import mutual_info_classif
from sqlalchemy.orm import Session
from models import SessionLocal, SensorRecord, SystemStatus
import pandas as pd
import joblib
import os
import matplotlib.pyplot as plt

# Fonction utilitaire pour l'affichage des métriques
def print_metrics(y_true, y_pred, y_proba=None):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)

    print(f"Accuracy  : {acc:.4f}")
    print(f"Precision : {prec:.4f}")
    print(f"Recall    : {rec:.4f}")
    print(f"F1-Score  : {f1:.4f}")

    if y_proba is not None:
        try:
            auc = roc_auc_score(y_true, y_proba)
            print(f"AUC-ROC   : {auc:.4f}")
        except:
            print("AUC-ROC   : non calculable (probas manquantes ou classes déséquilibrées)")

# Fonction pour calculer l'entropie d'une variable cible (label)
def calculate_entropy(y):
    class_counts = np.bincount(y.astype(int))
    probabilities = class_counts / len(y)
    entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0])
    return entropy

# Fonction pour calculer l'entropie conditionnelle H(Y|X)
def conditional_entropy(y, x):
    entropy = 0
    values, counts = np.unique(x, return_counts=True)
    total = len(x)
    for value, count in zip(values, counts):
        y_sub = y[x == value]
        class_counts = np.bincount(y_sub.astype(int), minlength=len(np.unique(y)))
        probabilities = class_counts / len(y_sub)
        cond_entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0])
        entropy += (count / total) * cond_entropy
    return entropy

# Fonction pour calculer l'information mutuelle I(X;Y)
def information_gain(y, x):
    return calculate_entropy(y) - conditional_entropy(y, x)

# === MODÈLE DE SANTÉ ===
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
        "ecg_summary": r.ecg_summary,
        "label": r.label
    } for r in records])

    # Sauvegarder les données brutes
    os.makedirs("../datasets", exist_ok=True)
    data.to_csv("../datasets/sensor_data.csv", index=False)

    cat_cols = ['device_id', 'timestamp', 'ecg_summary']
    num_cols = ['heart_rate', 'spo2', 'temperature', 'systolic_bp', 'diastolic_bp', 'respiration_rate', 'glucose_level']

    # Encodage des colonnes catégorielles
    le_dict = {col: LabelEncoder().fit(data[col]) for col in cat_cols}
    for col, le in le_dict.items():
        data[col] = le.transform(data[col])

    X = data[cat_cols + num_cols]
    y = data["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] if len(model.classes_) == 2 else None

    print("\n📊 Métriques du modèle santé :")
    print_metrics(y_test, y_pred, y_proba)

    # === Analyse des Features ===

    # 1. Gain d'information (Information Gain)
    info_gains = {}
    for col in X.columns:
        ig = information_gain(y, X[col])
        info_gains[col] = ig

    info_gain_df = pd.DataFrame.from_dict(info_gains, orient='index', columns=['Information Gain'])
    info_gain_df = info_gain_df.sort_values(by='Information Gain', ascending=False)

    print("\n🔍 Information Gain (Gain d'information) :")
    print(info_gain_df)

    # 2. Feature Importance via Random Forest
    feat_importances = pd.Series(model.feature_importances_, index=X.columns)
    feat_importances = feat_importances.sort_values(ascending=False)

    print("\n🌳 Feature Importance (Random Forest) :")
    print(feat_importances)

    # 3. Mutual Information (scikit-learn)
    mi = mutual_info_classif(X, y)
    mi_series = pd.Series(mi, index=X.columns, name="Mutual Information")
    mi_series = mi_series.sort_values(ascending=False)

    print("\n🧮 Mutual Information (scikit-learn) :")
    print(mi_series)

    # === Affichage graphique ===
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))

    info_gain_df.plot(kind='barh', ax=axes[0], title="Information Gain", color='skyblue')
    feat_importances.plot(kind='barh', ax=axes[1], title="Feature Importance (RF)", color='salmon')
    mi_series.plot(kind='barh', ax=axes[2], title="Mutual Info Classif", color='lightgreen')

    plt.tight_layout()
    plt.show()

    joblib.dump(model, "../models/rf_health.pkl")
    print(f"✅ Modèle santé entraîné — {len(data)} entrées, anomalies : {y.sum()}")

if __name__ == "__main__":
    train_health_model()