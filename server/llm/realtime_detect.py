from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import pandas as pd
import time
from log_utils import parse_last_logs_from_raw_file, build_context_from_logs

# 🔁 Chemin du modèle fine-tuné
model_path = "./tinybert-logs"

# 🔁 Chargement du tokenizer et modèle fine-tuné
tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForSequenceClassification.from_pretrained(model_path)
model.eval().cuda()  # Pour ton GPU

# 🔁 Fonction de prédiction
def detect_anomalies(logs_batch):
    inputs = tokenizer(logs_batch, return_tensors="pt", padding=True, truncation=True, max_length=128)
    inputs = {k: v.cuda() for k, v in inputs.items()}
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)
        preds = torch.argmax(probs, dim=1).cpu().tolist()
    return preds, probs[:, 1].cpu().tolist()  # 1 = anomalie

def stream_log_file(file_path, chunk_size=10, delay=10):
    seen_contexts = set()

    while True:
        # 🔁 Lire les logs bruts (dernier chunk de taille chunk_size)
        block_logs = parse_last_logs_from_raw_file(file_path, block_size=chunk_size)
        if not block_logs:
            print("⏳ Aucun nouveau log détecté.")
            time.sleep(delay)
            continue

        # 🔁 Construire un contexte textuel
        context = build_context_from_logs(block_logs)

        # 🔁 Éviter de traiter deux fois le même contexte
        context_hash = hash(context)
        if context_hash in seen_contexts:
            time.sleep(delay)
            continue
        seen_contexts.add(context_hash)

        # 🔍 Détection par LLM classique (à remplacer par TinyBERT si nécessaire)
        preds, scores = detect_anomalies([context])  # batch = 1

        if preds[0] == 1:
            print(f"\n🚨 Anomalie détectée dans le bloc de {chunk_size} logs !")
            print(f"📝 Contexte :\n{context}")
            print(f"⚠️ Score d'anomalie : {scores[0]:.2f}")

            respond_to_threat(context, scores[0], "Anomalie détectée dans les logs IoMT.")

        else:
            print(f"✅ Aucun comportement suspect détecté. (Score : {scores[0]:.2f})")

        time.sleep(delay)

def respond_to_threat(context, score, response):
    print("📥 Enregistrement de l'anomalie détectée...")

    with open("alerts/generated_responses.log", "a") as f:
        f.write(f"[Score : {score:.2f}]\n{context}\n---\n{response}\n===\n")

    print("📬 Réponse enregistrée et alerte transmise à l'équipe sécurité.")

# Lancer le monitoring
stream_log_file("../logs/for_bert.csv", chunk_size=10, delay=10)
