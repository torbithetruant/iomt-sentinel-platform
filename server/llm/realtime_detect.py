from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import pandas as pd
import time
from log_utils import parse_last_logs_from_raw_file, build_context_from_logs

# Take the fine-tuned model path
model_path = "./tinybert-logs"

# Tokenizer and model
# Note: You can use any model from Hugging Face Model Hub
tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForSequenceClassification.from_pretrained(model_path)
model.eval().cuda()  # Pour ton GPU

# Prediction function
# Note: This function takes a batch of logs and returns the predictions and probabilities
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
        # Read the last 'chunk_size' logs from the file
        block_logs = parse_last_logs_from_raw_file(file_path, block_size=chunk_size)
        if not block_logs:
            print("⏳ Aucun nouveau log détecté.")
            time.sleep(delay)
            continue

        # Build the context from the logs
        # Note: You can modify this function to build the context as needed
        context = build_context_from_logs(block_logs)

        # Check if the context has already been seen
        # Note: This is a simple hash check, you can use a more sophisticated method if needed
        context_hash = hash(context)
        if context_hash in seen_contexts:
            time.sleep(delay)
            continue
        seen_contexts.add(context_hash)

        # Detect anomalies
        # Note: You can modify the chunk size and delay as needed
        preds, scores = detect_anomalies([context])  # batch = 1

        if preds[0] == 1:
            print(f"\nAnomalie détectée dans le bloc de {chunk_size} logs !")
            print(f"Contexte :\n{context}")
            print(f"Score d'anomalie : {scores[0]:.2f}")

            respond_to_threat(context, scores[0], "Anomalie détectée dans les logs IoMT.")

        else:
            print(f"Aucun comportement suspect détecté. (Score : {scores[0]:.2f})")

        time.sleep(delay)

def respond_to_threat(context, score, response):
    # A faire : envoyer une alerte, enregistrer dans une base de données, etc.
    return None

# Lancer le monitoring
stream_log_file("../logs/for_bert.csv", chunk_size=10, delay=10)
