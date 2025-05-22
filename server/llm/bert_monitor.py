# llm_monitor.py
import time
import joblib
import asyncio
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from log_utils import parse_last_logs_from_raw_file, build_context_from_logs, extract_features_from_line_detailed, encode_features_dict_to_vector
from collections import deque

log_buffer = deque(maxlen=100)  # Holds last 100 logs (adjustable)

model_path = "llm/tinybert-logs"
rf_model_path = "llm/random_forest_detector.pkl"

tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForSequenceClassification.from_pretrained(model_path)
model.eval().cuda()

seen_contexts = set()

# Queue for detected incidents
incident_queue = asyncio.Queue()

def detect_anomalies(logs_batch):
    inputs = tokenizer(logs_batch, return_tensors="pt", padding=True, truncation=True, max_length=128)
    inputs = {k: v.cuda() for k, v in inputs.items()}
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)
        preds = torch.argmax(probs, dim=1).cpu().tolist()
    return preds, probs[:, 1].cpu().tolist()

async def monitor_logs_with_llm(file_path, chunk_size=10, delay=10, X_BEFORE=5, Y_AFTER=5):
    global rf_model
    rf_model = joblib.load(rf_model_path)

    while True:
        blocks = parse_last_logs_from_raw_file(file_path, block_size=chunk_size)
        if not blocks:
            await asyncio.sleep(delay)
            continue

        for block in blocks:
            lines = block.strip().split("\n")
            log_buffer.extend(lines)

            # === Step 1: Feature extraction line by line ===
            feature_vecs = []
            for line in lines:
                f_dict = extract_features_from_line_detailed(line)
                f_vec = encode_features_dict_to_vector(f_dict)
                feature_vecs.append(f_vec)

            if not feature_vecs:
                continue

            X_tensor = torch.tensor(feature_vecs).float().cuda()
            X_mean = torch.mean(X_tensor, dim=0).unsqueeze(0).cpu().numpy()

            # === Step 2: RF Detection ===
            rf_pred = rf_model.predict(X_mean)[0]
            rf_score = rf_model.predict_proba(X_mean)[0][1]

            if rf_pred == 1:
                # === Step 3: Extract extended context ===
                total_logs = list(log_buffer)
                idx = len(total_logs) - len(lines)  # Start of current block in buffer
                start = max(0, idx - X_BEFORE)
                end = min(len(total_logs), idx + len(lines) + Y_AFTER)

                extended_context_logs = total_logs[start:end]
                extended_context = build_context_from_logs(extended_context_logs)

                # Deduplication
                context_hash = hash(extended_context)
                if context_hash in seen_contexts:
                    continue
                seen_contexts.add(context_hash)

                # === Step 4: LLM validation ===
                preds, scores = detect_anomalies([extended_context])
                if preds[0] == 1:
                    await incident_queue.put((extended_context, scores[0]))

        await asyncio.sleep(delay)

async def handle_detected_threat(context, score):
    print(f"Threat detected with score {score:.2f}: {context}")
    # Here you can add your incident response logic, such as sending alerts or taking action.


async def incident_responder():
    while True:
        context, score = await incident_queue.get()
        await handle_detected_threat(context, score)
