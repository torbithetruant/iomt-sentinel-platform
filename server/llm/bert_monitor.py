# llm_monitor.py
import time
import asyncio
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from llm.log_utils import parse_last_logs_from_raw_file, build_context_from_logs

model_path = "llm/tinybert-logs"

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

async def monitor_logs_with_llm(file_path, chunk_size=10, delay=10):
    while True:
        block_logs = parse_last_logs_from_raw_file(file_path, block_size=chunk_size)
        if not block_logs:
            await asyncio.sleep(delay)
            continue

        context = build_context_from_logs(block_logs)
        context_hash = hash(context)
        if context_hash in seen_contexts:
            await asyncio.sleep(delay)
            continue
        seen_contexts.add(context_hash)

        preds, scores = detect_anomalies([context])
        if preds[0] == 1:
            await incident_queue.put((context, scores[0]))

        await asyncio.sleep(delay)

async def handle_detected_threat(context, score):
    print(f"Threat detected with score {score:.2f}: {context}")
    # Here you can add your incident response logic, such as sending alerts or taking action.


async def incident_responder():
    while True:
        context, score = await incident_queue.get()
        await handle_detected_threat(context, score)
