import torch
import psutil
import os
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from fastapi import FastAPI
from pydantic import BaseModel

# === Model Loading ===
model_path = "llm/bert-supervisor"
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"🚀 LLM Server running on device: {device}")

tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForSequenceClassification.from_pretrained(model_path)
model.eval().to(device)

# === FastAPI App ===
app = FastAPI()

# === Pydantic Model ===
class ContextRequest(BaseModel):
    context: str

def monitor_resources():
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    print(f"🧠 Memory: {mem_info.rss / (1024*1024):.2f} MB")
    print(f"⚙️ CPU: {process.cpu_percent()}%")


# === Inference Endpoint ===
@app.post("/infer")
async def infer(request: ContextRequest):
    context_text = request.context

    inputs = tokenizer(context_text, return_tensors="pt", padding=True, truncation=True, max_length=128)
    inputs = {k: v.to(device) for k, v in inputs.items()}
    
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)
        pred = torch.argmax(probs, dim=1).item()
        score = probs[0, 1].item()
    
    return {
        "prediction": pred,
        "score": score
    }
