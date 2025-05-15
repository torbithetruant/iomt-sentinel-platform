import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
from datasets import Dataset
from sklearn.model_selection import train_test_split
import pandas as pd
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# Vérifie si CUDA est dispo
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("Using device:", device)

# 🔹 1. Chargement des données (exemple simplifié)
# Le CSV doit avoir deux colonnes : 'text' (log) et 'label' (0 normal, 1 attaque)
df = pd.read_csv("logs/processed_logs.csv")  # remplace par ton chemin

# 🔹 2. Division en train/test
train_texts, test_texts, train_labels, test_labels = train_test_split(
    df['context'], df['label'], test_size=0.2, random_state=42
)

# 🔹 3. Chargement du tokenizer
model_name = "prajjwal1/bert-tiny"  # ou "google/bert_uncased_L-4_H-512_A-8" pour un TinyBERT plus costaud
tokenizer = AutoTokenizer.from_pretrained(model_name)

# 🔹 4. Tokenization
def tokenize(batch):
    return tokenizer(batch["context"], padding="max_length", truncation=True, max_length=128)

train_dataset = Dataset.from_dict({"context": train_texts.tolist(), "label": train_labels.tolist()})
test_dataset = Dataset.from_dict({"context": test_texts.tolist(), "label": test_labels.tolist()})

train_dataset = train_dataset.map(tokenize, batched=True)
test_dataset = test_dataset.map(tokenize, batched=True)

train_dataset.set_format("torch", columns=["input_ids", "attention_mask", "label"])
test_dataset.set_format("torch", columns=["input_ids", "attention_mask", "label"])

# 🔹 5. Chargement du modèle
model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2).to(device)

# 🔹 6. Définition des métriques
def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = torch.argmax(torch.tensor(logits), dim=1)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average='binary')
    acc = accuracy_score(labels, preds)
    return {"accuracy": acc, "f1": f1, "precision": precision, "recall": recall}

# 🔹 7. Entraînement
training_args = TrainingArguments(
    output_dir="./tinybert-logs",
    eva_strategy="epoch",
    save_strategy="epoch",
    learning_rate=2e-5,
    per_device_train_batch_size=32,
    per_device_eval_batch_size=64,
    num_train_epochs=5,
    weight_decay=0.01,
    logging_dir="./logs",
    load_best_model_at_end=True,
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset,
    tokenizer=tokenizer,
    compute_metrics=compute_metrics,
)

trainer.train()
trainer.save_model("tinybert-logs")