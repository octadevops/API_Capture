#!/usr/bin/env python3
"""
Train / fine-tune FinBERT on CSE data for Streamlit 'trained model' analysis.

- Input: api_captures/_live.json or api_captures/*.json (news + pdf text)
- Labels derived from lexicon or existing sentiment; for demo we use weak-supervision
- Output: ./models/cse_finbert (HF save_pretrained) — loaded by TrainedCSEAnalyzer at priority 1

Usage:
  python models/train.py --data api_captures/_live.json --model ProsusAI/finbert --epochs 3 --output models/cse_finbert
  # Then set env TRAINED_MODEL_PATH=models/cse_finbert and redeploy Streamlit

On Streamlit Cloud, run once locally and commit the ./models/cse_finbert folder (or push to HF Hub).
"""
import argparse
import json
import os
import random
import re
from pathlib import Path

def load_texts(data_path: str):
    p = Path(data_path)
    if p.is_dir():
        files = sorted(p.glob("api_capture_*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
        if not files:
            raise FileNotFoundError(f"No captures in {data_path}")
        data_path = str(files[0])
    with open(data_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    texts = []
    for n in data.get("news", {}).values():
        t = (n.get("title","") + ". " + n.get("text",""))[:512]
        lbl = n.get("sentiment", {}).get("label", "Neutral")
        if t.strip():
            texts.append((t, lbl))
    for pdf in data.get("pdfs", {}).values():
        t = (pdf.get("title","") + ". " + pdf.get("text_preview",""))[:512]
        lbl = pdf.get("sentiment", {}).get("label", "Neutral")
        if t.strip() and len(t) > 40:
            texts.append((t, lbl))
    return texts

LABEL2ID = {"Negative": 0, "Neutral": 1, "Positive": 2}
ID2LABEL = {v: k for k, v in LABEL2ID.items()}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="api_captures/_live.json", help="JSON capture or dir")
    ap.add_argument("--model", default="ProsusAI/finbert", help="HF base model")
    ap.add_argument("--output", default="models/cse_finbert")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--batch", type=int, default=8)
    args = ap.parse_args()

    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
        from datasets import Dataset
        import torch
    except ImportError as e:
        print(f"[!] Missing training deps: {e}\n    pip install transformers datasets torch scikit-learn")
        return 1

    texts = load_texts(args.data)
    if len(texts) < 20:
        print(f"[!] Not enough samples ({len(texts)}). Need >=20. Run capture first.")
        return 1
    print(f"[*] Loaded {len(texts)} samples from {args.data}")
    random.shuffle(texts)
    split = int(len(texts)*0.9)
    train_raw, eval_raw = texts[:split], texts[split:]
    print(f"[*] Train {len(train_raw)} / Eval {len(eval_raw)}")

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    def tok_fn(batch):
        return tokenizer(batch["text"], truncation=True, padding="max_length", max_length=128)
    import datasets
    train_ds = datasets.Dataset.from_dict({"text": [t for t,_ in train_raw], "label": [LABEL2ID[l] for _,l in train_raw]})
    eval_ds = datasets.Dataset.from_dict({"text": [t for t,_ in eval_raw], "label": [LABEL2ID[l] for _,l in eval_raw]})
    train_ds = train_ds.map(tok_fn, batched=True)
    eval_ds = eval_ds.map(tok_fn, batched=True)
    train_ds.set_format(type="torch", columns=["input_ids","attention_mask","label"])
    eval_ds.set_format(type="torch", columns=["input_ids","attention_mask","label"])

    model = AutoModelForSequenceClassification.from_pretrained(args.model, num_labels=3, id2label=ID2LABEL, label2id=LABEL2ID)

    training_args = TrainingArguments(
        output_dir=args.output,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=args.batch,
        learning_rate=args.lr,
        weight_decay=0.01,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        logging_steps=10,
        load_best_model_at_end=True,
        metric_for_best_model="accuracy",
    )
    def compute_metrics(pred):
        import numpy as np
        from sklearn.metrics import accuracy_score, f1_score
        labels = pred.label_ids
        preds = np.argmax(pred.predictions, axis=1)
        return {"accuracy": accuracy_score(labels, preds), "f1": f1_score(labels, preds, average="weighted")}

    trainer = Trainer(model=model, args=training_args, train_dataset=train_ds, eval_dataset=eval_ds, tokenizer=tokenizer, compute_metrics=compute_metrics)
    trainer.train()
    trainer.save_model(args.output)
    tokenizer.save_pretrained(args.output)
    # save info
    with open(os.path.join(args.output, "training_info.json"), "w") as f:
        json.dump({"base": args.model, "samples": len(texts), "epochs": args.epochs, "label2id": LABEL2ID}, f, indent=2)
    print(f"[+] Saved fine-tuned model to {args.output}")
    print(f"[+] Set TRAINED_MODEL_PATH={args.output} for inference")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
