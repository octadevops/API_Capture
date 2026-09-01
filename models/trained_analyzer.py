#!/usr/bin/env python3
"""
Trained CSE Analyzer — loads a fine-tuned FinBERT (or fallback) for sentiment.
Priority:
  1) env TRAINED_MODEL_PATH (e.g. ./models/cse_finbert or HF id)
  2) ./models/cse_finbert  (local fine-tuned checkpoint)
  3) ./models/cse_finbert_tone / FinBERT checkpoints
  4) CSE_RECOMMENDED_MODELS['primary_sentiment'] (ProsusAI/finbert)
  5) lexicon fallback (FIN_POSITIVE/FIN_NEGATIVE)

Training script `models/train.py` fine-tunes ProsusAI/finbert on CSE news titles.
On Streamlit Cloud the model is cached via @st.cache_resource; first load downloads from HF.

Usage:
    from models.trained_analyzer import TrainedCSEAnalyzer, get_analyzer
    analyzer = get_analyzer()  # singleton
    result = analyzer.analyze("CSE profits surge, dividend increased")  # {'label','score','engine','model_path'}
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, Optional

# Load .env for keys (local dev); Streamlit Cloud uses secrets.toml
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass

try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    pipeline = None
    TRANSFORMERS_AVAILABLE = False
    AutoTokenizer = None

# Reuse lexicon sets from app without circular import
FIN_POSITIVE = {
    'gain', 'gains', 'gained', 'profit', 'profits', 'profitable', 'earnings', 'beat', 'beats',
    'upbeat', 'growth', 'grow', 'growing', 'rise', 'rises', 'rose', 'rising', 'rally', 'rallying',
    'surge', 'surges', 'surged', 'jump', 'jumps', 'jumped', 'increase', 'increases', 'increased',
    'boost', 'boosts', 'boosted', 'strong', 'stronger', 'strengthen', 'recover', 'recovery',
    'rebound', 'record', 'high', 'higher', 'highest', 'outperform', 'outperformed', 'upgrade',
    'upgraded', 'bullish', 'buy', 'positive', 'good', 'improve', 'improved', 'improvement',
    'dividend', 'dividends', 'expansion', 'expands', 'launch', 'new', 'win', 'wins', 'won',
    'award', 'awarded', 'success', 'successful', 'optimistic', 'outlook', 'momentum', 'resilient',
    'solid', 'robust', 'healthy', 'impressive', 'exceed', 'exceeded', 'above', 'target',
}
FIN_NEGATIVE = {
    'loss', 'losses', 'lost', 'decline', 'declines', 'declined', 'drop', 'drops', 'dropped',
    'fall', 'falls', 'fell', 'falling', 'slump', 'slumps', 'slumped', 'plunge', 'plunges',
    'plunged', 'tumble', 'tumbles', 'tumbled', 'slide', 'slides', 'slid', 'weaken', 'weakened',
    'weak', 'weaker', 'weakness', 'downgrade', 'downgraded', 'sell', 'bearish', 'negative',
    'poor', 'bad', 'worse', 'worst', 'cut', 'cuts', 'slashed', 'miss', 'misses', 'missed',
    'below', 'underperform', 'underperformed', 'risk', 'risks', 'uncertainty', 'concern',
    'concerns', 'worried', 'worry', 'fear', 'fears', 'crisis', 'bankrupt', 'bankruptcy',
    'default', 'defaults', 'debt', 'liability', 'lawsuit', 'fraud', 'penalty', 'penalized',
    'investigation', 'probe', 'shortfall', 'shed', 'sheds', 'erode', 'erodes', 'eroded',
    'pressure', 'pressured', 'struggle', 'struggles', 'struggled', 'stagnant', 'halt', 'halts',
    'halted', 'suspend', 'suspended',
}

CANDIDATE_PATHS = [
    os.environ.get("TRAINED_MODEL_PATH", ""),
    os.environ.get("CSE_MODEL_PATH", ""),
    "models/cse_finbert",
    "models/cse_finbert_tone",
    "models/finbert_cse",
    "ProsusAI/finbert",
]

# Singleton
_ANALYZER_SINGLETON = None

class TrainedCSEAnalyzer:
    """
    Trained model wrapper. `analyze()` returns {'label','score','engine','model_path'}.
    Engine values: 'trained-local' | 'trained-hf' | 'finbert' | 'lexicon'
    """

    def __init__(self, model_path: Optional[str] = None, device: int = -1):
        self.model_path = None
        self.engine = "lexicon"
        self._pipe = None
        self._load_error: Optional[str] = None

        if not TRANSFORMERS_AVAILABLE:
            self._load_error = "transformers not installed"
            return

        # Resolve priority
        if model_path:
            candidates = [model_path] + CANDIDATE_PATHS
        else:
            candidates = CANDIDATE_PATHS

        for cand in candidates:
            if not cand:
                continue
            # local path exists?
            if os.path.isdir(cand) or os.path.isfile(os.path.join(cand, "config.json")):
                try:
                    self._pipe = pipeline("sentiment-analysis", model=cand, tokenizer=cand, device=device, truncation=True)
                    self.model_path = cand
                    self.engine = "trained-local"
                    return
                except Exception as e:
                    self._load_error = f"{cand}: {e}"
                    continue
            else:
                # HF id — try if looks like namespace/model
                if "/" in cand and not os.path.sep in cand.replace("/", "", 1):
                    try:
                        self._pipe = pipeline("sentiment-analysis", model=cand, device=device, truncation=True)
                        self.model_path = cand
                        self.engine = "trained-hf" if "cse" in cand.lower() or "finbert" in cand.lower() else "finbert"
                        return
                    except Exception as e:
                        self._load_error = f"{cand}: {e}"
                        continue
        # last resort: pure lexicon
        self.engine = "lexicon"
        self._load_error = self._load_error or "no model loaded"

    def analyze(self, text: str) -> Dict:
        text = (text or "").strip()
        if len(text) < 12:
            return {"label": "Neutral", "score": 0.5, "engine": self.engine, "model_path": self.model_path}
        # Try transformer
        if self._pipe:
            try:
                # HF FinBERT uses labels positive/negative/neutral
                out = self._pipe(text[:512])[0]
                raw_label = str(out.get("label", "")).lower()
                score = float(out.get("score", 0.5))
                # Normalize
                if "pos" in raw_label:
                    label = "Positive"
                elif "neg" in raw_label:
                    label = "Negative"
                else:
                    label = "Neutral"
                    score = 0.5
                return {"label": label, "score": round(score, 4), "engine": self.engine, "model_path": self.model_path}
            except Exception:
                pass
        # Lexicon fallback
        words = re.findall(r"[a-z']+", text.lower())
        pos = sum(1 for w in words if w in FIN_POSITIVE)
        neg = sum(1 for w in words if w in FIN_NEGATIVE)
        total = pos + neg
        if total == 0:
            return {"label": "Neutral", "score": 0.5, "engine": "lexicon", "model_path": None}
        ratio = pos / total
        label = "Positive" if ratio >= 0.6 else ("Negative" if ratio <= 0.4 else "Neutral")
        return {"label": label, "score": round(ratio, 4), "engine": "lexicon", "model_path": None}

    def batch_analyze(self, texts, batch_size: int = 16):
        return [self.analyze(t) for t in texts]

    def info(self) -> Dict:
        return {
            "engine": self.engine,
            "model_path": self.model_path,
            "transformers": TRANSFORMERS_AVAILABLE,
            "load_error": self._load_error,
            "candidates": [c for c in CANDIDATE_PATHS if c],
        }

def get_analyzer(model_path: Optional[str] = None) -> TrainedCSEAnalyzer:
    global _ANALYZER_SINGLETON
    if _ANALYZER_SINGLETON is None:
        _ANALYZER_SINGLETON = TrainedCSEAnalyzer(model_path=model_path)
    elif model_path and _ANALYZER_SINGLETON.model_path != model_path:
        _ANALYZER_SINGLETON = TrainedCSEAnalyzer(model_path=model_path)
    return _ANALYZER_SINGLETON

def quick_sentiment(text: str, model_path: Optional[str] = None) -> Dict:
    return get_analyzer(model_path).analyze(text)
