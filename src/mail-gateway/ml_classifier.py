from __future__ import annotations

import csv
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, Tuple

_TOKEN_RE = re.compile(r"[A-Za-zА-Яа-я0-9_]{3,}")
SPAM_LABELS = {"spam", "phishing", "malware", "1", "true", "bad"}
HAM_LABELS = {"ham", "legit", "notspam", "0", "false", "good"}


def tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text or "")]


class NaiveBayesMailClassifier:
    def __init__(self) -> None:
        self.class_docs: Counter[str] = Counter()
        self.token_counts: Dict[str, Counter[str]] = defaultdict(Counter)
        self.total_tokens: Counter[str] = Counter()
        self.vocabulary: set[str] = set()

    def fit(self, rows: Iterable[Tuple[str, str]]) -> None:
        for text, label in rows:
            norm_label = normalize_label(label)
            self.class_docs[norm_label] += 1
            tokens = tokenize(text)
            self.token_counts[norm_label].update(tokens)
            self.total_tokens[norm_label] += len(tokens)
            self.vocabulary.update(tokens)
        if not self.class_docs:
            raise ValueError("Training dataset is empty")

    def predict_spam_probability(self, text: str) -> float:
        tokens = tokenize(text)
        labels = ["ham", "spam"]
        log_probs: Dict[str, float] = {}
        total_docs = sum(self.class_docs.values())
        vocab_size = max(1, len(self.vocabulary))
        for label in labels:
            prior = (self.class_docs[label] + 1) / (total_docs + len(labels))
            log_prob = math.log(prior)
            denom = self.total_tokens[label] + vocab_size
            for token in tokens:
                log_prob += math.log((self.token_counts[label][token] + 1) / denom)
            log_probs[label] = log_prob
        max_log = max(log_probs.values())
        spam_exp = math.exp(log_probs["spam"] - max_log)
        ham_exp = math.exp(log_probs["ham"] - max_log)
        return spam_exp / (spam_exp + ham_exp)

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "class_docs": dict(self.class_docs),
            "token_counts": {label: dict(counter) for label, counter in self.token_counts.items()},
            "total_tokens": dict(self.total_tokens),
            "vocabulary": sorted(self.vocabulary),
        }
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "NaiveBayesMailClassifier":
        p = Path(path)
        obj = cls()
        if not p.exists():
            return default_classifier()
        data = json.loads(p.read_text(encoding="utf-8"))
        obj.class_docs = Counter(data.get("class_docs", {}))
        obj.token_counts = defaultdict(Counter, {k: Counter(v) for k, v in data.get("token_counts", {}).items()})
        obj.total_tokens = Counter(data.get("total_tokens", {}))
        obj.vocabulary = set(data.get("vocabulary", []))
        return obj


def normalize_label(label: str) -> str:
    value = str(label).strip().lower()
    if value in SPAM_LABELS:
        return "spam"
    if value in HAM_LABELS:
        return "ham"
    raise ValueError(f"Unknown label: {label}")


def load_csv_rows(path: str | Path) -> list[Tuple[str, str]]:
    with Path(path).open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if "text" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError("CSV must contain text and label columns")
        return [(row["text"], row["label"]) for row in reader]


def default_classifier() -> NaiveBayesMailClassifier:
    rows = [
        ("счет договор встреча коммерческое предложение", "ham"),
        ("отчет проект согласование документы во вложении", "ham"),
        ("срочно подтвердите пароль login verify account", "spam"),
        ("вы выиграли получите выплату перейдите по ссылке", "spam"),
        ("password expires urgent action required", "spam"),
        ("протокол совещания и план работ", "ham"),
    ]
    model = NaiveBayesMailClassifier()
    model.fit(rows)
    return model
