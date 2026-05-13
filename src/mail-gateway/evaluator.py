from __future__ import annotations

from typing import Iterable, Tuple

from .models import MetricResult


def compute_metrics(pairs: Iterable[Tuple[str, str]]) -> MetricResult:
    tp = tn = fp = fn = 0
    for expected, predicted in pairs:
        e = _is_spam(expected)
        p = _is_spam(predicted)
        if e and p:
            tp += 1
        elif not e and not p:
            tn += 1
        elif not e and p:
            fp += 1
        elif e and not p:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fp1000 = fp / tn * 1000 if tn else 0.0
    return MetricResult(tp, tn, fp, fn, precision, recall, f1, fpr, fp1000)


def _is_spam(value: str) -> bool:
    return str(value).lower() in {"spam", "phishing", "malware", "reject", "quarantine", "1", "bad"}
