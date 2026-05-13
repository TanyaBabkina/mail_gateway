from __future__ import annotations

from typing import Any, Dict

from ..ml_classifier import NaiveBayesMailClassifier
from ..models import CheckResult, MailMessage


def run(message: MailMessage, config: Dict[str, Any], model: NaiveBayesMailClassifier | None = None) -> CheckResult:
    clf = model or NaiveBayesMailClassifier.load("")
    text = " ".join([message.subject, message.text])
    proba = clf.predict_spam_probability(text)
    threshold = float(config["adaptive"].get("ml_threshold", 0.62))
    if proba >= threshold:
        return CheckResult(
            "ml",
            config["weights"].get("ml_spam", 30),
            "suspicious",
            ["ml_probability_above_threshold"],
            {"spam_probability": round(proba, 4), "threshold": threshold},
        )
    return CheckResult("ml", 0, "passed", [], {"spam_probability": round(proba, 4), "threshold": threshold})
