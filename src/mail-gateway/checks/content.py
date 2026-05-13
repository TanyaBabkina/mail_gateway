from __future__ import annotations

import re
from typing import Any, Dict

from ..models import CheckResult, MailMessage


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def run(message: MailMessage, config: Dict[str, Any]) -> CheckResult:
    text = _normalize(" ".join([message.subject, message.text, message.html]))
    reasons = []
    details = {"keyword_hits": [], "dlp_hits": []}
    score = 0

    for keyword in config["content"].get("spam_keywords", []):
        if keyword.lower() in text:
            score += config["weights"].get("content_keyword", 12)
            reasons.append("spam_keyword_detected")
            details["keyword_hits"].append(keyword)

    for pattern in config["content"].get("dlp_regex", []):
        if re.search(pattern, text):
            score += config["weights"].get("dlp_pattern", 18)
            reasons.append("dlp_pattern_detected")
            details["dlp_hits"].append(pattern)

    unique_reasons = list(dict.fromkeys(reasons))
    return CheckResult("content", score, "suspicious" if score else "passed", unique_reasons, details)
