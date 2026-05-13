from __future__ import annotations

import re
from typing import Any, Dict
from urllib.parse import urlparse

from ..models import CheckResult, MailMessage

_IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def run(message: MailMessage, config: Dict[str, Any]) -> CheckResult:
    score = 0
    reasons = []
    hits = []
    weight = config["weights"].get("url_suspicious", 22)
    shorteners = set(config["urls"].get("shorteners", []))
    blocked_domains = set(config["urls"].get("blocked_domains", []))
    tokens = config["urls"].get("suspicious_tokens", [])

    for url in message.urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().strip(".")
        url_reasons = []
        if not host:
            continue
        if host in blocked_domains:
            score += 90
            url_reasons.append("blocked_domain")
        if host in shorteners:
            score += weight
            url_reasons.append("url_shortener")
        if host.startswith("xn--") or ".xn--" in host:
            score += weight
            url_reasons.append("punycode_domain")
        if _IP_HOST_RE.match(host):
            score += weight
            url_reasons.append("ip_address_in_url")
        if any(token in url.lower() for token in tokens):
            score += max(8, weight // 2)
            url_reasons.append("phishing_token")
        if url_reasons:
            reasons.extend(url_reasons)
            hits.append({"url": url, "reasons": url_reasons})

    return CheckResult("urls", score, "suspicious" if score else "passed", list(dict.fromkeys(reasons)), {"hits": hits})
