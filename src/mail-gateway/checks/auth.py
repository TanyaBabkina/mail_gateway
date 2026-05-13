from __future__ import annotations

from typing import Any, Dict

from ..models import CheckResult, MailMessage


def run(message: MailMessage, config: Dict[str, Any]) -> CheckResult:
    auth = " ".join(value.lower() for key, value in message.headers.items() if key.lower() == "authentication-results")
    reasons = []
    score = 0
    weight = config["weights"].get("auth_fail", 25)

    if not auth:
        return CheckResult("auth", 5, "unknown", ["authentication_results_header_missing"], {})

    for mechanism in ("spf", "dkim", "dmarc"):
        if f"{mechanism}=fail" in auth or f"{mechanism}=softfail" in auth:
            score += weight
            reasons.append(f"{mechanism}_failed")

    if "dmarc=pass" not in auth and "spf=pass" not in auth and "dkim=pass" not in auth:
        score += weight // 2
        reasons.append("no_positive_auth_result")

    return CheckResult("auth", score, "suspicious" if score else "passed", reasons, {"authentication_results": auth[:500]})
