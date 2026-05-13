from __future__ import annotations

from .models import ScanResult


def to_cef(result: ScanResult) -> str:
    severity = 10 if result.action == "reject" else 6 if result.action == "quarantine" else 2
    subject = result.message.subject.replace("|", " ")[:120]
    sender = result.message.sender.replace("|", " ")[:120]
    reasons = ",".join(result.reasons)[:250]
    return (
        f"CEF:0|mail-gateway|MailGateway|0.1|MAIL_SCAN|Adaptive mail scan|{severity}|"
        f"src={result.message.client_ip or 'unknown'} suser={sender} msg={subject} "
        f"cs1Label=action cs1={result.action} cs2Label=risk_score cs2={result.total_score} "
        f"cs3Label=reasons cs3={reasons}"
    )
