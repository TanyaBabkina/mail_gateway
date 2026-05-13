from __future__ import annotations

from email.utils import parseaddr
from ipaddress import ip_address, ip_network
from typing import Any, Dict

from ..models import CheckResult, MailMessage

_PRIVATE_NETS = [
    ip_network("10.0.0.0/8"), ip_network("172.16.0.0/12"), ip_network("192.168.0.0/16"), ip_network("127.0.0.0/8")
]


def run(message: MailMessage, config: Dict[str, Any]) -> CheckResult:
    reasons = []
    score = 0
    sender_addr = parseaddr(message.sender)[1]
    sender_domain = sender_addr.split("@")[-1].lower() if "@" in sender_addr else ""
    trusted_domains = set(config["gateway"].get("trusted_internal_domains", []))

    if message.size_bytes > config["gateway"].get("max_message_size_bytes", 10_485_760):
        score += config["weights"].get("session_anomaly", 15)
        reasons.append("message_size_exceeds_policy")

    if not sender_addr or "@" not in sender_addr:
        score += config["weights"].get("session_anomaly", 15)
        reasons.append("invalid_sender_address")

    if sender_domain in trusted_domains and message.client_ip:
        try:
            ip = ip_address(message.client_ip)
            if not any(ip in net for net in _PRIVATE_NETS):
                score += config["weights"].get("session_anomaly", 15)
                reasons.append("internal_domain_from_external_ip")
        except ValueError:
            score += config["weights"].get("session_anomaly", 15)
            reasons.append("invalid_client_ip")

    verdict = "suspicious" if score else "passed"
    return CheckResult("session", score, verdict, reasons, {"sender_domain": sender_domain, "client_ip": message.client_ip})
