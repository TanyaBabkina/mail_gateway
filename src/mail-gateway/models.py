from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    sha256: str
    payload_path: Optional[str] = None


@dataclass
class MailMessage:
    source_path: str
    message_id: str
    sender: str
    recipients: List[str]
    subject: str
    headers: Dict[str, str]
    text: str
    html: str
    urls: List[str]
    attachments: List[AttachmentInfo]
    size_bytes: int
    client_ip: Optional[str] = None


@dataclass
class CheckResult:
    name: str
    score: int
    verdict: str
    reasons: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    message: MailMessage
    checks: List[CheckResult]
    total_score: int
    action: str
    reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["message"]["attachments"] = [asdict(a) for a in self.message.attachments]
        return result


@dataclass
class MetricResult:
    tp: int
    tn: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_positives_per_1000: float
