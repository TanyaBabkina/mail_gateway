from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
from zipfile import BadZipFile, ZipFile

from ..models import CheckResult, MailMessage


def run(message: MailMessage, config: Dict[str, Any]) -> CheckResult:
    score = 0
    reasons = []
    hits = []
    dangerous = {ext.lower() for ext in config["attachments"].get("dangerous_extensions", [])}
    archives = {ext.lower() for ext in config["attachments"].get("archive_extensions", [])}
    bad_hashes = {h.lower() for h in config["attachments"].get("known_bad_sha256", [])}

    for attachment in message.attachments:
        name = attachment.filename
        suffix = Path(name).suffix.lower()
        item_reasons = []
        if attachment.sha256.lower() in bad_hashes:
            score += config["weights"].get("known_bad_hash", 90)
            item_reasons.append("known_bad_sha256")
        if suffix in dangerous:
            score += config["weights"].get("dangerous_attachment", 35)
            item_reasons.append("dangerous_extension")
        if suffix in archives and attachment.payload_path:
            item_reasons.extend(_inspect_zip(attachment.payload_path, dangerous))
            if item_reasons:
                score += config["weights"].get("dangerous_attachment", 35)
        if item_reasons:
            reasons.extend(item_reasons)
            hits.append({"filename": name, "sha256": attachment.sha256, "reasons": item_reasons})

    return CheckResult("attachments", score, "suspicious" if score else "passed", list(dict.fromkeys(reasons)), {"hits": hits})


def _inspect_zip(path: str, dangerous_ext: set[str]) -> list[str]:
    reasons: list[str] = []
    try:
        with ZipFile(path) as zf:
            for member in zf.namelist():
                if Path(member).suffix.lower() in dangerous_ext:
                    reasons.append("dangerous_file_inside_archive")
                    break
    except BadZipFile:
        reasons.append("invalid_archive")
    return reasons
