from __future__ import annotations

import hashlib
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List

from .models import AttachmentInfo, MailMessage

_URL_RE = re.compile(r"https?://[^\s<>'\")]+", re.IGNORECASE)
_IP_RE = re.compile(r"\[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]")


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: List[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data.strip())

    def get_text(self) -> str:
        return " ".join(self.parts)


def html_to_text(html: str) -> str:
    parser = _HTMLTextExtractor()
    parser.feed(html or "")
    return parser.get_text()


def extract_urls(*texts: str) -> List[str]:
    found: List[str] = []
    for text in texts:
        for match in _URL_RE.findall(text or ""):
            cleaned = match.rstrip(".,;:!?]")
            if cleaned not in found:
                found.append(cleaned)
    return found


def parse_eml(path: str | Path, attachment_dir: str | Path | None = None) -> MailMessage:
    source = Path(path)
    raw = source.read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    headers: Dict[str, str] = {key: str(value) for key, value in msg.items()}
    sender = str(msg.get("From", ""))
    recipients = [addr for _, addr in getaddresses([str(msg.get("To", "")), str(msg.get("Cc", ""))])]
    subject = str(msg.get("Subject", ""))
    message_id = str(msg.get("Message-ID", source.name))

    text_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[AttachmentInfo] = []

    save_dir = Path(attachment_dir) if attachment_dir else None
    if save_dir:
        save_dir.mkdir(parents=True, exist_ok=True)

    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        content_type = part.get_content_type()
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""

        if disposition == "attachment" or filename:
            safe_name = Path(filename or "attachment.bin").name
            digest = hashlib.sha256(payload).hexdigest()
            saved_path = None
            if save_dir:
                saved = save_dir / f"{digest[:12]}_{safe_name}"
                saved.write_bytes(payload)
                saved_path = str(saved)
            attachments.append(AttachmentInfo(safe_name, content_type, len(payload), digest, saved_path))
            continue

        if content_type == "text/plain":
            try:
                text_parts.append(part.get_content())
            except Exception:
                text_parts.append(payload.decode("utf-8", errors="replace"))
        elif content_type == "text/html":
            try:
                html_parts.append(part.get_content())
            except Exception:
                html_parts.append(payload.decode("utf-8", errors="replace"))

    html = "\n".join(html_parts)
    text = "\n".join(text_parts).strip()
    if not text and html:
        text = html_to_text(html)

    client_ip = None
    received = headers.get("Received", "")
    match = _IP_RE.search(received)
    if match:
        client_ip = match.group("ip")

    return MailMessage(
        source_path=str(source),
        message_id=message_id,
        sender=sender,
        recipients=recipients,
        subject=subject,
        headers=headers,
        text=text,
        html=html,
        urls=extract_urls(text, html),
        attachments=attachments,
        size_bytes=len(raw),
        client_ip=client_ip,
    )
