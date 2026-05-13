from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .checks import attachments, auth, content, ml, session, urls
from .ml_classifier import NaiveBayesMailClassifier
from .models import CheckResult, MailMessage, ScanResult


class AdaptivePolicyOrchestrator:
    """Формирует цепочку проверок письма и агрегирует результаты."""

    def __init__(self, config: Dict[str, Any], model: Optional[NaiveBayesMailClassifier] = None) -> None:
        self.config = config
        self.model = model

    def scan(self, message: MailMessage) -> ScanResult:
        enabled = self.config.get("checks", {})
        results: list[CheckResult] = []

        if enabled.get("session", True):
            results.append(session.run(message, self.config))
        if enabled.get("auth", True):
            results.append(auth.run(message, self.config))
        if enabled.get("content", True):
            results.append(content.run(message, self.config))
        if enabled.get("urls", True):
            results.append(urls.run(message, self.config))
        if enabled.get("attachments", True):
            results.append(attachments.run(message, self.config))
        if enabled.get("ml", True):
            results.append(ml.run(message, self.config, self.model))

        total = min(100, sum(max(0, result.score) for result in results))
        action = self._action(total)
        reasons = []
        for result in results:
            reasons.extend(result.reasons)
        scan_result = ScanResult(message, results, total, action, list(dict.fromkeys(reasons)))
        if action in {"quarantine", "reject"}:
            self._store_quarantine(scan_result)
        return scan_result

    def _action(self, score: int) -> str:
        thresholds = self.config["risk_thresholds"]
        if score >= thresholds.get("reject_from", 85):
            return "reject"
        if score >= thresholds.get("deliver_below", 45):
            return "quarantine"
        return "deliver"

    def _store_quarantine(self, result: ScanResult) -> None:
        qdir = Path(self.config["gateway"].get("quarantine_dir", "artifacts/quarantine"))
        qdir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base = qdir / f"{stamp}_{Path(result.message.source_path).stem}"
        base.mkdir(parents=True, exist_ok=True)
        source = Path(result.message.source_path)
        if source.exists():
            shutil.copy2(source, base / source.name)
        (base / "verdict.json").write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
