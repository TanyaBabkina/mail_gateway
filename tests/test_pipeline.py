import unittest
from pathlib import Path

from mail-gateway.config import load_config
from mail-gateway.ml_classifier import default_classifier
from mail-gateway.orchestrator import AdaptivePolicyOrchestrator
from mail-gateway.parser import parse_eml

ROOT = Path(__file__).resolve().parents[1]


class PipelineTestCase(unittest.TestCase):
    def setUp(self):
        self.config = load_config(ROOT / "configs/policies.json")
        self.model = default_classifier()

    def test_legit_email_is_delivered(self):
        msg = parse_eml(ROOT / "data/sample_emails/legit_invoice.eml")
        result = AdaptivePolicyOrchestrator(self.config, self.model).scan(msg)
        self.assertEqual(result.action, "deliver")

    def test_phishing_email_is_not_delivered(self):
        msg = parse_eml(ROOT / "data/sample_emails/phishing_password.eml")
        result = AdaptivePolicyOrchestrator(self.config, self.model).scan(msg)
        self.assertIn(result.action, {"quarantine", "reject"})
        self.assertGreaterEqual(result.total_score, 45)

    def test_attachment_risk_detected(self):
        msg = parse_eml(
            ROOT / "data/sample_emails/malicious_attachment.eml",
            attachment_dir=ROOT / "artifacts/test_attachments",
        )
        result = AdaptivePolicyOrchestrator(self.config, self.model).scan(msg)
        self.assertTrue(any(check.name == "attachments" and check.score > 0 for check in result.checks))


if __name__ == "__main__":
    unittest.main()
