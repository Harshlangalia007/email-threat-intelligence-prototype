"""
Unit tests for UserFriendlySummaryGenerator in SIH26106.
Verifies plain-language explanations, zero-jargon communication,
and structured recommendations across standard scenarios and edge cases.
"""

import unittest
from engine.parser import EmailParser
from engine.threat_detector import ThreatDetector
from engine.forensic_investigator import ForensicInvestigator
from engine.samples import SAMPLE_EMAILS
from engine.human_summary import UserFriendlySummaryGenerator


class HumanSummaryTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = EmailParser()
        cls.threat_detector = ThreatDetector()
        cls.investigator = ForensicInvestigator()

    def _analyze(self, raw_eml):
        parsed = self.parser.parse_raw_eml(raw_eml)
        threat = self.threat_detector.analyze(parsed)
        forensic = self.investigator.investigate(parsed)
        summary = UserFriendlySummaryGenerator.generate_summary(parsed, threat, forensic)
        return summary, parsed, threat, forensic

    def test_sample_1_legitimate_is_safe(self):
        """Sample 1 should be clearly marked safe with reassuring recommendations."""
        raw = SAMPLE_EMAILS["sample_1_legitimate"]["raw_eml"]
        summary, _, threat, _ = self._analyze(raw)

        self.assertTrue(summary["is_safe"])
        self.assertIn("safe", summary["verdict_headline"].lower())
        self.assertEqual(summary["risk_color"], "safe")
        self.assertGreater(len(summary["action_checklist"]), 0)
        self.assertIn("safely open", summary["recommendation"].lower())
        # Confirm no technical acronyms in plain reasons
        for r in summary["plain_reasons"]:
            self.assertNotIn("DMARC", r)
            self.assertNotIn("DKIM", r)
            self.assertNotIn("SPF", r)

    def test_sample_2_phishing_is_dangerous(self):
        """Sample 2 (Credential Phishing) should have clear warnings and action steps."""
        raw = SAMPLE_EMAILS["sample_2_phishing"]["raw_eml"]
        summary, _, _, _ = self._analyze(raw)

        self.assertFalse(summary["is_safe"])
        self.assertIn("danger", summary["verdict_headline"].lower())
        self.assertIn("🚫", summary["recommendation"])
        # Should explain lookalike domain in plain English
        reasons_text = " ".join(summary["plain_reasons"]).lower()
        self.assertTrue(
            "lookalike" in reasons_text or "impersonat" in reasons_text or "could not be verified" in reasons_text
        )
        self.assertTrue(summary["identity_breakdown"]["is_deceptive"])
        self.assertIn("micros0ft", summary["identity_breakdown"]["actual_domain"])

    def test_sample_3_bec_fraud_is_dangerous(self):
        """Sample 3 (Executive BEC) should flag payment fraud and reply address diversion."""
        raw = SAMPLE_EMAILS["sample_3_bec"]["raw_eml"]
        summary, _, _, _ = self._analyze(raw)

        self.assertFalse(summary["is_safe"])
        self.assertIn("danger", summary["verdict_headline"].lower())
        reasons_text = " ".join(summary["plain_reasons"]).lower()
        self.assertTrue("reply address is different" in reasons_text or "fraud" in reasons_text)
        self.assertIsNotNone(summary["identity_breakdown"]["reply_to"])

    def test_sample_4_malware_file_warning(self):
        """Sample 4 (Malware Delivery) should warn about dangerous executable attachment."""
        raw = SAMPLE_EMAILS["sample_4_malware_shared_infra"]["raw_eml"]
        summary, _, _, _ = self._analyze(raw)

        self.assertFalse(summary["is_safe"])
        self.assertIn("malicious file", summary["verdict_headline"].lower())
        reasons_text = " ".join(summary["plain_reasons"]).lower()
        self.assertTrue("executable" in reasons_text or "attachment" in reasons_text)

    def test_pasted_text_without_routing_headers(self):
        """Pasted text without Received headers should generate a clean fallback journey."""
        raw = "From: hr@example.com\nTo: employee@example.com\nSubject: Test\n\nPlease review."
        summary, _, _, _ = self._analyze(raw)

        self.assertIn("simplified_journey", summary)
        self.assertFalse(summary["simplified_journey"]["has_network_data"])
        self.assertIn("Pasted Input", summary["simplified_journey"]["stages"][0]["title"])


if __name__ == "__main__":
    unittest.main()
