"""
Edge Case Tests for Arbitrary Pasted Emails (e.g. without headers, or incomplete headers)
"""

import unittest
from engine.parser import EmailParser
from engine.threat_detector import ThreatDetector
from engine.forensic_investigator import ForensicInvestigator
from engine.ai_provider import AIProviderManager
from engine.graph_engine import GraphEngine
from engine.case_store import CaseStore


class TestPastedEmails(unittest.TestCase):

    def setUp(self):
        self.p = EmailParser()
        self.td = ThreatDetector()
        self.fi = ForensicInvestigator()
        self.ai = AIProviderManager.get_instance()
        self.ge = GraphEngine()
        self.cs = CaseStore(db_path=":memory:")

    def test_pasted_plain_body_no_headers(self):
        raw = "Immediate action required: please verify your credentials at https://micros0ft-auth.com"
        parsed = self.p.parse_raw_eml(raw)
        threat = self.td.analyze(parsed)
        forensic = self.fi.investigate(parsed)
        ai_rep = self.ai.analyze(parsed, threat, forensic)
        graph = self.ge.build_email_graph("TEST-PASTE-1", parsed, threat, forensic)

        dossier = {
            "case_id": "TEST-PASTE-1",
            "parsed_email": parsed,
            "threat_detection": threat,
            "forensic_investigation": forensic,
            "ai_synthesis": ai_rep,
            "graph_data": graph
        }
        cid = self.cs.save_case(dossier)
        self.assertEqual(cid, "TEST-PASTE-1")
        self.assertEqual(threat["classification"], "Phishing")
        self.assertGreaterEqual(threat["risk_score"], 60)
        self.assertEqual(forensic["relay_path"]["origin_mta"]["ip"], "N/A")

    def test_pasted_simple_bec(self):
        raw = """From: "CEO John" <ceo@company.com>
Subject: Quick wire transfer
To: finance@company.com

Please process an urgent wire transfer of $25,000 today. I am in a meeting."""
        parsed = self.p.parse_raw_eml(raw)
        threat = self.td.analyze(parsed)
        forensic = self.fi.investigate(parsed)
        ai_rep = self.ai.analyze(parsed, threat, forensic)
        graph = self.ge.build_email_graph("TEST-PASTE-2", parsed, threat, forensic)

        self.assertEqual(threat["classification"], "Business Email Compromise (BEC)")
        self.assertGreaterEqual(threat["risk_score"], 50)
        self.assertIn("Insufficient routing header evidence", forensic["location_analysis"]["mandatory_statement"])


if __name__ == "__main__":
    unittest.main()
