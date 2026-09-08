"""
Automated Unit Test Suite for SIH26106 Engines
Tests RFC 5322 parsing, threat detection, forensic relay reconstruction,
graph generation, and local case storage.
"""

import unittest
from engine.parser import EmailParser
from engine.threat_detector import ThreatDetector
from engine.threat_intel import ThreatIntelEngine
from engine.forensic_investigator import ForensicInvestigator
from engine.graph_engine import GraphEngine
from engine.ai_provider import AIProviderManager
from engine.samples import SAMPLE_EMAILS
from engine.case_store import CaseStore


class TestCyberForensics(unittest.TestCase):

    def setUp(self):
        self.parser = EmailParser()
        self.threat_detector = ThreatDetector()
        self.intel_engine = ThreatIntelEngine()
        self.forensic_investigator = ForensicInvestigator(self.intel_engine)
        self.graph_engine = GraphEngine()
        self.ai_manager = AIProviderManager.get_instance()
        self.case_store = CaseStore(db_path=":memory:")

    def test_sample_1_legitimate(self):
        raw = SAMPLE_EMAILS["sample_1_legitimate"]["raw_eml"]
        parsed = self.parser.parse_raw_eml(raw)
        
        self.assertEqual(parsed["identity"]["from_email"], "sarah.jenkins@acmepartners.com")
        self.assertIn("Q3 Architecture Sync", parsed["identity"]["subject"])
        
        threat = self.threat_detector.analyze(parsed)
        self.assertEqual(threat["classification"], "Legitimate")
        self.assertLessEqual(threat["risk_score"], 25)
        self.assertEqual(threat["auth_analysis"]["spf"]["status"], "PASS")
        self.assertEqual(threat["auth_analysis"]["dkim"]["status"], "PASS")

        forensic = self.forensic_investigator.investigate(parsed)
        relay = forensic["relay_path"]
        self.assertGreaterEqual(relay["total_hops"], 1)
        origin = relay["origin_mta"]
        self.assertIsNotNone(origin)
        self.assertEqual(origin["ip"], "209.85.220.41")

    def test_sample_2_phishing_credential_harvest(self):
        raw = SAMPLE_EMAILS["sample_2_phishing"]["raw_eml"]
        parsed = self.parser.parse_raw_eml(raw)
        
        # Check domain lookalike
        self.assertIn("micros0ft", parsed["identity"]["from_domain"])
        self.assertTrue(len(parsed["urls"]) > 0)

        threat = self.threat_detector.analyze(parsed)
        self.assertEqual(threat["classification"], "Phishing")
        self.assertGreaterEqual(threat["risk_score"], 80)
        self.assertTrue(threat["identity_analysis"]["is_lookalike_domain"])
        self.assertEqual(threat["auth_analysis"]["spf"]["status"], "FAIL")
        self.assertTrue(threat["social_engineering"]["has_credential_harvesting"])

        forensic = self.forensic_investigator.investigate(parsed)
        loc = forensic["location_analysis"]
        self.assertIn("Observed sending infrastructure appears to be located in", loc["mandatory_statement"])
        self.assertIn("This does not necessarily represent the physical location of the attacker.", loc["disclaimer"])

    def test_sample_3_executive_bec(self):
        raw = SAMPLE_EMAILS["sample_3_bec"]["raw_eml"]
        parsed = self.parser.parse_raw_eml(raw)
        
        threat = self.threat_detector.analyze(parsed)
        self.assertEqual(threat["classification"], "Business Email Compromise (BEC)")
        self.assertGreaterEqual(threat["risk_score"], 80)
        self.assertTrue(threat["identity_analysis"]["reply_to_mismatch"])
        self.assertTrue(threat["social_engineering"]["has_money_requests"])
        self.assertTrue(threat["social_engineering"]["has_executive_impersonation"])

    def test_sample_4_malware_and_cross_correlation(self):
        raw = SAMPLE_EMAILS["sample_4_malware_shared_infra"]["raw_eml"]
        parsed = self.parser.parse_raw_eml(raw)
        
        self.assertEqual(len(parsed["attachments"]), 1)
        self.assertTrue(parsed["attachments"][0]["is_suspicious"])
        self.assertTrue(parsed["attachments"][0]["filename"].endswith(".exe"))

        threat = self.threat_detector.analyze(parsed)
        self.assertEqual(threat["classification"], "Malware Delivery")
        self.assertGreaterEqual(threat["risk_score"], 90)

        forensic = self.forensic_investigator.investigate(parsed)
        graph = self.graph_engine.build_email_graph("CASE-TEST-MALWARE", parsed, threat, forensic)
        
        # Verify cross-campaign correlation nodes
        node_ids = [n["id"] for n in graph["nodes"]]
        self.assertIn("campaign_FIN_PHISH_26", node_ids)
        self.assertIn("email_hist_094", node_ids)

    def test_case_store(self):
        dossier = {
            "case_id": "CASE-UNIT-1",
            "parsed_email": {"identity": {"subject": "Test", "from_email": "a@b.com", "from_domain": "b.com"}, "urls": []},
            "threat_detection": {"classification": "Legitimate", "risk_score": 10, "risk_level": "LOW", "confidence": 95},
            "forensic_investigation": {"relay_path": {"total_hops": 2, "origin_mta": {"ip": "1.2.3.4", "country": "US", "asn": "AS123"}}}
        }
        case_id = self.case_store.save_case(dossier)
        self.assertEqual(case_id, "CASE-UNIT-1")
        
        retrieved = self.case_store.get_case("CASE-UNIT-1")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["case_id"], "CASE-UNIT-1")
        
        metrics = self.case_store.get_soc_metrics()
        self.assertEqual(metrics["total_analyzed"], 1)


if __name__ == "__main__":
    unittest.main()
