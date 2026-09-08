"""
Unit Tests for Mailbox Integration (Gmail, Outlook, IMAP, and Unified Pipeline)
"""

import unittest
from engine.mailbox.gmail_connector import GmailConnector
from engine.mailbox.outlook_connector import OutlookConnector
from engine.mailbox.imap_connector import IMAPConnector
from engine.mailbox.manager import MailboxManager
from engine.parser import EmailParser
from engine.threat_detector import ThreatDetector
from engine.forensic_investigator import ForensicInvestigator


class TestMailboxIntegration(unittest.TestCase):

    def setUp(self):
        self.parser = EmailParser()
        self.threat_detector = ThreatDetector()
        self.forensic_investigator = ForensicInvestigator()
        self.manager = MailboxManager.get_instance()

    def test_gmail_demo_connector(self):
        connector = GmailConnector()
        conn_res = connector.connect({"mode": "demo"})
        self.assertEqual(conn_res["status"], "connected")
        self.assertTrue(connector.is_connected)

        messages = connector.list_messages()
        self.assertGreater(len(messages), 0)
        first_msg = messages[0]
        self.assertIn("subject", first_msg)
        self.assertIn("from", first_msg)

        raw_mime = connector.fetch_raw_message(first_msg["id"])
        self.assertTrue(len(raw_mime) > 50)
        self.assertIn("Delivered-To:", raw_mime)

        # Pipe through standard forensic pipeline
        parsed = self.parser.parse_raw_eml(raw_mime)
        threat = self.threat_detector.analyze(parsed)
        forensic = self.forensic_investigator.investigate(parsed)

        self.assertIn(threat["classification"], ["Phishing", "Legitimate", "Business Email Compromise (BEC)", "Malware Delivery"])
        self.assertIsNotNone(forensic["relay_path"]["origin_mta"])

        connector.disconnect()
        self.assertFalse(connector.is_connected)

    def test_outlook_demo_connector(self):
        connector = OutlookConnector()
        conn_res = connector.connect({"mode": "demo"})
        self.assertEqual(conn_res["status"], "connected")
        self.assertTrue(connector.is_connected)

        messages = connector.list_messages()
        self.assertGreater(len(messages), 0)
        first_msg = messages[0]

        raw_mime = connector.fetch_raw_message(first_msg["id"])
        self.assertTrue(len(raw_mime) > 50)

        parsed = self.parser.parse_raw_eml(raw_mime)
        threat = self.threat_detector.analyze(parsed)
        forensic = self.forensic_investigator.investigate(parsed)

        self.assertIn(threat["classification"], ["Phishing", "Legitimate", "Business Email Compromise (BEC)", "Malware Delivery"])
        connector.disconnect()

    def test_imap_demo_connector(self):
        connector = IMAPConnector()
        conn_res = connector.connect({"mode": "demo"})
        self.assertEqual(conn_res["status"], "connected")
        self.assertTrue(connector.is_connected)

        messages = connector.list_messages()
        self.assertGreater(len(messages), 0)
        first_msg = messages[0]

        raw_mime = connector.fetch_raw_message(first_msg["id"])
        self.assertTrue(len(raw_mime) > 50)

        parsed = self.parser.parse_raw_eml(raw_mime)
        threat = self.threat_detector.analyze(parsed)
        self.assertTrue(threat["risk_score"] >= 0)
        connector.disconnect()

    def test_mailbox_manager_unified_pipeline(self):
        self.manager.disconnect()
        status_init = self.manager.get_status()
        self.assertFalse(status_init["connected"])

        # Connect Gmail in demo mode
        conn_res = self.manager.connect("gmail", {"mode": "demo"})
        self.assertEqual(conn_res["status"], "connected")
        status_active = self.manager.get_status()
        self.assertTrue(status_active["connected"])
        self.assertEqual(status_active["provider"], "gmail")

        # Browse messages
        messages = self.manager.list_messages()
        self.assertGreater(len(messages), 0)

        # Fetch and analyze directly via manager
        raw_mime = self.manager.fetch_raw_message(messages[0]["id"])
        parsed = self.parser.parse_raw_eml(raw_mime)
        threat = self.threat_detector.analyze(parsed)
        self.assertIsNotNone(threat["classification"])

        # Switch to Outlook
        conn_res2 = self.manager.connect("outlook", {"mode": "demo"})
        self.assertEqual(conn_res2["status"], "connected")
        self.assertEqual(self.manager.active_provider, "outlook")

        self.manager.disconnect()
        self.assertFalse(self.manager.get_status()["connected"])


if __name__ == "__main__":
    unittest.main()
