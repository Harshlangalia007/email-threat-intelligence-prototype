"""
Integration Test Suite for SIH26106 Direct Mailbox Integration API
Tests Flask endpoints for Gmail, Outlook, and IMAP connectors.
"""

import unittest
import json
from app import app, mailbox_manager, case_store


class MailboxIntegrationTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        # Reset mailbox state before each test
        mailbox_manager.disconnect()

    def tearDown(self):
        mailbox_manager.disconnect()

    def test_01_mailbox_status_initial(self):
        """Verify initial mailbox status is disconnected."""
        res = self.app.get('/api/mailbox/status')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "success")
        self.assertFalse(data["mailbox"]["connected"])

    def test_02_gmail_demo_connect_and_analyze(self):
        """Verify connecting to Gmail Demo mailbox, listing messages, and analyzing an email."""
        # 1. Connect
        connect_res = self.app.post('/api/mailbox/connect', json={
            "provider": "gmail",
            "credentials": {"mode": "demo"}
        })
        self.assertEqual(connect_res.status_code, 200)
        conn_data = json.loads(connect_res.data)
        self.assertEqual(conn_data["status"], "connected")
        self.assertIn("gmail", conn_data["provider"].lower())

        # 2. List Messages
        list_res = self.app.get('/api/mailbox/messages')
        self.assertEqual(list_res.status_code, 200)
        list_data = json.loads(list_res.data)
        self.assertEqual(list_data["status"], "success")
        self.assertGreater(len(list_data["messages"]), 0)

        # 3. Analyze First Message
        target_msg = list_data["messages"][0]
        analyze_res = self.app.post('/api/mailbox/analyze', json={
            "message_id": target_msg["id"]
        })
        self.assertEqual(analyze_res.status_code, 200)
        ana_data = json.loads(analyze_res.data)
        self.assertEqual(ana_data["status"], "success")
        self.assertTrue(ana_data["case_id"].startswith("CASE-MBOX-"))

        # Verify dossier structure
        dossier = ana_data["dossier"]
        self.assertIn("threat_detection", dossier)
        self.assertIn("forensic_investigation", dossier)
        self.assertIn("ai_synthesis", dossier)
        self.assertIn("graph_data", dossier)
        self.assertIn("parsed_email", dossier)

        # Check threat score exists
        risk_score = dossier["threat_detection"].get("composite_risk_score", 0)
        self.assertGreaterEqual(risk_score, 0)

    def test_03_outlook_demo_connect_and_analyze(self):
        """Verify connecting to Outlook Demo mailbox, listing messages, and analyzing an email."""
        # 1. Connect
        connect_res = self.app.post('/api/mailbox/connect', json={
            "provider": "outlook",
            "credentials": {"mode": "demo"}
        })
        self.assertEqual(connect_res.status_code, 200)
        conn_data = json.loads(connect_res.data)
        self.assertEqual(conn_data["status"], "connected")
        self.assertIn("outlook", conn_data["provider"].lower())

        # 2. List Messages with query
        list_res = self.app.get('/api/mailbox/messages?query=wire')
        self.assertEqual(list_res.status_code, 200)
        list_data = json.loads(list_res.data)
        self.assertEqual(list_data["status"], "success")
        self.assertGreater(len(list_data["messages"]), 0)

        # 3. Analyze filtered message
        target_msg = list_data["messages"][0]
        analyze_res = self.app.post('/api/mailbox/analyze', json={
            "message_id": target_msg["id"]
        })
        self.assertEqual(analyze_res.status_code, 200)
        ana_data = json.loads(analyze_res.data)
        self.assertEqual(ana_data["status"], "success")
        self.assertIn("threat_detection", ana_data["dossier"])

    def test_04_imap_demo_connect_and_analyze(self):
        """Verify connecting to Generic IMAP Demo mailbox and analyzing an email."""
        # 1. Connect
        connect_res = self.app.post('/api/mailbox/connect', json={
            "provider": "imap",
            "credentials": {"mode": "demo"}
        })
        self.assertEqual(connect_res.status_code, 200)
        conn_data = json.loads(connect_res.data)
        self.assertEqual(conn_data["status"], "connected")
        self.assertIn("imap", conn_data["provider"].lower())

        # 2. List Messages
        list_res = self.app.get('/api/mailbox/messages')
        self.assertEqual(list_res.status_code, 200)
        list_data = json.loads(list_res.data)
        self.assertEqual(list_data["status"], "success")
        self.assertGreater(len(list_data["messages"]), 0)

        # 3. Analyze
        target_msg = list_data["messages"][0]
        analyze_res = self.app.post('/api/mailbox/analyze', json={
            "message_id": target_msg["id"]
        })
        self.assertEqual(analyze_res.status_code, 200)
        ana_data = json.loads(analyze_res.data)
        self.assertEqual(ana_data["status"], "success")

    def test_05_disconnect_and_oauth_url(self):
        """Verify disconnecting resets status, and OAuth URL generation works."""
        # Connect then disconnect
        self.app.post('/api/mailbox/connect', json={"provider": "gmail", "credentials": {"mode": "demo"}})
        status_before = json.loads(self.app.get('/api/mailbox/status').data)
        self.assertTrue(status_before["mailbox"]["connected"])

        disc_res = self.app.post('/api/mailbox/disconnect')
        self.assertEqual(disc_res.status_code, 200)

        status_after = json.loads(self.app.get('/api/mailbox/status').data)
        self.assertFalse(status_after["mailbox"]["connected"])

        # OAuth URL generation for Gmail
        oauth_res = self.app.get('/api/mailbox/oauth/url?provider=gmail&client_id=test_client_id_123')
        self.assertEqual(oauth_res.status_code, 200)
        oauth_data = json.loads(oauth_res.data)
        self.assertEqual(oauth_data["status"], "success")
        self.assertIn("accounts.google.com", oauth_data["auth_url"])
        self.assertIn("test_client_id_123", oauth_data["auth_url"])

        # OAuth URL generation for Outlook
        oauth_res_out = self.app.get('/api/mailbox/oauth/url?provider=outlook&client_id=msft_client_id_456')
        self.assertEqual(oauth_res_out.status_code, 200)
        oauth_data_out = json.loads(oauth_res_out.data)
        self.assertEqual(oauth_data_out["status"], "success")
        self.assertIn("login.microsoftonline.com", oauth_data_out["auth_url"])
        self.assertIn("msft_client_id_456", oauth_data_out["auth_url"])


if __name__ == '__main__':
    unittest.main()
