"""
Generic IMAP Connector (imaplib SSL) for SIH26106
Connects to standard IMAP mailboxes (Yahoo, Zoho, iCloud, Corporate IMAP) over SSL port 993.
Retrieves full RFC 822 MIME messages without storing user passwords to disk.
Includes clean Simulated / Demo Mode for instant offline testing.
"""

import imaplib
import email
from email.header import decode_header
from typing import Dict, Any, List, Optional

from engine.mailbox.base import BaseMailboxConnector


class IMAPConnector(BaseMailboxConnector):
    """
    Connects to IMAP servers using Python's standard imaplib with SSL encryption.
    Fetches raw RFC 822 messages. Never stores passwords in persistent storage.
    """

    DEMO_INBOX = [
        {
            "id": "imap_msg_201",
            "from": "payroll-update@company-directdeposit.vip",
            "from_name": "Corporate Payroll Department",
            "to": "employee@corporate-domain.com",
            "subject": "ACTION REQUIRED: Direct Deposit Banking Update Verification",
            "date": "Mon, 7 Sep 2026 14:15:00 +0000",
            "snippet": "Dear Employee, Our payroll ledger detected an error with your direct deposit routing number. Update your details immediately to ensure on-time salary credit...",
            "is_unread": True,
            "raw_eml": """Delivered-To: employee@corporate-domain.com
Received: from mail.company-directdeposit.vip (mail.company-directdeposit.vip [185.220.101.5])
        by imap.corporate-domain.com with ESMTP id p4910284;
        Mon, 7 Sep 2026 14:15:05 +0000
Received-SPF: fail client-ip=185.220.101.5;
Authentication-Results: spf=fail; dkim=fail; dmarc=fail;
From: "Corporate Payroll Department" <payroll-update@company-directdeposit.vip>
Reply-To: "Payroll Routing" <hr-payroll289@gmail.com>
To: <employee@corporate-domain.com>
Subject: ACTION REQUIRED: Direct Deposit Banking Update Verification
Date: Mon, 7 Sep 2026 14:15:00 +0000
Message-ID: <PAY94820194.2026@company-directdeposit.vip>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Dear Employee,

Our payroll ledger detected an error with your direct deposit routing information for the upcoming disbursement cycle.

Failure to verify your banking routing details within 24 hours will delay your salary disbursement.

Verify your direct deposit credentials below:
http://portal-payroll-verify.vip/login.php?user=employee

Sincerely,
Corporate Payroll Operations
"""
        },
        {
            "id": "imap_msg_202",
            "from": "alerts@dhl-express-tracking.top",
            "from_name": "DHL Express Tracking",
            "to": "employee@corporate-domain.com",
            "subject": "Notice: Delivery Exception for Parcel #DHL-99214 — Customs Fee Due",
            "date": "Tue, 8 Sep 2026 09:30:10 +0000",
            "snippet": "Your express delivery #DHL-99214 could not be completed due to an unpaid customs handling fee of $3.50. Pay online to release shipment...",
            "is_unread": True,
            "raw_eml": """Delivered-To: employee@corporate-domain.com
Received: from vps88.bulletproof-transit.nl (vps88.bulletproof-transit.nl [45.154.255.88])
        by imap.corporate-domain.com with ESMTP id dhl88329;
        Tue, 8 Sep 2026 09:30:12 +0000
Received-SPF: fail;
Authentication-Results: spf=fail; dkim=fail; dmarc=fail;
From: "DHL Express Tracking" <alerts@dhl-express-tracking.top>
To: <employee@corporate-domain.com>
Subject: Notice: Delivery Exception for Parcel #DHL-99214 — Customs Fee Due
Date: Tue, 8 Sep 2026 09:30:10 +0000
Message-ID: <DHL20260908.093010@dhl-express-tracking.top>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body>
  <h2 style="color: #d40511;">DHL Express: Delivery On Hold</h2>
  <p>Your package #DHL-99214 is currently detained at the logistics sorting terminal.</p>
  <p>Pay the unpaid customs inspection processing fee ($3.50) within 12 hours:</p>
  <p><a href="https://dhl-express-tracking.top/pay/fee.php">Pay Clearance Fee & Schedule Delivery</a></p>
</body>
</html>
"""
        }
    ]

    def __init__(self):
        self.server: Optional[imaplib.IMAP4_SSL] = None
        self.host: Optional[str] = None
        self.username: Optional[str] = None
        self.is_demo: bool = False

    @property
    def provider_name(self) -> str:
        return "Generic IMAP (SSL Port 993)"

    @property
    def is_connected(self) -> bool:
        return (self.server is not None) or self.is_demo

    def connect(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Connects to IMAP server over SSL or initializes Demo mode.
        Pass credentials: {'mode': 'demo'} OR {'host': '...', 'username': '...', 'password': '...', 'port': 993}
        """
        mode = credentials.get("mode", "live").lower()
        if mode == "demo":
            self.is_demo = True
            self.host = "demo.imap.enterprise.com"
            self.username = "sec-analyst@enterprise.com"
            return {
                "status": "connected",
                "mode": "demo",
                "email": self.username,
                "host": self.host,
                "provider": self.provider_name
            }

        host = credentials.get("host", "").strip()
        port = int(credentials.get("port", 993))
        username = credentials.get("username", "").strip()
        password = credentials.get("password", "").strip()

        if not host or not username or not password:
            return {"status": "error", "message": "Host, username, and password are required for IMAP connection."}

        try:
            # Enforce SSL port 993
            self.server = imaplib.IMAP4_SSL(host, port)
            self.server.login(username, password)
            self.host = host
            self.username = username
            self.is_demo = False
            return {
                "status": "connected",
                "mode": "live",
                "email": self.username,
                "host": self.host,
                "provider": self.provider_name
            }
        except Exception as e:
            self.server = None
            return {"status": "error", "message": f"IMAP authentication failed: {str(e)}"}

    def list_messages(self, folder: str = "INBOX", query: Optional[str] = None, max_results: int = 20) -> List[Dict[str, Any]]:
        """Lists message headers from IMAP or Demo inbox."""
        if self.is_demo:
            results = self.DEMO_INBOX
            if query:
                q_lower = query.lower()
                results = [
                    m for m in results
                    if q_lower in m["subject"].lower() or q_lower in m["from"].lower() or q_lower in m["snippet"].lower()
                ]
            return [
                {
                    "id": m["id"],
                    "from": m["from"],
                    "from_name": m["from_name"],
                    "to": m["to"],
                    "subject": m["subject"],
                    "date": m["date"],
                    "snippet": m["snippet"],
                    "is_unread": m.get("is_unread", False)
                }
                for m in results[:max_results]
            ]

        if not self.server:
            return []

        try:
            self.server.select(folder, readonly=True)
            search_crit = f'TEXT "{query}"' if query else "ALL"
            status, data = self.server.search(None, search_crit)
            if status != "OK" or not data[0]:
                return []

            msg_ids = data[0].split()
            # Fetch latest messages first
            recent_ids = msg_ids[-max_results:]
            recent_ids.reverse()

            summaries = []
            for m_id in recent_ids:
                status, msg_data = self.server.fetch(m_id, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE TO)])")
                if status == "OK" and msg_data:
                    raw_headers = msg_data[0][1]
                    parsed_headers = email.message_from_bytes(raw_headers)
                    
                    def decode_hdr(val):
                        if not val:
                            return ""
                        decoded_parts = decode_header(val)
                        res = []
                        for text, enc in decoded_parts:
                            if isinstance(text, bytes):
                                res.append(text.decode(enc or "utf-8", errors="replace"))
                            else:
                                res.append(str(text))
                        return "".join(res)

                    from_str = decode_hdr(parsed_headers.get("From", ""))
                    subj_str = decode_hdr(parsed_headers.get("Subject", "No Subject"))
                    date_str = parsed_headers.get("Date", "")
                    to_str = decode_hdr(parsed_headers.get("To", ""))

                    summaries.append({
                        "id": m_id.decode("utf-8"),
                        "from": from_str,
                        "from_name": from_str.split("<")[0].strip(' "'),
                        "to": to_str,
                        "subject": subj_str,
                        "date": date_str,
                        "snippet": f"IMAP Message #{m_id.decode('utf-8')}",
                        "is_unread": False
                    })

            return summaries
        except Exception as e:
            print(f"[!] IMAP list error: {e}")
            return []

    def fetch_raw_message(self, message_id: str) -> str:
        """Fetches the complete raw RFC 822 MIME message from IMAP."""
        if self.is_demo:
            for m in self.DEMO_INBOX:
                if m["id"] == message_id:
                    return m["raw_eml"]
            raise ValueError(f"Message ID {message_id} not found in demo inbox")

        if not self.server:
            raise ValueError("IMAP connector is not connected")

        try:
            self.server.select("INBOX", readonly=True)
            status, data = self.server.fetch(message_id.encode("utf-8"), "(RFC822)")
            if status == "OK" and data and data[0]:
                raw_bytes = data[0][1]
                return raw_bytes.decode("utf-8", errors="replace")
            raise RuntimeError(f"Failed to fetch RFC822 for message {message_id}")
        except Exception as e:
            raise RuntimeError(f"IMAP fetch error: {str(e)}")

    def disconnect(self) -> None:
        """Closes IMAP connection and clears in-memory state."""
        if self.server:
            try:
                self.server.close()
                self.server.logout()
            except Exception:
                pass
        self.server = None
        self.host = None
        self.username = None
        self.is_demo = False
