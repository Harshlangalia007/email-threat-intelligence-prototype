"""
Gmail Mailbox Connector (OAuth 2.0 & REST API) for SIH26106
Integrates with Google Gmail API using read-only scopes and raw MIME message retrieval.
Includes clean Simulated / Demo Mode for instant demonstration.
"""

import base64
import json
import urllib.parse
from typing import Dict, Any, List, Optional
import requests

from engine.mailbox.base import BaseMailboxConnector


class GmailConnector(BaseMailboxConnector):
    """
    Connects to Gmail via Google OAuth 2.0 and Gmail REST API.
    Retrieves full raw RFC 822 MIME messages using format='raw'.
    """

    AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
    SCOPE = "https://www.googleapis.com/auth/gmail.readonly"

    # Pre-packaged demo inbox demonstrating realistic Gmail telemetry and phishing threats
    DEMO_INBOX = [
        {
            "id": "gmail_msg_001",
            "thread_id": "thread_001",
            "from": "security-alert@micros0ft-security-auth.com",
            "from_name": "Microsoft 365 Security Team",
            "to": "analyst.user@gmail.com",
            "subject": "CRITICAL: Immediate Account Verification Required — Access Suspended Within 24 Hours",
            "date": "Tue, 8 Sep 2026 11:22:01 +0000",
            "snippet": "Our security systems detected repeated unauthorized attempts to access your corporate workstation account from Moscow, Russia. Verify credentials immediately...",
            "is_unread": True,
            "labels": ["INBOX", "UNREAD", "IMPORTANT"],
            "raw_eml": """Delivered-To: analyst.user@gmail.com
Received: by 2002:a05:6402:3004:0:0:0:0 with SMTP id b4csp239104plk;
        Tue, 8 Sep 2026 04:22:11 -0700 (PDT)
X-Received: by 2002:a17:906:8552:b0:994:ef41:1201 with SMTP id n18-20020a170906855200b00994ef411201mr9120349ejk.8.1694172131000;
        Tue, 8 Sep 2026 04:22:11 -0700 (PDT)
Return-Path: <bounce-daemon@micros0ft-security-auth.com>
Received: from mail.micros0ft-security-auth.com (mail.micros0ft-security-auth.com [185.220.101.5])
        by mx.google.com with ESMTP id q19si8321049plk.2026.09.08.04.22.10
        for <analyst.user@gmail.com>;
        Tue, 8 Sep 2026 04:22:10 -0700 (PDT)
Received-SPF: fail (google.com: domain of bounce-daemon@micros0ft-security-auth.com does not designate 185.220.101.5 as permitted sender) client-ip=185.220.101.5;
Authentication-Results: mx.google.com;
       dkim=fail reason="signature verification failed" header.i=@micros0ft-security-auth.com;
       spf=fail (google.com: domain of bounce-daemon@micros0ft-security-auth.com does not designate 185.220.101.5 as permitted sender) smtp.mailfrom=bounce-daemon@micros0ft-security-auth.com;
       dmarc=fail (p=REJECT dis=REJECT) header.from=microsoft.com
From: "Microsoft 365 Security Team" <security-alert@micros0ft-security-auth.com>
Reply-To: "M365 Identity Support" <auth-escalations@micros0ft-security-auth.com>
To: <analyst.user@gmail.com>
Subject: CRITICAL: Immediate Account Verification Required — Access Suspended Within 24 Hours
Date: Tue, 8 Sep 2026 11:22:01 +0000
Message-ID: <20260908112201.A392FF1902@mail.micros0ft-security-auth.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body>
  <h2>Urgent Notice: Unusual Sign-in Detected</h2>
  <p>Our security systems detected repeated unauthorized attempts to access your account.</p>
  <p>Verify your credentials within 24 hours to prevent account lockout:</p>
  <p><a href="https://login.micros0ft-security-auth.com/owa/auth/verify.php?token=938029148">Verify Identity Now</a></p>
</body>
</html>
"""
        },
        {
            "id": "gmail_msg_002",
            "thread_id": "thread_002",
            "from": "sarah.jenkins@acmepartners.com",
            "from_name": "Sarah Jenkins",
            "to": "analyst.user@gmail.com",
            "subject": "Q3 Architecture Sync & Project Status Review",
            "date": "Mon, 7 Sep 2026 09:14:22 -0700",
            "snippet": "Hi Team, Hope you had a great weekend. Attached is our scheduled status report for the Q3 SIH cybersecurity project milestones...",
            "is_unread": False,
            "labels": ["INBOX", "WORK"],
            "raw_eml": """Delivered-To: analyst.user@gmail.com
Received: by 2002:a05:6e02:18c4:0:0:0:0 with SMTP id v4csp1290941ilq;
        Mon, 7 Sep 2026 09:14:22 -0700 (PDT)
Return-Path: <sarah.jenkins@acmepartners.com>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.google.com with SMTPS id s12sor239401plk.14.2026.09.07.09.14.21
        for <analyst.user@gmail.com>;
        Mon, 7 Sep 2026 09:14:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of sarah.jenkins@acmepartners.com designates 209.85.220.41 as permitted sender) client-ip=209.85.220.41;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@acmepartners.com header.s=google;
       spf=pass;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acmepartners.com
From: "Sarah Jenkins" <sarah.jenkins@acmepartners.com>
To: <analyst.user@gmail.com>
Subject: Q3 Architecture Sync & Project Status Review
Date: Mon, 7 Sep 2026 12:14:15 -0400
Message-ID: <CABp=mO_943029482039@mail.acmepartners.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi Team,

Hope you had a great weekend. Attached is our scheduled status report for the Q3 SIH cybersecurity project milestones.

Please review the notes before our sync this Thursday at 2:00 PM EST.

Best regards,
Sarah Jenkins
"""
        },
        {
            "id": "gmail_msg_003",
            "thread_id": "thread_003",
            "from": "david.sterling@cyberdefense-corp.com",
            "from_name": "David Sterling [CEO]",
            "to": "analyst.user@gmail.com",
            "subject": "STRICTLY CONFIDENTIAL // Time-Sensitive Acquisition Wire Transfer",
            "date": "Mon, 7 Sep 2026 19:45:02 -0400",
            "snippet": "Hi Richard, Are you at your desk right now? I am currently locked in an all-day executive board meeting regarding a time-sensitive acquisition and cannot take calls...",
            "is_unread": True,
            "labels": ["INBOX", "UNREAD"],
            "raw_eml": """Delivered-To: analyst.user@gmail.com
Received: by 2002:a05:6808:1441:0:0:0:0 with SMTP id b1csp9410298eji;
        Mon, 7 Sep 2026 16:45:10 -0700 (PDT)
Return-Path: <exec-dispatch@executive-privatemail.top>
Received: from vps-relay14.bulletproof-transit.nl (vps-relay14.bulletproof-transit.nl [194.36.191.12])
        by mx.google.com with ESMTP id m12si9201481plk.2026.09.07.16.45.09
        for <analyst.user@gmail.com>;
        Mon, 7 Sep 2026 16:45:09 -0700 (PDT)
Received-SPF: softfail (google.com: transitioning domain of executive-privatemail.top does not designate 194.36.191.12 as permitted sender) client-ip=194.36.191.12;
Authentication-Results: mx.google.com;
       spf=softfail;
       dkim=fail;
       dmarc=fail (p=NONE dis=NONE) header.from=cyberdefense-corp.com
From: "David Sterling [CEO]" <david.sterling@cyberdefense-corp.com>
Reply-To: "David Sterling" <exec-privatemail892@gmail.com>
To: <analyst.user@gmail.com>
Subject: STRICTLY CONFIDENTIAL // Time-Sensitive Acquisition Wire Transfer
Date: Mon, 7 Sep 2026 19:45:02 -0400
Message-ID: <9480194810294.20260907@executive-privatemail.top>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi Richard,

Are you at your desk right now? 

I am currently locked in an all-day executive board meeting regarding a time-sensitive acquisition and cannot take calls on my cell. 

We need to execute an urgent initial wire transfer of $84,500.00 today before the bank closing window (5:00 PM EST) to finalize the escrow retainer. 

Reply back immediately to confirm you can process this direct wire transfer right now.

David Sterling
Chief Executive Officer | CyberDefense Corp
"""
        }
    ]

    def __init__(self):
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.user_email: Optional[str] = None
        self.is_demo: bool = False

    @property
    def provider_name(self) -> str:
        return "Gmail (Google Workspace)"

    @property
    def is_connected(self) -> bool:
        return bool(self.access_token) or self.is_demo

    def build_auth_url(self, client_id: str, redirect_uri: str, state: str = "gmail_oauth") -> str:
        """Constructs Google OAuth 2.0 authorization URL for read-only Gmail access."""
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": self.SCOPE,
            "access_type": "offline",
            "prompt": "consent",
            "state": state
        }
        return f"{self.AUTH_URL}?{urllib.parse.urlencode(params)}"

    def connect(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Connects using OAuth code exchange, direct access token, or demo mode.
        """
        mode = credentials.get("mode", "live").lower()
        if mode == "demo":
            self.is_demo = True
            self.user_email = "soc-analyst-demo@gmail.com"
            return {
                "status": "connected",
                "mode": "demo",
                "email": self.user_email,
                "scope": self.SCOPE,
                "provider": self.provider_name
            }

        # Live OAuth code exchange
        code = credentials.get("code")
        client_id = credentials.get("client_id")
        client_secret = credentials.get("client_secret")
        redirect_uri = credentials.get("redirect_uri")

        if code and client_id and client_secret and redirect_uri:
            resp = requests.post(self.TOKEN_URL, data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code"
            })
            if resp.status_code == 200:
                token_data = resp.json()
                self.access_token = token_data.get("access_token")
                self.refresh_token = token_data.get("refresh_token")
                self.is_demo = False
                
                # Fetch user profile
                prof_resp = requests.get(
                    f"{self.API_BASE}/profile",
                    headers={"Authorization": f"Bearer {self.access_token}"}
                )
                if prof_resp.status_code == 200:
                    self.user_email = prof_resp.json().get("emailAddress")

                return {
                    "status": "connected",
                    "mode": "live",
                    "email": self.user_email or "authorized_account@gmail.com",
                    "scope": self.SCOPE,
                    "provider": self.provider_name
                }
            else:
                return {"status": "error", "message": f"OAuth token exchange failed: {resp.text}"}

        # Direct token mode
        token = credentials.get("access_token")
        if token:
            self.access_token = token
            self.is_demo = False
            return {
                "status": "connected",
                "mode": "live",
                "email": credentials.get("email", "authorized_account@gmail.com"),
                "scope": self.SCOPE,
                "provider": self.provider_name
            }

        return {"status": "error", "message": "Invalid connection parameters"}

    def list_messages(self, folder: str = "INBOX", query: Optional[str] = None, max_results: int = 20) -> List[Dict[str, Any]]:
        """Lists message summaries from Gmail or Demo inbox."""
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
                    "is_unread": m["is_unread"],
                    "labels": m["labels"]
                }
                for m in results[:max_results]
            ]

        if not self.access_token:
            return []

        headers = {"Authorization": f"Bearer {self.access_token}"}
        params = {"maxResults": max_results}
        if query:
            params["q"] = query

        list_resp = requests.get(f"{self.API_BASE}/messages", headers=headers, params=params)
        if list_resp.status_code != 200:
            return []

        msg_stubs = list_resp.json().get("messages", [])
        summaries = []

        # Batch/individual fetch metadata format
        for stub in msg_stubs[:max_results]:
            m_id = stub.get("id")
            meta_resp = requests.get(
                f"{self.API_BASE}/messages/{m_id}?format=metadata&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Subject&metadataHeaders=Date",
                headers=headers
            )
            if meta_resp.status_code == 200:
                m_data = meta_resp.json()
                headers_dict = {h["name"].lower(): h["value"] for h in m_data.get("payload", {}).get("headers", [])}
                summaries.append({
                    "id": m_id,
                    "from": headers_dict.get("from", "Unknown"),
                    "from_name": headers_dict.get("from", "Unknown").split("<")[0].strip(' "'),
                    "to": headers_dict.get("to", ""),
                    "subject": headers_dict.get("subject", "No Subject"),
                    "date": headers_dict.get("date", ""),
                    "snippet": m_data.get("snippet", ""),
                    "is_unread": "UNREAD" in m_data.get("labelIds", []),
                    "labels": m_data.get("labelIds", [])
                })

        return summaries

    def fetch_raw_message(self, message_id: str) -> str:
        """Retrieves raw RFC 822 MIME text for the selected message ID."""
        if self.is_demo:
            for m in self.DEMO_INBOX:
                if m["id"] == message_id:
                    return m["raw_eml"]
            raise ValueError(f"Message ID {message_id} not found in demo mailbox")

        if not self.access_token:
            raise ValueError("Gmail connector is not authenticated")

        headers = {"Authorization": f"Bearer {self.access_token}"}
        resp = requests.get(f"{self.API_BASE}/messages/{message_id}?format=raw", headers=headers)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch message {message_id} from Gmail API: {resp.text}")

        raw_b64 = resp.json().get("raw", "")
        # Gmail API uses base64url encoding (- and _ instead of + and /)
        raw_bytes = base64.urlsafe_b64decode(raw_b64 + "==")
        return raw_bytes.decode("utf-8", errors="replace")

    def disconnect(self) -> None:
        """Revokes tokens and clears connection state."""
        if self.access_token and not self.is_demo:
            try:
                requests.post(f"https://oauth2.googleapis.com/revoke?token={self.access_token}", timeout=2)
            except Exception:
                pass
        self.access_token = None
        self.refresh_token = None
        self.user_email = None
        self.is_demo = False
