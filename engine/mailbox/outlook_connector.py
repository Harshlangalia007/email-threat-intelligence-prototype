"""
Outlook / Microsoft 365 Mailbox Connector (Microsoft Graph API & OAuth 2.0) for SIH26106
Integrates with Microsoft Graph using Mail.Read read-only scope and messages/{id}/$value raw MIME endpoint.
Includes clean Simulated / Demo Mode for immediate evaluation.
"""

import json
import urllib.parse
from typing import Dict, Any, List, Optional
import requests

from engine.mailbox.base import BaseMailboxConnector


class OutlookConnector(BaseMailboxConnector):
    """
    Connects to Microsoft 365 / Outlook via Microsoft Graph API and OAuth 2.0.
    Fetches raw RFC 822 MIME content via https://graph.microsoft.com/v1.0/me/messages/{id}/$value.
    """

    AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    API_BASE = "https://graph.microsoft.com/v1.0/me"
    SCOPE = "https://graph.microsoft.com/Mail.Read offline_access openid profile"

    # Pre-packaged demo inbox representing realistic enterprise Microsoft 365 telemetry
    DEMO_INBOX = [
        {
            "id": "outlook_msg_101",
            "from": "billing@cloud-billing-portal.xyz",
            "from_name": "Accounts Payable Notification",
            "to": "corporate.analyst@cyberdefense-corp.com",
            "subject": "OVERDUE INVOICE #INV-2026-8941 — FINAL NOTICE BEFORE LEGAL DISPUTE",
            "date": "Tue, 8 Sep 2026 15:10:52 +0000",
            "snippet": "Accounts Payable, Your organization has failed to remit settlement for past-due invoice #INV-2026-8941 ($14,280.00). Attached is calculation...",
            "is_unread": True,
            "has_attachments": True,
            "raw_eml": """Delivered-To: corporate.analyst@cyberdefense-corp.com
Received: by 2002:a05:6808:9921:0:0:0:0 with SMTP id c8csp1029482pli;
        Tue, 8 Sep 2026 08:11:02 -0700 (PDT)
Return-Path: <invoicing@cloud-billing-portal.xyz>
Received: from c2-host88.bulletproof-transit.nl (c2-host88.bulletproof-transit.nl [45.154.255.88])
        by outlook.office365.com with ESMTP id k44si1029381plk.2026.09.08.08.11.01
        for <corporate.analyst@cyberdefense-corp.com>;
        Tue, 8 Sep 2026 08:11:01 -0700 (PDT)
Received-SPF: fail (outlook.office365.com: domain of cloud-billing-portal.xyz does not designate 45.154.255.88 as permitted sender);
Authentication-Results: spf=fail; dkim=fail; dmarc=fail;
From: "Accounts Payable Notification" <billing@cloud-billing-portal.xyz>
To: <corporate.analyst@cyberdefense-corp.com>
Subject: OVERDUE INVOICE #INV-2026-8941 — FINAL NOTICE BEFORE LEGAL DISPUTE
Date: Tue, 8 Sep 2026 15:10:52 +0000
Message-ID: <INV94819401.2026@cloud-billing-portal.xyz>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_98241_209148"

------=_Part_98241_209148
Content-Type: text/plain; charset="UTF-8"

Accounts Payable,

Your organization has failed to remit settlement for past-due invoice #INV-2026-8941 ($14,280.00).

Review the attached overdue invoice calculation immediately before legal escalation.

------=_Part_98241_209148
Content-Type: application/octet-stream; name="Invoice_INV-8941_Overdue.pdf.exe"
Content-Disposition: attachment; filename="Invoice_INV-8941_Overdue.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAyAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v
ZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAAAAAAAA
------=_Part_98241_209148--
"""
        },
        {
            "id": "outlook_msg_102",
            "from": "david.sterling@cyberdefense-corp.com",
            "from_name": "David Sterling [CEO]",
            "to": "corporate.analyst@cyberdefense-corp.com",
            "subject": "STRICTLY CONFIDENTIAL // Time-Sensitive Acquisition Wire Transfer",
            "date": "Mon, 7 Sep 2026 19:45:02 -0400",
            "snippet": "Are you at your desk right now? I am currently locked in an all-day executive board meeting regarding a time-sensitive acquisition and cannot take calls...",
            "is_unread": True,
            "has_attachments": False,
            "raw_eml": """Delivered-To: corporate.analyst@cyberdefense-corp.com
Received: from vps-relay14.bulletproof-transit.nl (vps-relay14.bulletproof-transit.nl [194.36.191.12])
        by outlook.office365.com with ESMTP id m12si9201481plk.2026.09.07.16.45.09
        for <corporate.analyst@cyberdefense-corp.com>;
        Mon, 7 Sep 2026 16:45:09 -0700 (PDT)
Return-Path: <exec-dispatch@executive-privatemail.top>
Received-SPF: softfail;
Authentication-Results: spf=softfail; dkim=fail; dmarc=fail header.from=cyberdefense-corp.com
From: "David Sterling [CEO]" <david.sterling@cyberdefense-corp.com>
Reply-To: "David Sterling" <exec-privatemail892@gmail.com>
To: <corporate.analyst@cyberdefense-corp.com>
Subject: STRICTLY CONFIDENTIAL // Time-Sensitive Acquisition Wire Transfer
Date: Mon, 7 Sep 2026 19:45:02 -0400
Message-ID: <9480194810294.20260907@executive-privatemail.top>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi Team,

We need to execute an urgent initial wire transfer of $84,500.00 today before the bank closing window (5:00 PM EST) to finalize the escrow retainer. 

Please keep this strictly confidential between us for now. Reply back immediately to confirm.

David Sterling
Chief Executive Officer | CyberDefense Corp
"""
        },
        {
            "id": "outlook_msg_103",
            "from": "sarah.jenkins@acmepartners.com",
            "from_name": "Sarah Jenkins",
            "to": "corporate.analyst@cyberdefense-corp.com",
            "subject": "Acme Corp / CyberDefense Quarterly Integration Architecture",
            "date": "Mon, 7 Sep 2026 12:14:15 -0400",
            "snippet": "Attached is our scheduled status report for the Q3 SIH cybersecurity project milestones. Please review before our sync this Thursday...",
            "is_unread": False,
            "has_attachments": False,
            "raw_eml": """Delivered-To: corporate.analyst@cyberdefense-corp.com
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by outlook.office365.com with SMTPS id s12sor239401plk.14.2026.09.07.09.14.21
        for <corporate.analyst@cyberdefense-corp.com>;
        Mon, 7 Sep 2026 09:14:21 -0700 (PDT)
Return-Path: <sarah.jenkins@acmepartners.com>
Received-SPF: pass client-ip=209.85.220.41;
Authentication-Results: dkim=pass header.i=@acmepartners.com; spf=pass; dmarc=pass header.from=acmepartners.com
DKIM-Signature: v=1; a=rsa-sha256; d=acmepartners.com; s=m365;
From: "Sarah Jenkins" <sarah.jenkins@acmepartners.com>
To: <corporate.analyst@cyberdefense-corp.com>
Subject: Acme Corp / CyberDefense Quarterly Integration Architecture
Date: Mon, 7 Sep 2026 12:14:15 -0400
Message-ID: <CABp=mO_943029482039@mail.acmepartners.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi Team,

Review the notes for our Thursday architecture sync:
https://wiki.acmepartners.com/projects/cyber-architecture

Best regards,
Sarah Jenkins
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
        return "Outlook / Microsoft 365"

    @property
    def is_connected(self) -> bool:
        return bool(self.access_token) or self.is_demo

    def build_auth_url(self, client_id: str, redirect_uri: str, tenant: str = "common", state: str = "outlook_oauth") -> str:
        """Constructs Microsoft Azure AD OAuth 2.0 authorization URL for Mail.Read access."""
        url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
        params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": self.SCOPE,
            "state": state
        }
        return f"{url}?{urllib.parse.urlencode(params)}"

    def connect(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Connects using OAuth code exchange, direct token, or demo mode."""
        mode = credentials.get("mode", "live").lower()
        if mode == "demo":
            self.is_demo = True
            self.user_email = "analyst@enterprise365.onmicrosoft.com"
            return {
                "status": "connected",
                "mode": "demo",
                "email": self.user_email,
                "scope": "Mail.Read (Read-Only)",
                "provider": self.provider_name
            }

        code = credentials.get("code")
        client_id = credentials.get("client_id")
        client_secret = credentials.get("client_secret")
        redirect_uri = credentials.get("redirect_uri")
        tenant = credentials.get("tenant", "common")

        if code and client_id and client_secret and redirect_uri:
            token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
            resp = requests.post(token_url, data={
                "client_id": client_id,
                "scope": self.SCOPE,
                "code": code,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "client_secret": client_secret
            })
            if resp.status_code == 200:
                t_data = resp.json()
                self.access_token = t_data.get("access_token")
                self.refresh_token = t_data.get("refresh_token")
                self.is_demo = False

                # Fetch user email from Graph API
                me_resp = requests.get(self.API_BASE, headers={"Authorization": f"Bearer {self.access_token}"})
                if me_resp.status_code == 200:
                    me_json = me_resp.json()
                    self.user_email = me_json.get("mail") or me_json.get("userPrincipalName")

                return {
                    "status": "connected",
                    "mode": "live",
                    "email": self.user_email or "authorized@office365.com",
                    "scope": "Mail.Read",
                    "provider": self.provider_name
                }
            else:
                return {"status": "error", "message": f"Microsoft OAuth token exchange failed: {resp.text}"}

        token = credentials.get("access_token")
        if token:
            self.access_token = token
            self.is_demo = False
            return {
                "status": "connected",
                "mode": "live",
                "email": credentials.get("email", "authorized@office365.com"),
                "scope": "Mail.Read",
                "provider": self.provider_name
            }

        return {"status": "error", "message": "Invalid credentials provided"}

    def list_messages(self, folder: str = "INBOX", query: Optional[str] = None, max_results: int = 20) -> List[Dict[str, Any]]:
        """Lists message headers from Outlook 365 or Demo inbox."""
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
                    "has_attachments": m.get("has_attachments", False)
                }
                for m in results[:max_results]
            ]

        if not self.access_token:
            return []

        headers = {"Authorization": f"Bearer {self.access_token}"}
        url = f"{self.API_BASE}/mailFolders/inbox/messages?$top={max_results}&$select=id,subject,from,toRecipients,receivedDateTime,bodyPreview,isRead,hasAttachments"
        if query:
            url += f"&$search=\"{urllib.parse.quote(query)}\""

        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            return []

        raw_items = resp.json().get("value", [])
        results = []
        for item in raw_items:
            f_obj = item.get("from", {}).get("emailAddress", {})
            to_recips = [t.get("emailAddress", {}).get("address", "") for t in item.get("toRecipients", [])]
            results.append({
                "id": item.get("id"),
                "from": f_obj.get("address", ""),
                "from_name": f_obj.get("name", ""),
                "to": ", ".join(to_recips),
                "subject": item.get("subject", "No Subject"),
                "date": item.get("receivedDateTime", ""),
                "snippet": item.get("bodyPreview", ""),
                "is_unread": not item.get("isRead", True),
                "has_attachments": item.get("hasAttachments", False)
            })

        return results

    def fetch_raw_message(self, message_id: str) -> str:
        """
        Fetches the complete RFC 822 MIME message using Microsoft Graph's native $value endpoint:
        GET /v1.0/me/messages/{id}/$value
        """
        if self.is_demo:
            for m in self.DEMO_INBOX:
                if m["id"] == message_id:
                    return m["raw_eml"]
            raise ValueError(f"Message ID {message_id} not found in demo mailbox")

        if not self.access_token:
            raise ValueError("Outlook connector is not authenticated")

        headers = {"Authorization": f"Bearer {self.access_token}"}
        url = f"{self.API_BASE}/messages/{message_id}/$value"
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch raw MIME from Microsoft Graph API: {resp.text}")

        # Returns raw MIME byte string directly
        return resp.content.decode("utf-8", errors="replace")

    def disconnect(self) -> None:
        """Clears session tokens."""
        self.access_token = None
        self.refresh_token = None
        self.user_email = None
        self.is_demo = False
