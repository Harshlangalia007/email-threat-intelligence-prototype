"""
Mailbox Integration Package for SIH26106
Exposes Gmail, Outlook, IMAP connectors and MailboxManager.
"""

from engine.mailbox.base import BaseMailboxConnector
from engine.mailbox.gmail_connector import GmailConnector
from engine.mailbox.outlook_connector import OutlookConnector
from engine.mailbox.imap_connector import IMAPConnector
from engine.mailbox.manager import MailboxManager

__all__ = [
    "BaseMailboxConnector",
    "GmailConnector",
    "OutlookConnector",
    "IMAPConnector",
    "MailboxManager"
]
