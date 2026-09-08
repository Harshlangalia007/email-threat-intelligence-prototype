"""
Unified Mailbox Session Manager for SIH26106
Coordinates Gmail, Outlook, and IMAP connectors under a single unified interface.
"""

from typing import Dict, Any, List, Optional
from engine.mailbox.base import BaseMailboxConnector
from engine.mailbox.gmail_connector import GmailConnector
from engine.mailbox.outlook_connector import OutlookConnector
from engine.mailbox.imap_connector import IMAPConnector


class MailboxManager:
    """Manages active email mailbox sessions and providers."""

    _instance = None

    def __init__(self):
        self.connectors: Dict[str, BaseMailboxConnector] = {
            "gmail": GmailConnector(),
            "outlook": OutlookConnector(),
            "imap": IMAPConnector()
        }
        self.active_provider: Optional[str] = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_active_connector(self) -> Optional[BaseMailboxConnector]:
        if self.active_provider and self.active_provider in self.connectors:
            return self.connectors[self.active_provider]
        return None

    def connect(self, provider: str, credentials: Dict[str, Any]) -> Dict[str, Any]:
        p = provider.lower().strip()
        if p not in self.connectors:
            return {"status": "error", "message": f"Unsupported mailbox provider: {provider}"}

        connector = self.connectors[p]
        res = connector.connect(credentials)
        if res.get("status") == "connected":
            self.active_provider = p
        return res

    def list_messages(self, query: Optional[str] = None, max_results: int = 20) -> List[Dict[str, Any]]:
        connector = self.get_active_connector()
        if not connector or not connector.is_connected:
            return []
        return connector.list_messages(query=query, max_results=max_results)

    def fetch_raw_message(self, message_id: str) -> str:
        connector = self.get_active_connector()
        if not connector or not connector.is_connected:
            raise RuntimeError("No mailbox provider currently connected")
        return connector.fetch_raw_message(message_id)

    def disconnect(self) -> Dict[str, Any]:
        if self.active_provider and self.active_provider in self.connectors:
            self.connectors[self.active_provider].disconnect()
        prev = self.active_provider
        self.active_provider = None
        return {"status": "disconnected", "previous_provider": prev}

    def get_status(self) -> Dict[str, Any]:
        connector = self.get_active_connector()
        if connector and connector.is_connected:
            return {
                "connected": True,
                "provider": self.active_provider,
                "provider_name": connector.provider_name,
                "is_demo": getattr(connector, "is_demo", False),
                "email": getattr(connector, "user_email", getattr(connector, "username", "Active Session"))
            }
        return {
            "connected": False,
            "provider": None,
            "provider_name": "None",
            "is_demo": False,
            "email": None
        }
