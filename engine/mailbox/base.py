"""
Base Mailbox Connector Interface for SIH26106
Defines standard contracts for retrieving raw RFC 822 / 5322 MIME messages from mail servers.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional


class BaseMailboxConnector(ABC):
    """Abstract base class for email mailbox providers."""

    @abstractmethod
    def connect(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Authenticates and connects to the mailbox service.
        Returns connection status details.
        """
        pass

    @abstractmethod
    def list_messages(self, folder: str = "INBOX", query: Optional[str] = None, max_results: int = 20) -> List[Dict[str, Any]]:
        """
        Lists summary metadata of messages in the mailbox (Sender, Subject, Date, Snippet).
        Does not fetch heavy message bodies.
        """
        pass

    @abstractmethod
    def fetch_raw_message(self, message_id: str) -> str:
        """
        Fetches the complete raw RFC 822 / 5322 MIME string for a specific message,
        including all original SMTP headers and raw multipart body.
        """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Closes connection and clears session tokens/credentials."""
        pass

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """Returns True if the connector currently holds an active authorized session."""
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Returns the human-readable name of the provider (e.g. Gmail, Outlook, IMAP)."""
        pass
