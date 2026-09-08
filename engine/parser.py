"""
RFC 5322 & MIME Email Parser Engine for SIH26106
Extracts structured headers, multipart bodies, attachment metadata, and URLs.
"""

import email
from email import policy
from email.utils import parseaddr, getaddresses
import re
import hashlib
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from typing import Dict, Any, List, Optional


class EmailParser:
    """Parses raw .eml RFC 5322 text or bytes into a rich structured representation."""

    URL_REGEX = re.compile(
        r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s<>"\'`{}\\]*)?',
        re.IGNORECASE
    )

    DANGEROUS_EXTENSIONS = {
        '.exe', '.scr', '.vbs', '.hta', '.bat', '.cmd', '.ps1', '.js', '.wsf',
        '.iso', '.img', '.dll', '.jar', '.xlsm', '.docm', '.pptm', '.zip', '.rar', '.7z'
    }

    def __init__(self):
        pass

    def parse_raw_eml(self, raw_content: str) -> Dict[str, Any]:
        """
        Parses raw .eml string into structured email metadata.
        """
        if isinstance(raw_content, str):
            msg = email.message_from_string(raw_content, policy=policy.default)
        else:
            msg = email.message_from_bytes(raw_content, policy=policy.default)

        # 1. Primary Headers
        headers = {}
        for key in msg.keys():
            all_v = msg.get_all(key)
            headers[key] = all_v if (all_v and len(all_v) > 1) else msg.get(key)

        from_raw = msg.get("From", "")
        from_name, from_email = parseaddr(from_raw)
        
        reply_to_raw = msg.get("Reply-To", "")
        reply_to_name, reply_to_email = parseaddr(reply_to_raw)

        to_raw = msg.get("To", "")
        to_addresses = [addr for _, addr in getaddresses([to_raw])] if to_raw else []

        cc_raw = msg.get("Cc", "")
        cc_addresses = [addr for _, addr in getaddresses([cc_raw])] if cc_raw else []

        return_path = msg.get("Return-Path", "")
        if return_path:
            return_path = return_path.strip("<> \t\r\n")

        subject = msg.get("Subject", "")
        date_str = msg.get("Date", "")
        message_id = msg.get("Message-ID", "")
        x_mailer = msg.get("X-Mailer", "") or msg.get("User-Agent", "")

        # Extract domains
        from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""
        reply_to_domain = reply_to_email.split("@")[-1].lower() if "@" in reply_to_email else ""
        return_path_domain = return_path.split("@")[-1].lower() if "@" in return_path else ""

        # 2. Authentication Headers
        auth_results = msg.get("Authentication-Results", "")
        received_spf = msg.get("Received-SPF", "")
        dkim_signatures = msg.get_all("DKIM-Signature", [])
        arc_auth = msg.get("ARC-Authentication-Results", "")

        # 3. Received Headers (Ordered from earliest hop to destination)
        received_headers = msg.get_all("Received", [])
        if not received_headers:
            received_headers = []
            for k, v in msg.items():
                if k.lower() == "received":
                    received_headers.append(str(v))

        # 4. Extract Body (Plain text & HTML)
        body_plain = ""
        body_html = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition.lower() or part.get_filename():
                    att = self._extract_attachment_info(part)
                    if att:
                        attachments.append(att)
                elif content_type == "text/plain" and not body_plain:
                    try:
                        body_plain = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                    except Exception:
                        body_plain = str(part.get_payload())
                elif content_type == "text/html" and not body_html:
                    try:
                        body_html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                    except Exception:
                        body_html = str(part.get_payload())
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            text_payload = payload.decode(msg.get_content_charset() or "utf-8", errors="replace") if payload else ""
            if content_type == "text/html":
                body_html = text_payload
            else:
                body_plain = text_payload

        # Clean body text for NLP/heuristics
        effective_text = body_plain
        if not effective_text and body_html:
            soup = BeautifulSoup(body_html, "html.parser")
            effective_text = soup.get_text(separator="\n")

        # 5. Extract URLs safely (without fetching)
        urls = self._extract_urls(body_plain, body_html)

        return {
            "headers": headers,
            "raw_received": received_headers,
            "identity": {
                "from_raw": from_raw,
                "from_name": from_name,
                "from_email": from_email,
                "from_domain": from_domain,
                "reply_to_raw": reply_to_raw,
                "reply_to_name": reply_to_name,
                "reply_to_email": reply_to_email,
                "reply_to_domain": reply_to_domain,
                "return_path": return_path,
                "return_path_domain": return_path_domain,
                "to": to_addresses,
                "cc": cc_addresses,
                "subject": subject,
                "date": date_str,
                "message_id": message_id,
                "x_mailer": x_mailer
            },
            "auth_headers": {
                "authentication_results": auth_results,
                "received_spf": received_spf,
                "dkim_signatures": dkim_signatures,
                "arc_authentication_results": arc_auth
            },
            "body": {
                "plain": body_plain,
                "html": body_html,
                "effective_text": effective_text,
                "has_html": bool(body_html)
            },
            "attachments": attachments,
            "urls": urls
        }

    def _extract_attachment_info(self, part) -> Optional[Dict[str, Any]]:
        filename = part.get_filename() or "untitled_attachment"
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True)
        size_bytes = len(payload) if payload else 0
        
        sha256 = ""
        if payload:
            sha256 = hashlib.sha256(payload).hexdigest()

        ext = ""
        if "." in filename:
            ext = "." + filename.rsplit(".", 1)[-1].lower()
            
        is_suspicious = ext in self.DANGEROUS_EXTENSIONS

        return {
            "filename": filename,
            "content_type": content_type,
            "size_bytes": size_bytes,
            "sha256": sha256,
            "extension": ext,
            "is_suspicious": is_suspicious
        }

    def _extract_urls(self, body_plain: str, body_html: str) -> List[Dict[str, Any]]:
        url_map = {}

        if body_plain:
            for match in self.URL_REGEX.finditer(body_plain):
                url = match.group(0).rstrip(".,)>]\"'")
                if url not in url_map:
                    url_map[url] = {"url": url, "source": "plaintext", "anchor_text": ""}

        if body_html:
            try:
                soup = BeautifulSoup(body_html, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith("http://") or href.startswith("https://"):
                        anchor_text = a.get_text().strip()
                        if href not in url_map:
                            url_map[href] = {"url": href, "source": "html_anchor", "anchor_text": anchor_text}
                        else:
                            url_map[href]["anchor_text"] = anchor_text
            except Exception:
                pass

        results = []
        for url, data in url_map.items():
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if ":" in domain:
                domain = domain.split(":")[0]

            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))

            results.append({
                "url": url,
                "domain": domain,
                "path": parsed.path,
                "query": parsed.query,
                "scheme": parsed.scheme,
                "source": data["source"],
                "anchor_text": data.get("anchor_text", ""),
                "is_ip_domain": is_ip
            })

        return results
