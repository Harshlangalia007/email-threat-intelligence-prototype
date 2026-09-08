"""
Local Investigation Case Storage Engine (SQLite) for SIH26106
Persists case dossiers, metrics, and investigation telemetry for SOC audit and review.
"""

import sqlite3
import json
import os
import time
import uuid
from typing import Dict, Any, List, Optional


class CaseStore:
    """Manages SQLite persistence for investigation dossiers."""

    def __init__(self, db_path: str = "cases.db"):
        self.db_path = db_path
        self._memory_conn = None
        if self.db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_conn(self):
        if self._memory_conn:
            return self._memory_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    timestamp REAL,
                    date_str TEXT,
                    subject TEXT,
                    sender_email TEXT,
                    sender_domain TEXT,
                    classification TEXT,
                    risk_score INTEGER,
                    risk_level TEXT,
                    confidence INTEGER,
                    origin_ip TEXT,
                    origin_country TEXT,
                    origin_asn TEXT,
                    total_hops INTEGER,
                    total_urls INTEGER,
                    has_attachments INTEGER,
                    full_dossier_json TEXT
                )
            """)
            conn.commit()

    def save_case(self, dossier: Dict[str, Any]) -> str:
        case_id = dossier.get("case_id") or f"CASE-{int(time.time())}-{uuid.uuid4().hex[:4].upper()}"
        dossier["case_id"] = case_id
        ts = time.time()
        date_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))

        ident = dossier.get("parsed_email", {}).get("identity", {})
        threat = dossier.get("threat_detection", {})
        forensic = dossier.get("forensic_investigation", {})
        relay = forensic.get("relay_path", {})
        origin = relay.get("origin_mta", {}) or {}

        with self._get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO cases (
                    case_id, timestamp, date_str, subject, sender_email, sender_domain,
                    classification, risk_score, risk_level, confidence, origin_ip,
                    origin_country, origin_asn, total_hops, total_urls, has_attachments,
                    full_dossier_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                case_id,
                ts,
                date_str,
                ident.get("subject", "No Subject"),
                ident.get("from_email", "unknown"),
                ident.get("from_domain", "unknown"),
                threat.get("classification", "Unknown"),
                threat.get("risk_score", 0),
                threat.get("risk_level", "INFO"),
                threat.get("confidence", 0),
                origin.get("ip", "N/A"),
                origin.get("country", "Unknown"),
                origin.get("asn", "N/A"),
                relay.get("total_hops", 0),
                len(dossier.get("parsed_email", {}).get("urls", [])),
                1 if dossier.get("parsed_email", {}).get("attachments") else 0,
                json.dumps(dossier)
            ))
            conn.commit()
        return case_id

    def list_cases(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute("""
                SELECT case_id, timestamp, date_str, subject, sender_email, sender_domain,
                       classification, risk_score, risk_level, confidence, origin_ip,
                       origin_country, origin_asn, total_hops, total_urls, has_attachments
                FROM cases
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute("SELECT full_dossier_json FROM cases WHERE case_id = ?", (case_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row["full_dossier_json"])
        return None

    def get_soc_metrics(self) -> Dict[str, Any]:
        with self._get_conn() as conn:
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_analyzed,
                    SUM(CASE WHEN risk_score >= 75 THEN 1 ELSE 0 END) as high_risk_count,
                    SUM(CASE WHEN classification = 'Phishing' THEN 1 ELSE 0 END) as phishing_count,
                    SUM(CASE WHEN classification = 'Business Email Compromise (BEC)' THEN 1 ELSE 0 END) as bec_count,
                    SUM(CASE WHEN classification = 'Malware Delivery' THEN 1 ELSE 0 END) as malware_count,
                    COUNT(DISTINCT sender_domain) as distinct_domains,
                    COUNT(DISTINCT origin_ip) as distinct_ips
                FROM cases
            """)
            row = dict(cursor.fetchone())
            return {
                "total_analyzed": row.get("total_analyzed") or 0,
                "high_risk_count": row.get("high_risk_count") or 0,
                "phishing_count": row.get("phishing_count") or 0,
                "bec_count": row.get("bec_count") or 0,
                "malware_count": row.get("malware_count") or 0,
                "suspicious_domains": row.get("distinct_domains") or 0,
                "suspicious_ips": row.get("distinct_ips") or 0
            }
