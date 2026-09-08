"""
Module 1: Fraud & Threat Detection Engine for SIH26106
Evaluates identity spoofing, SPF/DKIM/DMARC authentication, social engineering intents,
lookalike domains/typosquatting, static URL features, and outputs explainable risk scoring.
"""

import re
from typing import Dict, Any, List, Tuple


class ThreatDetector:
    """Evaluates an email's metadata, authentication, content, and URLs for cyber threats."""

    TARGET_BRANDS = [
        "microsoft", "office365", "google", "apple", "amazon", "paypal", "netflix",
        "chase", "bankofamerica", "wellsfargo", "citibank", "dhl", "fedex", "ups",
        "adobe", "dropbox", "facebook", "instagram", "linkedin", "irs", "gov", "standardchartered"
    ]

    SUSPICIOUS_TLDS = {
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "work", "loan",
        "fit", "icu", "click", "rest", "cam", "vip", "monster", "cfd", "sbs"
    }

    SOCIAL_ENGINEERING_INDICATORS = {
        "urgency": [
            r"\b(urgent|immediately|immediate action|within 24 hours|within 12 hours|expires? today|asap|time sensitive)\b",
            r"\b(account suspended|access suspended|deactivation|disabled within|final warning|final notice)\b"
        ],
        "threats": [
            r"\b(legal action|law enforcement|arrest|police|court summons|penalt(?:y|ies)|terminated|severance)\b",
            r"\b(reported to authorities|breach of policy|disciplinary)\b"
        ],
        "money_requests": [
            r"\b(wire transfer|swift transfer|bank transfer|direct deposit|bank details|routing number)\b",
            r"\b(gift cards?|apple card|itunes card|amazon gift card|steam card)\b",
            r"\b(overdue invoice|pending payment|remittance advice|crypto|bitcoin|wallet address)\b"
        ],
        "credential_harvesting": [
            r"\b(verify your (?:account|identity|password|credentials)|confirm your login)\b",
            r"\b(sign in to (?:verify|unlock|keep|restore)|reset your password now|update your security information)\b",
            r"\b(reactivate your mailbox|storage quota exceeded|upgrade your mailbox storage)\b"
        ],
        "executive_impersonation": [
            r"\b(i am (?:currently )?in a meeting|busy in a conference|cannot take calls|reach me only by email)\b",
            r"\b(keep this confidential|strictly confidential|between us|do not mention this to anyone)\b",
            r"\b(are you at your desk|quick favor|are you available)\b"
        ]
    }

    def __init__(self):
        pass

    def analyze(self, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        """Performs full threat detection analysis on the parsed email."""
        identity = parsed_email.get("identity", {})
        auth_headers = parsed_email.get("auth_headers", {})
        body = parsed_email.get("body", {})
        urls = parsed_email.get("urls", [])
        attachments = parsed_email.get("attachments", [])

        # 1. Identity & Spoofing Analysis
        identity_analysis = self._analyze_identity(identity)

        # 2. Authentication Analysis (SPF, DKIM, DMARC, Alignment)
        auth_analysis = self._analyze_authentication(identity, auth_headers)

        # 3. Social Engineering / NLP Analysis
        social_eng_analysis = self._analyze_social_engineering(identity.get("subject", ""), body.get("effective_text", ""))

        # 4. URL Analysis
        url_analysis = self._analyze_urls(urls, identity.get("from_domain", ""))

        # 5. Attachment Analysis
        attachment_analysis = self._analyze_attachments(attachments)

        # 6. Calculate Risk Score & Detailed Explainability Breakdown
        risk_evaluation = self._calculate_risk(
            identity_analysis,
            auth_analysis,
            social_eng_analysis,
            url_analysis,
            attachment_analysis
        )

        return {
            "classification": risk_evaluation["classification"],
            "risk_score": risk_evaluation["risk_score"],
            "risk_level": risk_evaluation["risk_level"],
            "confidence": risk_evaluation["confidence"],
            "reasons": risk_evaluation["reasons"],
            "risk_factors": risk_evaluation["risk_factors"],
            "mitigating_factors": risk_evaluation["mitigating_factors"],
            "identity_analysis": identity_analysis,
            "auth_analysis": auth_analysis,
            "social_engineering": social_eng_analysis,
            "url_analysis": url_analysis,
            "attachment_analysis": attachment_analysis
        }

    def _analyze_identity(self, identity: Dict[str, Any]) -> Dict[str, Any]:
        from_name = identity.get("from_name", "")
        from_email = identity.get("from_email", "")
        from_domain = identity.get("from_domain", "")
        reply_to_email = identity.get("reply_to_email", "")
        reply_to_domain = identity.get("reply_to_domain", "")
        return_path = identity.get("return_path", "")
        return_path_domain = identity.get("return_path_domain", "")

        findings = []
        is_spoofed = False

        # 1. Display-name spoofing: does display name contain an email address different from From?
        email_in_name = re.search(r'[\w\.-]+@[\w\.-]+', from_name)
        if email_in_name:
            embedded_addr = email_in_name.group(0).lower()
            if embedded_addr != from_email.lower():
                is_spoofed = True
                findings.append({
                    "type": "display_name_spoofing",
                    "severity": "HIGH",
                    "description": f"Display name contains embedded address '{embedded_addr}' which differs from actual sender '{from_email}'"
                })

        # 2. Executive / VIP display name with generic or mismatched domain
        for brand in self.TARGET_BRANDS:
            if brand in from_name.lower() and brand not in from_domain.lower():
                is_spoofed = True
                findings.append({
                    "type": "brand_display_impersonation",
                    "severity": "HIGH",
                    "description": f"Display name impersonates '{brand.capitalize()}' but sending domain is '{from_domain}'"
                })

        # 3. Sender vs Reply-To mismatch
        reply_to_mismatch = False
        if reply_to_email and reply_to_email.lower() != from_email.lower():
            reply_to_mismatch = True
            sev = "HIGH" if (reply_to_domain != from_domain) else "MEDIUM"
            findings.append({
                "type": "reply_to_mismatch",
                "severity": sev,
                "description": f"Reply-To address '{reply_to_email}' diverges from From address '{from_email}'"
            })

        # 4. Return-path mismatch
        return_path_mismatch = False
        if return_path and return_path_domain and return_path_domain != from_domain:
            return_path_mismatch = True
            findings.append({
                "type": "return_path_mismatch",
                "severity": "MEDIUM",
                "description": f"Return-Path domain '{return_path_domain}' differs from From domain '{from_domain}'"
            })

        # 5. Lookalike / Typosquatting Domain Analysis
        typosquat_info = self._check_lookalike(from_domain)
        if typosquat_info["is_lookalike"]:
            findings.append({
                "type": "typosquatting_domain",
                "severity": "CRITICAL",
                "description": f"Sender domain '{from_domain}' is a lookalike/typosquat of target brand '{typosquat_info['target_brand']}' ({typosquat_info['reason']})"
            })

        # 6. Suspicious TLD
        has_suspicious_tld = False
        if from_domain:
            tld = from_domain.split(".")[-1].lower()
            if tld in self.SUSPICIOUS_TLDS:
                has_suspicious_tld = True
                findings.append({
                    "type": "suspicious_tld",
                    "severity": "MEDIUM",
                    "description": f"Sender domain uses high-abuse/suspicious TLD: '.{tld}'"
                })

        return {
            "from_display": from_name,
            "from_email": from_email,
            "from_domain": from_domain,
            "reply_to_email": reply_to_email,
            "reply_to_mismatch": reply_to_mismatch,
            "return_path_mismatch": return_path_mismatch,
            "is_display_spoofed": is_spoofed,
            "is_lookalike_domain": typosquat_info["is_lookalike"],
            "lookalike_details": typosquat_info,
            "has_suspicious_tld": has_suspicious_tld,
            "findings": findings
        }

    def _check_lookalike(self, domain: str) -> Dict[str, Any]:
        """Detects typosquatting, character substitutions (homoglyphs), and brand lookalikes."""
        if not domain:
            return {"is_lookalike": False, "target_brand": "", "reason": ""}

        # Normalization: replace 0->o, 1->l/i, rn->m, vv->w
        normalized = domain.lower()
        substitutions = {
            "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
            "rn": "m", "vv": "w", "cl": "d"
        }
        for k, v in substitutions.items():
            normalized = normalized.replace(k, v)

        # Check target brands
        for brand in self.TARGET_BRANDS:
            # Check direct inclusion with hyphen tricks e.g. "microsoft-security-verify.com"
            if brand in domain.lower() and domain.lower() != f"{brand}.com" and not domain.lower().endswith(f".{brand}.com"):
                return {
                    "is_lookalike": True,
                    "target_brand": brand,
                    "reason": f"Contains brand name '{brand}' in an unverified third-party domain"
                }
            
            # Check normalized match (homoglyphs like 'micros0ft')
            if brand in normalized and brand not in domain.lower():
                return {
                    "is_lookalike": True,
                    "target_brand": brand,
                    "reason": f"Character substitution / homoglyph detected imitating '{brand}'"
                }

            # Check Levenshtein distance on primary domain label
            primary_label = domain.split(".")[0].lower()
            dist = self._levenshtein_distance(primary_label, brand)
            if 0 < dist <= 2 and len(brand) >= 5:
                return {
                    "is_lookalike": True,
                    "target_brand": brand,
                    "reason": f"Typo-squatting edit distance ({dist}) closely matches legitimate brand '{brand}'"
                }

        return {"is_lookalike": False, "target_brand": "", "reason": ""}

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _analyze_authentication(self, identity: Dict[str, Any], auth_headers: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates SPF, DKIM, DMARC, and SPF/DKIM domain alignment."""
        auth_results = auth_headers.get("authentication_results", "") or ""
        received_spf = auth_headers.get("received_spf", "") or ""
        dkim_sigs = auth_headers.get("dkim_signatures", [])
        from_domain = identity.get("from_domain", "").lower()

        # Combine text for inspection
        combined_auth = f"{auth_results} {received_spf}".lower()

        # 1. SPF Evaluation
        spf_status = "UNKNOWN / NOT AVAILABLE"
        spf_detail = "No SPF authentication record located in incoming headers."

        if "spf=pass" in combined_auth or "pass (google.com:" in combined_auth or received_spf.lower().startswith("pass"):
            spf_status = "PASS"
            spf_detail = "SPF validation passed for sending server IP."
        elif "spf=fail" in combined_auth or "fail (google.com:" in combined_auth or received_spf.lower().startswith("fail"):
            spf_status = "FAIL"
            spf_detail = "SPF hard fail: sending host is not authorized by the domain's SPF policy."
        elif "spf=softfail" in combined_auth or received_spf.lower().startswith("softfail"):
            spf_status = "FAIL"
            spf_detail = "SPF softfail: domain owner flagged host as questionable/unauthorized."
        elif "spf=neutral" in combined_auth or received_spf.lower().startswith("neutral"):
            spf_status = "NEUTRAL"
            spf_detail = "SPF neutral: domain does not assert whether the IP is authorized."

        # 2. DKIM Evaluation
        dkim_status = "UNKNOWN / NOT AVAILABLE"
        dkim_detail = "No DKIM signature verified."
        dkim_domain = ""

        if "dkim=pass" in combined_auth:
            dkim_status = "PASS"
            dkim_detail = "Cryptographic DKIM signature verified successfully."
        elif "dkim=fail" in combined_auth:
            dkim_status = "FAIL"
            dkim_detail = "DKIM cryptographic signature verification failed (possible tampering or key mismatch)."
        elif dkim_sigs:
            dkim_status = "PRESENT (UNVERIFIED)"
            dkim_detail = "DKIM signature header is present but no authentication-results record confirmed."

        # Extract DKIM d= domain if present
        if dkim_sigs:
            first_sig = dkim_sigs[0] if isinstance(dkim_sigs, list) else str(dkim_sigs)
            d_match = re.search(r'\bd=([a-zA-Z0-9\.-]+)', first_sig)
            if d_match:
                dkim_domain = d_match.group(1).lower()

        # 3. DMARC Evaluation
        dmarc_status = "UNKNOWN / NOT AVAILABLE"
        dmarc_detail = "No DMARC policy result located."

        if "dmarc=pass" in combined_auth:
            dmarc_status = "PASS"
            dmarc_detail = "DMARC policy passed with confirmed identifier alignment."
        elif "dmarc=fail" in combined_auth:
            dmarc_status = "FAIL"
            dmarc_detail = "DMARC check failed: email failed SPF/DKIM alignment requirements."

        # 4. Alignment Analysis
        spf_aligned = (spf_status == "PASS") and (from_domain in combined_auth or identity.get("return_path_domain") == from_domain)
        dkim_aligned = (dkim_status == "PASS") and (dkim_domain and (dkim_domain == from_domain or from_domain.endswith(f".{dkim_domain}")))

        alignment_status = "FAIL"
        if spf_aligned and dkim_aligned:
            alignment_status = "FULL ALIGNMENT (SPF & DKIM)"
        elif spf_aligned:
            alignment_status = "PARTIAL ALIGNMENT (SPF Only)"
        elif dkim_aligned:
            alignment_status = "PARTIAL ALIGNMENT (DKIM Only)"
        else:
            alignment_status = "NO ALIGNMENT"

        return {
            "spf": {
                "status": spf_status,
                "detail": spf_detail,
                "is_pass": spf_status == "PASS"
            },
            "dkim": {
                "status": dkim_status,
                "detail": dkim_detail,
                "signing_domain": dkim_domain,
                "is_pass": dkim_status == "PASS"
            },
            "dmarc": {
                "status": dmarc_status,
                "detail": dmarc_detail,
                "is_pass": dmarc_status == "PASS"
            },
            "alignment": {
                "status": alignment_status,
                "spf_aligned": spf_aligned,
                "dkim_aligned": dkim_aligned
            }
        }

    def _analyze_social_engineering(self, subject: str, body: str) -> Dict[str, Any]:
        text_to_scan = f"{subject}\n{body}".lower()
        detections = []
        categories_detected = set()

        for category, patterns in self.SOCIAL_ENGINEERING_INDICATORS.items():
            for pattern in patterns:
                matches = re.findall(pattern, text_to_scan, re.IGNORECASE)
                if matches:
                    categories_detected.add(category)
                    detections.append({
                        "category": category,
                        "trigger": matches[0] if isinstance(matches[0], str) else matches[0][0],
                        "matched_snippets": [str(m) for m in matches[:3]]
                    })

        # Calculate social engineering severity
        severity = "LOW"
        if len(categories_detected) >= 3 or ("money_requests" in categories_detected and "urgency" in categories_detected):
            severity = "CRITICAL"
        elif len(categories_detected) >= 2:
            severity = "HIGH"
        elif len(categories_detected) == 1:
            severity = "MEDIUM"

        return {
            "severity": severity,
            "detected_categories": list(categories_detected),
            "detections": detections,
            "has_urgency": "urgency" in categories_detected,
            "has_threats": "threats" in categories_detected,
            "has_money_requests": "money_requests" in categories_detected,
            "has_credential_harvesting": "credential_harvesting" in categories_detected,
            "has_executive_impersonation": "executive_impersonation" in categories_detected
        }

    def _analyze_urls(self, urls: List[Dict[str, Any]], sender_domain: str) -> Dict[str, Any]:
        url_findings = []
        suspicious_count = 0

        for u in urls:
            url_str = u.get("url", "")
            domain = u.get("domain", "")
            is_ip = u.get("is_ip_domain", False)
            tld = domain.split(".")[-1].lower() if "." in domain else ""
            
            reasons = []
            if is_ip:
                reasons.append("Raw IP address used in host portion instead of registered domain")
            if tld in self.SUSPICIOUS_TLDS:
                reasons.append(f"Domain uses high-risk/abuse TLD '.{tld}'")
            
            # Check lookalike
            lookalike = self._check_lookalike(domain)
            if lookalike["is_lookalike"]:
                reasons.append(f"Impersonates target brand '{lookalike['target_brand']}' ({lookalike['reason']})")

            # Check if domain differs from sender domain
            domain_divergence = False
            if sender_domain and domain and sender_domain not in domain and domain not in sender_domain:
                domain_divergence = True

            # Obfuscation checks
            if "@" in url_str.split("://")[-1]:
                reasons.append("URL contains '@' character trick to disguise target host")

            if reasons:
                suspicious_count += 1
                url_findings.append({
                    "url": url_str,
                    "domain": domain,
                    "is_suspicious": True,
                    "risk_factors": reasons,
                    "domain_divergence": domain_divergence
                })
            else:
                url_findings.append({
                    "url": url_str,
                    "domain": domain,
                    "is_suspicious": False,
                    "risk_factors": [],
                    "domain_divergence": domain_divergence
                })

        return {
            "total_urls": len(urls),
            "suspicious_urls_count": suspicious_count,
            "urls": url_findings,
            "has_suspicious_urls": suspicious_count > 0
        }

    def _analyze_attachments(self, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        suspicious_atts = []
        for att in attachments:
            if att.get("is_suspicious"):
                suspicious_atts.append(att)

        return {
            "total_attachments": len(attachments),
            "suspicious_count": len(suspicious_atts),
            "items": attachments,
            "has_malware_indicators": len(suspicious_atts) > 0
        }

    def _calculate_risk(
        self,
        identity: Dict[str, Any],
        auth: Dict[str, Any],
        social_eng: Dict[str, Any],
        urls: Dict[str, Any],
        attachments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculates 0-100 risk score, confidence, and transparent factor breakdown."""
        score = 5  # Base baseline
        reasons = []
        risk_factors = []
        mitigating_factors = []

        # 1. Authentication evaluation
        spf = auth.get("spf", {})
        dkim = auth.get("dkim", {})
        dmarc = auth.get("dmarc", {})
        alignment = auth.get("alignment", {})

        if spf.get("status") == "FAIL":
            score += 25
            factor = "SPF validation failed: Sender host unauthorized"
            risk_factors.append(factor)
            reasons.append(factor)
        elif spf.get("is_pass"):
            score -= 10
            mitigating_factors.append("SPF verified pass")

        if dkim.get("status") == "FAIL":
            score += 20
            factor = "DKIM cryptographic signature check failed"
            risk_factors.append(factor)
            reasons.append(factor)
        elif dkim.get("is_pass"):
            score -= 10
            mitigating_factors.append("DKIM cryptographically verified")

        if dmarc.get("status") == "FAIL":
            score += 20
            factor = "DMARC policy failed: alignment requirements violated"
            risk_factors.append(factor)
            reasons.append(factor)
        elif dmarc.get("is_pass"):
            score -= 15
            mitigating_factors.append("DMARC policy passed with domain alignment")

        # 2. Identity & Spoofing
        if identity.get("is_display_spoofed"):
            score += 30
            factor = "Display-name spoofing detected (impersonation indicator)"
            risk_factors.append(factor)
            reasons.append(factor)

        if identity.get("is_lookalike_domain"):
            score += 35
            details = identity.get("lookalike_details", {})
            factor = f"Typosquatting/Lookalike domain detected targeting {details.get('target_brand', 'brand')}"
            risk_factors.append(factor)
            reasons.append(factor)

        if identity.get("reply_to_mismatch"):
            score += 25
            factor = "Reply-To address diverges from From address (redirection indicator)"
            risk_factors.append(factor)
            reasons.append(factor)

        if identity.get("has_suspicious_tld"):
            score += 15
            factor = "Sender domain utilizes high-abuse / disposable TLD"
            risk_factors.append(factor)
            reasons.append(factor)

        # 3. Social Engineering
        if social_eng.get("has_credential_harvesting"):
            score += 30
            factor = "Credential harvesting intent detected in email body"
            risk_factors.append(factor)
            reasons.append(factor)

        if social_eng.get("has_money_requests"):
            score += 30
            factor = "Financial transfer / wire payment request detected"
            risk_factors.append(factor)
            reasons.append(factor)

        if social_eng.get("has_executive_impersonation"):
            score += 25
            factor = "Executive impersonation / meeting secrecy language detected"
            risk_factors.append(factor)
            reasons.append(factor)

        if social_eng.get("has_urgency"):
            score += 15
            factor = "High urgency / coercion pressure language detected"
            risk_factors.append(factor)
            reasons.append(factor)

        # 4. URLs
        if urls.get("has_suspicious_urls"):
            score += 30
            factor = f"{urls.get('suspicious_urls_count')} suspicious URL(s) detected with deceptive characteristics"
            risk_factors.append(factor)
            reasons.append(factor)

        # 5. Attachments
        if attachments.get("has_malware_indicators"):
            score += 40
            factor = "Dangerous executable/script attachment detected (malware risk)"
            risk_factors.append(factor)
            reasons.append(factor)

        # Clamp score to 0 - 100
        final_score = max(0, min(100, score))

        # Determine Classification & Risk Level
        if attachments.get("has_malware_indicators"):
            classification = "Malware Delivery"
            risk_level = "CRITICAL"
        elif social_eng.get("has_money_requests") and (identity.get("reply_to_mismatch") or social_eng.get("has_executive_impersonation")):
            classification = "Business Email Compromise (BEC)"
            risk_level = "CRITICAL" if final_score >= 75 else "HIGH"
        elif identity.get("is_lookalike_domain") or identity.get("is_display_spoofed"):
            if social_eng.get("has_credential_harvesting") or urls.get("has_suspicious_urls"):
                classification = "Phishing"
                risk_level = "CRITICAL" if final_score >= 80 else "HIGH"
            else:
                classification = "Impersonation"
                risk_level = "HIGH"
        elif social_eng.get("has_credential_harvesting") or urls.get("has_suspicious_urls"):
            classification = "Phishing"
            risk_level = "CRITICAL" if final_score >= 80 else "HIGH"
        elif social_eng.get("has_money_requests"):
            classification = "Fraud"
            risk_level = "HIGH"
        elif final_score >= 60:
            classification = "Suspicious"
            risk_level = "HIGH"
        elif final_score >= 35:
            classification = "Suspicious"
            risk_level = "MEDIUM"
        else:
            classification = "Legitimate"
            risk_level = "LOW"

        # Calculate confidence
        confidence = 94 if len(reasons) >= 3 else (88 if len(reasons) >= 1 else 92)

        if not reasons:
            reasons.append("Email passed all authentication, identity alignment, and content safety checks.")

        return {
            "classification": classification,
            "risk_score": final_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "reasons": reasons,
            "risk_factors": risk_factors,
            "mitigating_factors": mitigating_factors
        }
