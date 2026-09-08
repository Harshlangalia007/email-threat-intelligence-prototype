"""
Human-Readable Plain-Language Summary Engine for SIH26106
Translates technical email forensics, SPF/DKIM/DMARC authentication, and threat indicators
into plain, non-technical English that normal employees and managers can immediately understand.
"""

from typing import Dict, Any, List


class UserFriendlySummaryGenerator:
    """Transforms raw cybersecurity telemetry into human-understandable verdicts and action items."""

    @staticmethod
    def generate_summary(
        parsed_email: Dict[str, Any],
        threat_data: Dict[str, Any],
        forensic_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generates an end-user friendly assessment answering:
        - Is this email safe?
        - Why is it suspicious?
        - What should I do?
        - Who does it appear to come from?
        - Where did the email come through?
        - Related suspicious activity
        """
        score = threat_data.get("risk_score", 0)
        classification = threat_data.get("classification", "Unknown")
        identity = parsed_email.get("identity", {})
        auth_analysis = threat_data.get("auth_analysis", {})
        social_eng = threat_data.get("social_engineering", {})
        urls = threat_data.get("url_analysis", {})
        attachments = threat_data.get("attachment_analysis", {})
        threat_intel = forensic_data.get("threat_intelligence", {})
        origin_mta = forensic_data.get("origin_mta") or {}
        location_analysis = forensic_data.get("location_analysis", {})

        # Identity Analysis from Threat Detector
        ident_analysis = threat_data.get("identity_analysis") or {}
        is_lookalike = ident_analysis.get("is_lookalike_domain", False)
        lookalike_details = ident_analysis.get("lookalike_details") or {}
        is_spoofed = ident_analysis.get("is_display_spoofed", False)
        reply_mismatch = ident_analysis.get("reply_to_mismatch", False)

        # ---------------------------------------------------------------------
        # 1. Is this email safe? (Verdict Headline, Badge, & Primary Recommendation)
        # ---------------------------------------------------------------------
        is_safe = score < 35
        is_critical = score >= 70
        is_suspicious = not is_safe and not is_critical

        if is_safe:
            verdict_headline = "✅ This email appears safe to read"
            verdict_subtitle = "No deceptive links, fake sender addresses, or malicious patterns were found."
            risk_badge = f"Safe — {score}/100"
            risk_color = "safe"  # emerald
            recommendation = "You can safely open, read, and reply to this message."
        elif is_critical:
            if classification == "Malware Delivery":
                verdict_headline = "🚨 Dangerous: Malicious file attached"
                verdict_subtitle = "This email contains a harmful program or infected attachment that could compromise your computer."
            elif classification == "Business Email Compromise (BEC)":
                verdict_headline = "🚨 Danger: Possible executive payment fraud"
                verdict_subtitle = "The sender appears to be impersonating a colleague or executive to request unauthorized money or gift cards."
            else:
                verdict_headline = "🚨 Danger: This email is likely a scam or phishing attack"
                verdict_subtitle = "The sender is trying to steal your account credentials, passwords, or personal information."
            risk_badge = f"High Risk — {score}/100"
            risk_color = "danger"  # crimson
            recommendation = "🚫 We recommend not clicking any links, opening attachments, or replying to this email."
        else:
            verdict_headline = "⚠️ Caution: This email has suspicious characteristics"
            verdict_subtitle = "Some aspects of this message look unusual or could not be fully verified."
            risk_badge = f"Moderate Risk — {score}/100"
            risk_color = "caution"  # amber
            recommendation = "⚠️ Exercise caution. Do not share confidential information or passwords until you verify the sender through a separate channel."

        # ---------------------------------------------------------------------
        # 2. Why is it suspicious? (Plain English bullet points)
        # ---------------------------------------------------------------------
        plain_reasons: List[str] = []

        # Check authentication / verification
        spf_status = auth_analysis.get("spf", {}).get("status")
        dkim_status = auth_analysis.get("dkim", {}).get("status")
        dmarc_status = auth_analysis.get("dmarc", {}).get("status")
        
        if spf_status == "FAIL" or dkim_status == "FAIL" or dmarc_status == "FAIL":
            plain_reasons.append("The sender's identity could not be verified by corporate email security systems.")

        # Check sender impersonation / lookalike
        if is_lookalike:
            brand = lookalike_details.get("target_brand", "a known organization")
            plain_reasons.append(
                f"The sender address uses a lookalike domain designed to trick you into thinking it came from {brand.title()}."
            )
        elif is_spoofed:
            plain_reasons.append("The display name shows a trusted name, but the underlying email address does not match.")

        # Check reply-to redirection
        if reply_mismatch:
            plain_reasons.append("The reply address is different from the sender — if you reply, your message will secretly go to an outside address.")

        # Check social engineering / manipulation
        if social_eng.get("has_credential_harvesting"):
            plain_reasons.append("The message asks you to log in, verify credentials, or prevent account closure.")

        if social_eng.get("has_money_requests"):
            plain_reasons.append("The message requests an urgent wire transfer, invoice payment, or bank account update commonly associated with fraud.")

        if social_eng.get("has_executive_impersonation"):
            plain_reasons.append("The sender claims to be in an urgent meeting or unavailable by phone, asking you to handle this matter quietly.")

        if social_eng.get("has_urgency"):
            plain_reasons.append("The message uses high-pressure language demanding immediate action within hours to create panic.")

        # Check deceptive links
        if urls.get("has_suspicious_urls"):
            plain_reasons.append("The email contains deceptive links that lead to untrusted or fake websites rather than the official service.")

        # Check attachments
        if attachments.get("has_malware_indicators"):
            plain_reasons.append("The email contains an executable file disguised as a document (e.g., .pdf.exe or script file).")

        # Fallback if clean or few reasons
        if not plain_reasons:
            if is_safe:
                plain_reasons.append("The sender's domain passed all digital signature and authentication checks.")
                plain_reasons.append("No deceptive links, hidden redirects, or credential prompts were detected.")
                plain_reasons.append("The language appears to be legitimate, routine communication.")
            else:
                plain_reasons.append("Several technical routing attributes or sender behaviors deviated from normal corporate standards.")

        # ---------------------------------------------------------------------
        # 3. What should I do? (Actionable Guidance for Non-Technical Users)
        # ---------------------------------------------------------------------
        action_checklist: List[Dict[str, Any]] = []

        if is_safe:
            action_checklist = [
                {"type": "do", "text": "You can safely open and read this email."},
                {"type": "do", "text": "Normal replies and business communication are permitted."},
                {"type": "info", "text": "As always, never share master passwords via email."}
            ]
        else:
            action_checklist = [
                {"type": "dont", "text": "Do NOT click any links inside this email."},
                {"type": "dont", "text": "Do NOT download or open any attachments."},
                {"type": "dont", "text": "Do NOT reply or send any company, banking, or employee information."},
                {"type": "do", "text": "If this email claims to be from a colleague or vendor, call them on a known, verified phone number to verify."},
                {"type": "report", "text": "Click 'Report to IT Security' below to alert your organization's security team."}
            ]

        # ---------------------------------------------------------------------
        # 4. Who does it appear to come from? (Identity Breakdown)
        # ---------------------------------------------------------------------
        from_name = identity.get("from_name") or "Not Specified"
        from_email = identity.get("from_email") or "Unknown"
        from_domain = identity.get("from_domain") or ""
        reply_to_email = identity.get("reply_to_email") or ""

        # Plain language explanation of sender identity
        if is_lookalike:
            brand = lookalike_details.get("target_brand", "known company").title()
            sender_explanation = (
                f"The sender pretends to be '{brand}', but the actual website name is '{from_domain}', "
                f"which is subtly misspelled to mislead you."
            )
        elif reply_mismatch and reply_to_email:
            sender_explanation = (
                f"The sender shows as '{from_email}', but any email you write will secretly be routed to '{reply_to_email}'."
            )
        elif is_spoofed:
            sender_explanation = (
                f"The display name '{from_name}' does not match the actual email address '{from_email}'."
            )
        elif is_safe:
            sender_explanation = (
                f"The sender address '{from_email}' matches the official organizational domain '{from_domain}'."
            )
        else:
            sender_explanation = f"Email was received from '{from_email}'."

        identity_breakdown = {
            "displayed_name": from_name,
            "actual_email": from_email,
            "actual_domain": from_domain,
            "reply_to": reply_to_email if reply_mismatch else None,
            "plain_explanation": sender_explanation,
            "is_deceptive": bool(is_lookalike or is_spoofed or reply_mismatch)
        }

        # ---------------------------------------------------------------------
        # 5. Where did the email come through? (Simplified 3-Stage Transit Journey)
        # ---------------------------------------------------------------------
        ip_addr = origin_mta.get("ip") or "N/A"
        city = origin_mta.get("city") or "Unknown City"
        country = origin_mta.get("country") or "Unknown Country"
        isp = origin_mta.get("isp") or origin_mta.get("org") or "Commercial Hosting"

        is_no_headers = (ip_addr == "N/A" or "No Received" in str(ip_addr))

        if is_no_headers:
            journey_summary = "This email was analyzed from pasted text without transmission routing stamps."
            origin_stage_title = "Pasted Input / Unknown Server"
            origin_stage_desc = "No network transmission headers available"
        else:
            journey_summary = f"This message originated from an internet server located in {city}, {country} ({isp})."
            origin_stage_title = f"Origin Server: {city}, {country}"
            origin_stage_desc = f"Network Host: {isp} (IP: {ip_addr})"

        simplified_journey = {
            "summary": journey_summary,
            "has_network_data": not is_no_headers,
            "stages": [
                {
                    "step": 1,
                    "title": origin_stage_title,
                    "desc": origin_stage_desc,
                    "type": "origin",
                    "status": "warning" if (is_critical or is_suspicious) else "neutral"
                },
                {
                    "step": 2,
                    "title": "Email Security Gateway",
                    "desc": "Transited corporate MX mail servers & filters",
                    "type": "gateway",
                    "status": "neutral"
                },
                {
                    "step": 3,
                    "title": "Your Mailbox",
                    "desc": "Delivered to employee inbox",
                    "type": "destination",
                    "status": "neutral"
                }
            ]
        }

        # ---------------------------------------------------------------------
        # 6. Related Suspicious Activity
        # ---------------------------------------------------------------------
        asn_info = origin_mta.get("asn") or ""
        related_campaigns = threat_intel.get("related_campaigns") or []
        is_bulletproof = threat_intel.get("is_bulletproof_host", False)

        if related_campaigns:
            camp_names = ", ".join([c.get("name", "Campaign") for c in related_campaigns[:2]])
            related_activity = (
                f"⚠️ The computer server that delivered this email has been observed in other reported cyber attacks ({camp_names})."
            )
        elif is_bulletproof:
            related_activity = (
                "⚠️ This email was routed through an offshore hosting network known for hosting abusive online services."
            )
        elif not is_safe and not is_no_headers:
            related_activity = (
                f"The originating network ({isp}) is unusual for standard communication from the alleged sender organization."
            )
        else:
            related_activity = "No known prior malicious cyber campaigns are associated with this sender infrastructure."

        return {
            "is_safe": is_safe,
            "verdict_headline": verdict_headline,
            "verdict_subtitle": verdict_subtitle,
            "risk_badge": risk_badge,
            "risk_color": risk_color,
            "risk_score": score,
            "risk_level": threat_data.get("risk_level", "LOW"),
            "classification": classification,
            "recommendation": recommendation,
            "plain_reasons": plain_reasons,
            "action_checklist": action_checklist,
            "identity_breakdown": identity_breakdown,
            "simplified_journey": simplified_journey,
            "related_activity": related_activity
        }
