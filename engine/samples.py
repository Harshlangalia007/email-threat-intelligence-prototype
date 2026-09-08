"""
Pre-packaged Realistic Sample Emails for SIH26106 Demonstration
Contains full RFC 5322 headers, Received relay paths, authentication tags, and bodies.
"""

SAMPLE_EMAILS = {
    "sample_1_legitimate": {
        "id": "sample_1_legitimate",
        "title": "Sample 1: Legitimate Enterprise Communication",
        "description": "Legitimate quarterly project update from a verified corporate domain with valid SPF/DKIM/DMARC pass.",
        "expected_classification": "Legitimate",
        "expected_risk": "LOW (0-15)",
        "raw_eml": """Delivered-To: recipient.analyst@cyberdefense-corp.com
Received: by 2002:a05:6e02:18c4:0:0:0:0 with SMTP id v4csp1290941ilq;
        Mon, 7 Sep 2026 09:14:22 -0700 (PDT)
X-Google-Smtp-Source: AGHT+IF3N8B7Z1v6i3+j8P2m9q5N3K4v1C
X-Received: by 2002:a17:902:c289:b0:1d2:8b89:2231 with SMTP id c9-20020a170902c28900b001d28b892231mr4892336plg.12.1694074462100;
        Mon, 7 Sep 2026 09:14:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694074462; cv=none;
        d=google.com; s=arc-20160816;
        b=Bq2G38V4m
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        t=1694074462;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        h=to:from:subject:date:message-id:mime-version;
        b=dC34u
ARC-Authentication-Results: i=1; mx.google.com;
       dkim=pass header.i=@acmepartners.com header.s=google header.b=V39k;
       spf=pass (google.com: domain of sarah.jenkins@acmepartners.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=sarah.jenkins@acmepartners.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acmepartners.com
Return-Path: <sarah.jenkins@acmepartners.com>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.google.com with SMTPS id s12sor239401plk.14.2026.09.07.09.14.21
        for <recipient.analyst@cyberdefense-corp.com>
        (Google Transport Security);
        Mon, 7 Sep 2026 09:14:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of sarah.jenkins@acmepartners.com designates 209.85.220.41 as permitted sender) client-ip=209.85.220.41;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@acmepartners.com header.s=google;
       spf=pass (google.com: domain of sarah.jenkins@acmepartners.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=sarah.jenkins@acmepartners.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acmepartners.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=acmepartners.com; s=google; t=1694074460;
        h=to:from:subject:date:message-id:mime-version;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=V39kL8932mK932JF9832
From: "Sarah Jenkins" <sarah.jenkins@acmepartners.com>
To: <recipient.analyst@cyberdefense-corp.com>
Subject: Q3 Architecture Sync & Project Status Review
Date: Mon, 7 Sep 2026 12:14:15 -0400
Message-ID: <CABp=mO_943029482039@mail.acmepartners.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit

Hi Team,

Hope you had a great weekend. Attached is our scheduled status report for the Q3 SIH cybersecurity project milestones.

Please review the notes and let me know if anyone needs adjustments to the timeline before our sync this Thursday at 2:00 PM EST. 

Documentation is accessible on our internal team wiki as usual:
https://wiki.acmepartners.com/projects/cyber-architecture

Best regards,

Sarah Jenkins
Senior Director of Engineering | Acme Partners
Office: +1 (555) 019-2834
"""
    },

    "sample_2_phishing": {
        "id": "sample_2_phishing",
        "title": "Sample 2: Credential Phishing / Brand Impersonation",
        "description": "Lookalike typosquatting domain (micros0ft-security-auth.com), display spoofing, SPF fail, credential prompt, and offshore hosting.",
        "expected_classification": "Phishing",
        "expected_risk": "CRITICAL (85-98)",
        "raw_eml": """Delivered-To: victim.employee@cyberdefense-corp.com
Received: by 2002:a05:6402:3004:0:0:0:0 with SMTP id b4csp239104plk;
        Tue, 8 Sep 2026 04:22:11 -0700 (PDT)
X-Received: by 2002:a17:906:8552:b0:994:ef41:1201 with SMTP id n18-20020a170906855200b00994ef411201mr9120349ejk.8.1694172131000;
        Tue, 8 Sep 2026 04:22:11 -0700 (PDT)
Return-Path: <bounce-daemon@micros0ft-security-auth.com>
Received: from mail.micros0ft-security-auth.com (mail.micros0ft-security-auth.com [185.220.101.5])
        by mx.cyberdefense-corp.com with ESMTP id q19si8321049plk.2026.09.08.04.22.10
        for <victim.employee@cyberdefense-corp.com>;
        Tue, 8 Sep 2026 04:22:10 -0700 (PDT)
Received-SPF: fail (cyberdefense-corp.com: domain of bounce-daemon@micros0ft-security-auth.com does not designate 185.220.101.5 as permitted sender) client-ip=185.220.101.5;
Authentication-Results: mx.cyberdefense-corp.com;
       dkim=fail reason="signature verification failed" header.i=@micros0ft-security-auth.com;
       spf=fail (mx.cyberdefense-corp.com: domain of bounce-daemon@micros0ft-security-auth.com does not designate 185.220.101.5 as permitted sender) smtp.mailfrom=bounce-daemon@micros0ft-security-auth.com;
       dmarc=fail (p=REJECT dis=REJECT) header.from=microsoft.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=micros0ft-security-auth.com; s=badkey; t=1694172100;
        bh=94JFKLEJF0932=; b=invalidSig3092
From: "Microsoft 365 Security Team" <security-alert@micros0ft-security-auth.com>
Reply-To: "M365 Identity Support" <auth-escalations@micros0ft-security-auth.com>
To: <victim.employee@cyberdefense-corp.com>
Subject: CRITICAL: Immediate Account Verification Required — Access Suspended Within 24 Hours
Date: Tue, 8 Sep 2026 11:22:01 +0000
Message-ID: <20260908112201.A392FF1902@mail.micros0ft-security-auth.com>
X-Mailer: PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 8bit

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
  <div style="max-width: 600px; background: #ffffff; padding: 30px; border-top: 4px solid #0078d4;">
    <h2 style="color: #d83b01; margin-top: 0;">Urgent Notice: Unusual Sign-in Detected</h2>
    <p>Dear Employee,</p>
    <p>Our security systems detected repeated unauthorized attempts to access your corporate Microsoft 365 workstation account from an unrecognized IP in Moscow, Russia.</p>
    <div style="background: #fff4ce; border-left: 4px solid #ffb900; padding: 12px; margin: 20px 0;">
      <strong>Action Required:</strong> You must verify your credentials within 24 hours to prevent immediate account suspension and corporate quarantine.
    </div>
    <p>Click the secure link below to confirm your password and validate your multi-factor credentials:</p>
    <p style="text-align: center; margin: 30px 0;">
      <a href="https://login.micros0ft-security-auth.com/owa/auth/verify.php?token=938029148" 
         style="background: #0078d4; color: #ffffff; padding: 14px 28px; text-decoration: none; font-weight: bold; border-radius: 2px;">
         Verify Identity & Restore Access
      </a>
    </p>
    <p style="font-size: 11px; color: #666666;">
      Microsoft Security Operations Center &bull; One Microsoft Way, Redmond, WA 98052 &bull; This is an automated security transmission.
    </p>
  </div>
</body>
</html>
"""
    },

    "sample_3_bec": {
        "id": "sample_3_bec",
        "title": "Sample 3: Executive Business Email Compromise (BEC)",
        "description": "Urgent wire transfer request impersonating CEO with From/Reply-To divergence to untrusted webmail and urgency pressure.",
        "expected_classification": "Business Email Compromise (BEC)",
        "expected_risk": "CRITICAL (90-99)",
        "raw_eml": """Delivered-To: finance.controller@cyberdefense-corp.com
Received: by 2002:a05:6808:1441:0:0:0:0 with SMTP id b1csp9410298eji;
        Mon, 7 Sep 2026 16:45:10 -0700 (PDT)
X-Received: by 2002:a17:907:2210:b0:9c2:1240:8012 with SMTP id v16-20020a170907221000b009c212408012mr391024plm.19.1694130310000;
        Mon, 7 Sep 2026 16:45:10 -0700 (PDT)
Return-Path: <exec-dispatch@executive-privatemail.top>
Received: from vps-relay14.bulletproof-transit.nl (vps-relay14.bulletproof-transit.nl [194.36.191.12])
        by mx.cyberdefense-corp.com with ESMTP id m12si9201481plk.2026.09.07.16.45.09
        for <finance.controller@cyberdefense-corp.com>;
        Mon, 7 Sep 2026 16:45:09 -0700 (PDT)
Received-SPF: softfail (cyberdefense-corp.com: transitioning domain of executive-privatemail.top does not designate 194.36.191.12 as permitted sender) client-ip=194.36.191.12;
Authentication-Results: mx.cyberdefense-corp.com;
       spf=softfail (mx.cyberdefense-corp.com: transitioning domain of executive-privatemail.top does not designate 194.36.191.12 as permitted sender) smtp.mailfrom=exec-dispatch@executive-privatemail.top;
       dkim=fail;
       dmarc=fail (p=NONE dis=NONE) header.from=cyberdefense-corp.com
From: "David Sterling [CEO]" <david.sterling@cyberdefense-corp.com>
Reply-To: "David Sterling" <exec-privatemail892@gmail.com>
To: <finance.controller@cyberdefense-corp.com>
Subject: STRICTLY CONFIDENTIAL // Time-Sensitive Acquisition Wire Transfer
Date: Mon, 7 Sep 2026 19:45:02 -0400
Message-ID: <9480194810294.20260907@executive-privatemail.top>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit

Hi Richard,

Are you at your desk right now? 

I am currently locked in an all-day executive board meeting regarding a time-sensitive acquisition and cannot take calls on my cell. 

We need to execute an urgent initial wire transfer of $84,500.00 today before the bank closing window (5:00 PM EST) to finalize the escrow retainer. 

Please keep this strictly confidential between us for now, as regulatory filings have not yet been submitted. Do not discuss this with the rest of the finance team until I return tomorrow.

Reply back immediately to confirm you can process this direct wire transfer right now, and I will send over the SWIFT routing and beneficiary account details.

Thanks,

David Sterling
Chief Executive Officer | CyberDefense Corp
Sent from my mobile device
"""
    },

    "sample_4_malware_shared_infra": {
        "id": "sample_4_malware_shared_infra",
        "title": "Sample 4: Malicious Invoice Delivery (Shares Infrastructure with Sample 2)",
        "description": "Malware delivery with weaponized executable attachment routed through the exact same bulletproof ASN (AS49870) and host server as Sample 2.",
        "expected_classification": "Malware Delivery",
        "expected_risk": "CRITICAL (95-100)",
        "raw_eml": """Delivered-To: billing.clerk@cyberdefense-corp.com
Received: by 2002:a05:6808:9921:0:0:0:0 with SMTP id c8csp1029482pli;
        Tue, 8 Sep 2026 08:11:02 -0700 (PDT)
Return-Path: <invoicing@cloud-billing-portal.xyz>
Received: from c2-host88.bulletproof-transit.nl (c2-host88.bulletproof-transit.nl [45.154.255.88])
        by mx.cyberdefense-corp.com with ESMTP id k44si1029381plk.2026.09.08.08.11.01
        for <billing.clerk@cyberdefense-corp.com>;
        Tue, 8 Sep 2026 08:11:01 -0700 (PDT)
Received-SPF: fail (cyberdefense-corp.com: domain of cloud-billing-portal.xyz does not designate 45.154.255.88 as permitted sender);
Authentication-Results: mx.cyberdefense-corp.com;
       spf=fail;
       dkim=fail;
       dmarc=fail;
From: "Accounts Payable Notification" <billing@cloud-billing-portal.xyz>
To: <billing.clerk@cyberdefense-corp.com>
Subject: OVERDUE INVOICE #INV-2026-8941 — FINAL NOTICE BEFORE LEGAL DISPUTE
Date: Tue, 8 Sep 2026 15:10:52 +0000
Message-ID: <INV94819401.2026@cloud-billing-portal.xyz>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_98241_209148"

------=_Part_98241_209148
Content-Type: text/plain; charset="UTF-8"

Accounts Payable,

Your organization has failed to remit settlement for past-due invoice #INV-2026-8941 ($14,280.00).

This is your final notice. If payment is not submitted within 24 hours, our counsel will initiate formal legal action and file a collections dispute.

Review the attached invoice calculation immediately.

------=_Part_98241_209148
Content-Type: application/octet-stream; name="Invoice_INV-8941_Overdue.pdf.exe"
Content-Disposition: attachment; filename="Invoice_INV-8941_Overdue.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAyAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v
ZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAAAAAAAA
------=_Part_98241_209148--
"""
    }
}


def get_all_samples():
    """Returns metadata list of all available demonstration samples."""
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "description": s["description"],
            "expected_classification": s["expected_classification"],
            "expected_risk": s["expected_risk"]
        }
        for s in SAMPLE_EMAILS.values()
    ]


def get_sample_by_id(sample_id: str):
    """Retrieves single sample with full raw .eml text."""
    return SAMPLE_EMAILS.get(sample_id)
