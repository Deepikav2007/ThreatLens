"""
MailTrace AI - Demo Email Fixtures
Feature 1: AI Threat Detection
"""

from typing import Dict, Any

DEMO_EMAILS: Dict[str, Dict[str, Any]] = {
    "phishing": {
        "id": "phishing_demo",
        "title": "A. Phishing Email (Account Suspension)",
        "sender": "Security Alert <service-update@alert-center.xyz>",
        "recipient": "victim@corporation.com",
        "reply_to": "service-update@alert-center.xyz",
        "return_path": "bounce@alert-center.xyz",
        "subject": "URGENT: Verify your account",
        "body": "Your account has been suspended due to suspicious activity. Verify your identity immediately using the link below to prevent permanent deactivation within 24 hours. Sign in to verify your login credentials now.",
        "urls": ["http://secure-login.alert-center.xyz/auth/verify"],
        "domains": ["alert-center.xyz"],
        "ips": ["194.26.29.112"],
        "attachments": [],
        "spf": "pass",
        "dkim": "fail",
        "dmarc": "fail"
    },
    "bec": {
        "id": "bec_demo",
        "title": "B. BEC / Payment Email (Executive Wire Transfer)",
        "sender": "CEO James Vance <ceo@corporation.com>",
        "recipient": "accounting@corporation.com",
        "reply_to": "james.vance.confidential@gmail.com",
        "return_path": "ceo@corporation.com",
        "subject": "Urgent Payment Request - Strictly Confidential",
        "body": "Are you at your desk? Please process the payment immediately for the attached overdue invoice. New wire transfer instructions and bank account details must be used for this settlement. Do not delay this request or discuss with anyone else.",
        "urls": [],
        "domains": [],
        "ips": [],
        "attachments": [{"filename": "vendor_invoice_inv7892.pdf", "size": 45200}],
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass"
    },
    "impersonation": {
        "id": "impersonation_demo",
        "title": "C. Impersonation / Spoofing Email (IT Support)",
        "sender": "Microsoft IT Support <admin-office365@support-portal.top>",
        "recipient": "employee@corporation.com",
        "reply_to": "it-helpdesk@work.buzz",
        "return_path": "bounce@free-server.xyz",
        "subject": "Action Required: Microsoft 365 Password Expiration Notice",
        "body": "Your corporate Microsoft password will expire today. Update your password and confirm your login credentials immediately to avoid system administrator lockout.",
        "urls": ["http://185.190.140.22/login"],
        "domains": ["support-portal.top"],
        "ips": ["185.190.140.22"],
        "attachments": [],
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail"
    },
    "benign": {
        "id": "benign_demo",
        "title": "D. Benign / Legitimate Email (Team Meeting)",
        "sender": "Alice Johnson <alice@corporation.com>",
        "recipient": "bob@corporation.com",
        "reply_to": "alice@corporation.com",
        "return_path": "alice@corporation.com",
        "subject": "Meeting tomorrow - Quarterly Project Sync",
        "body": "Hi Bob,\n\nPlease find the meeting agenda attached for our sync tomorrow morning. Let me know if you would like to add any discussion points.\n\nSee you tomorrow,\nAlice",
        "urls": [],
        "domains": ["corporation.com"],
        "ips": [],
        "attachments": [{"filename": "quarterly_sync_agenda.pdf", "size": 105230}],
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass"
    }
}
