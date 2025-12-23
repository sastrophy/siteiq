"""
Web Cache Poisoning Security Tests

Tests for web cache poisoning vulnerabilities that can be exploited to
serve malicious content to users, perform XSS, or cause DoS.

References:
- https://portswigger.net/web-security/web-cache-poisoning
- https://portswigger.net/research/practical-web-cache-poisoning
- https://youst.in/posts/cache-poisoning-at-scale/
"""

import hashlib
import pytest
import requests
import time
import random
import string
from urllib.parse import urlparse, urlencode


def generate_cache_buster():
    """Generate a unique cache-busting string."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))


# Unkeyed header payloads for cache poisoning
UNKEYED_HEADER_PAYLOADS = [
    # Host header attacks
    {"X-Forwarded-Host": "evil.com"},
    {"X-Host": "evil.com"},
    {"X-Forwarded-Server": "evil.com"},
    {"X-HTTP-Host-Override": "evil.com"},
    {"Forwarded": "host=evil.com"},

    # Port/protocol manipulation
    {"X-Forwarded-Port": "443"},
    {"X-Forwarded-Scheme": "https"},
    {"X-Forwarded-Proto": "https"},

    # Path/URL manipulation
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Original-Host": "evil.com"},

    # Custom headers that might be reflected
    {"X-Custom-Header": "<script>alert(1)</script>"},
    {"X-Inject": "injected-value"},
    {"X-Debug": "true"},

    # Cache control manipulation
    {"X-Forwarded-For": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},

    # Vary header manipulation
    {"Accept-Language": "en-evil"},
    {"Accept-Encoding": "evil"},

    # Fat GET request headers
    {"X-HTTP-Method-Override": "POST"},
    {"X-Method-Override": "DELETE"},
]

# Cache key confusion payloads
CACHE_KEY_PAYLOADS = [
    # Unkeyed query parameters
    "utm_source=evil",
    "utm_content=<script>alert(1)</script>",
    "callback=evil",
    "jsonp=evil",
    "_=12345",  # jQuery cache buster

    # Parameter pollution
    "id=1&id=<script>alert(1)</script>",

    # Encoding variations
    "param=%3Cscript%3Ealert(1)%3C/script%3E",

    # Null byte injection
    "file=test%00.html",
]

# Response splitting / CRLF injection for cache poisoning
CRLF_PAYLOADS = [
    "X-Forwarded-Host: evil.com\r\nX-Injected: true",
    "evil.com\r\nSet-Cookie: poisoned=true",
    "evil.com\r\nX-XSS-Protection: 0",
    "evil.com\r\n\r\n<html>poisoned</html>",
    "%0d%0aX-Injected: true",
    "%0d%0aSet-Cookie: poisoned=true",
    "\r\nX-Injected: true",
]

# Web cache deception payloads
CACHE_DECEPTION_PATHS = [
    "/account/settings.css",
    "/api/user/.css",
    "/profile/me.js",
    "/dashboard/data.png",
    "/account.css",
    "/profile.js",
    "/.css",
    "/;.css",
    "/%2e.css",
    "/data.json",
]


class TestWebCachePoisoning:
    """Tests for web cache poisoning vulnerabilities."""

    @pytest.fixture(autouse=True)
    def setup(self, target_url, session):
        self.target_url = target_url
        self.session = session

    def is_cached_response(self, response):
        """Check if response appears to be cached."""
        cache_indicators = [
            ("X-Cache", ["HIT", "hit"]),
            ("X-Cache-Status", ["HIT", "hit"]),
            ("CF-Cache-Status", ["HIT", "hit"]),
            ("X-Varnish-Cache", ["HIT", "hit"]),
            ("X-Proxy-Cache", ["HIT", "hit"]),
            ("Age", None),  # Any Age header suggests caching
            ("X-Served-By", None),  # CDN indicator
        ]

        for header, values in cache_indicators:
            if header in response.headers:
                if values is None:
                    return True
                if any(v in response.headers[header] for v in values):
                    return True

        return False

    def get_cache_headers(self, response):
        """Extract cache-related headers from response."""
        cache_headers = {}
        relevant = [
            "Cache-Control", "Age", "X-Cache", "X-Cache-Status",
            "CF-Cache-Status", "X-Varnish", "Via", "Vary",
            "X-Served-By", "X-Cache-Hits"
        ]
        for header in relevant:
            if header in response.headers:
                cache_headers[header] = response.headers[header]
        return cache_headers

    @pytest.mark.cache_poisoning
    @pytest.mark.security
    def test_unkeyed_header_poisoning(self, target_url, session):
        """Test for cache poisoning via unkeyed headers."""
        findings = []

        # Generate unique cache buster for each test
        cache_buster = generate_cache_buster()
        test_url = f"{target_url.rstrip('/')}/?cb={cache_buster}"

        for payload in UNKEYED_HEADER_PAYLOADS:
            try:
                # Make request with poisoned header
                response1 = session.get(test_url, headers=payload, timeout=10)

                # Check if header value is reflected in response
                for header, value in payload.items():
                    if value.lower() in response1.text.lower():
                        # Make second request without the header to check if cached
                        time.sleep(0.5)
                        response2 = session.get(test_url, timeout=10)

                        if value.lower() in response2.text.lower():
                            findings.append({
                                "header": header,
                                "value": value,
                                "reflected": True,
                                "possibly_cached": True,
                                "cache_headers": self.get_cache_headers(response1),
                            })
                        else:
                            findings.append({
                                "header": header,
                                "value": value,
                                "reflected": True,
                                "possibly_cached": False,
                            })

            except requests.RequestException:
                continue

        if findings:
            cached_findings = [f for f in findings if f.get("possibly_cached")]
            if cached_findings:
                pytest.fail(
                    f"CRITICAL: Cache poisoning via unkeyed headers detected! "
                    f"Poisoned responses may be served to other users. "
                    f"Findings: {cached_findings}"
                )
            else:
                pytest.fail(
                    f"Header reflection detected (potential cache poisoning): {findings}"
                )

    @pytest.mark.cache_poisoning
    @pytest.mark.security
    def test_host_header_poisoning(self, target_url, session):
        """Test for cache poisoning via Host header manipulation."""
        findings = []

        parsed = urlparse(target_url)
        cache_buster = generate_cache_buster()

        host_payloads = [
            {"Host": "evil.com"},
            {"Host": f"{parsed.netloc}\r\nX-Injected: true"},
            {"Host": f"evil.com:{parsed.port or 80}"},
            {"Host": f"{parsed.netloc}@evil.com"},
            {"Host": f"{parsed.netloc}:@evil.com"},
        ]

        for payload in host_payloads:
            test_url = f"{target_url.rstrip('/')}/?hcb={cache_buster}"

            try:
                response = session.get(
                    test_url,
                    headers=payload,
                    timeout=10,
                    allow_redirects=False
                )

                # Check if evil.com appears in response (links, redirects, etc.)
                if "evil.com" in response.text.lower():
                    findings.append({
                        "payload": payload,
                        "reflected_in": "body",
                        "status": response.status_code,
                    })

                # Check Location header for redirects
                if "Location" in response.headers:
                    if "evil.com" in response.headers["Location"].lower():
                        findings.append({
                            "payload": payload,
                            "reflected_in": "Location header",
                            "redirect_to": response.headers["Location"],
                        })

            except requests.RequestException:
                continue

        if findings:
            pytest.fail(f"Host header poisoning detected: {findings}")

    @pytest.mark.cache_poisoning
    @pytest.mark.security
    def test_cache_key_normalization(self, target_url, session):
        """Test for cache key normalization issues."""
        findings = []

        # Test paths that might have different cache keys but same content
        path_variations = [
            ("/", "/%2f"),
            ("/", "/./"),
            ("/", "//"),
            ("/index", "/INDEX"),
            ("/test", "/test/"),
            ("/test", "/test?"),
            ("/test", "/test#"),
        ]

        for path1, path2 in path_variations:
            try:
                url1 = f"{target_url.rstrip('/')}{path1}"
                url2 = f"{target_url.rstrip('/')}{path2}"

                response1 = session.get(url1, timeout=10)
                response2 = session.get(url2, timeout=10)

                # If same content but potentially different cache keys
                if response1.status_code == response2.status_code == 200:
                    if len(response1.text) == len(response2.text):
                        # Could be exploitable
                        findings.append({
                            "path1": path1,
                            "path2": path2,
                            "same_content": True,
                            "potential_issue": "Cache key normalization mismatch",
                        })

            except requests.RequestException:
                continue

        if findings:
            pytest.fail(f"Cache key normalization issues detected: {findings}")

    @pytest.mark.cache_poisoning
    @pytest.mark.security
    def test_web_cache_deception(self, target_url, session):
        """Test for web cache deception vulnerabilities."""
        findings = []

        # Test if authenticated endpoints can be cached with static extensions
        auth_endpoints = [
            "/account",
            "/profile",
            "/dashboard",
            "/settings",
            "/api/user",
            "/api/me",
        ]

        for endpoint in auth_endpoints:
            for deception_path in CACHE_DECEPTION_PATHS:
                # Combine endpoint with deception path
                if deception_path.startswith("/"):
                    test_path = f"{endpoint}{deception_path}"
                else:
                    test_path = f"{endpoint}/{deception_path}"

                url = f"{target_url.rstrip('/')}{test_path}"

                try:
                    response = session.get(url, timeout=10)

                    # Check if response contains sensitive-looking data and has caching headers
                    cache_headers = self.get_cache_headers(response)

                    if response.status_code == 200:
                        # Check for caching indicators
                        if cache_headers:
                            # Check for sensitive data patterns
                            sensitive_patterns = [
                                "email", "username", "user_id", "token",
                                "password", "api_key", "session"
                            ]
                            for pattern in sensitive_patterns:
                                if pattern in response.text.lower():
                                    findings.append({
                                        "url": test_path,
                                        "status": response.status_code,
                                        "cache_headers": cache_headers,
                                        "sensitive_pattern": pattern,
                                    })
                                    break

                except requests.RequestException:
                    continue

        if findings:
            pytest.fail(
                f"Web cache deception vulnerability detected! "
                f"Sensitive data may be cached with static extensions: {findings}"
            )

    @pytest.mark.cache_poisoning
    @pytest.mark.security
    def test_parameter_cloaking(self, target_url, session):
        """Test for parameter cloaking / HPP in cache contexts."""
        findings = []

        cache_buster = generate_cache_buster()

        # Test parameter cloaking techniques
        cloaking_tests = [
            # Semicolon as parameter separator
            f"?cb={cache_buster};evil=<script>alert(1)</script>",
            # Duplicate parameters
            f"?cb={cache_buster}&cb=evil",
            # Encoded separators
            f"?cb={cache_buster}%26evil=true",
            # Null byte
            f"?cb={cache_buster}%00evil=true",
            # Unicode separators
            f"?cb={cache_buster}%ef%bb%bfevil=true",
        ]

        for test_param in cloaking_tests:
            url = f"{target_url.rstrip('/')}/{test_param}"

            try:
                response = session.get(url, timeout=10)

                # Check if cloaked parameter is reflected
                if "evil" in response.text.lower() or "script" in response.text.lower():
                    findings.append({
                        "url": test_param,
                        "reflected": True,
                        "status": response.status_code,
                    })

            except requests.RequestException:
                continue

        if findings:
            pytest.fail(f"Parameter cloaking detected: {findings}")

    @pytest.mark.cache_poisoning
    @pytest.mark.security
    def test_vary_header_exploitation(self, target_url, session):
        """Test for Vary header-based cache poisoning."""
        findings = []

        cache_buster = generate_cache_buster()
        test_url = f"{target_url.rstrip('/')}/?vcb={cache_buster}"

        # Headers that might be in Vary but exploitable
        vary_headers = [
            {"User-Agent": "PoisonedAgent/<script>alert(1)</script>"},
            {"Accept-Language": "en-poison"},
            {"Accept": "text/poison"},
            {"Cookie": "poison=true"},
            {"Origin": "https://evil.com"},
            {"Referer": "https://evil.com/"},
        ]

        try:
            # First check what Vary headers the server uses
            response = session.get(test_url, timeout=10)
            vary_header = response.headers.get("Vary", "")

            for payload in vary_headers:
                header_name = list(payload.keys())[0]

                # If this header is in Vary, it affects cache key
                if header_name.lower() in vary_header.lower():
                    poisoned_response = session.get(test_url, headers=payload, timeout=10)

                    # Check if our value is reflected
                    value = list(payload.values())[0]
                    if value.lower() in poisoned_response.text.lower():
                        findings.append({
                            "header": header_name,
                            "value": value,
                            "in_vary": True,
                            "reflected": True,
                        })

        except requests.RequestException:
            pass

        if findings:
            pytest.fail(f"Vary header exploitation detected: {findings}")

    @pytest.mark.cache_poisoning
    @pytest.mark.security
    def test_crlf_cache_poisoning(self, target_url, session):
        """Test for CRLF injection in cache poisoning context."""
        findings = []

        cache_buster = generate_cache_buster()

        for payload in CRLF_PAYLOADS:
            # Try in X-Forwarded-Host
            try:
                test_url = f"{target_url.rstrip('/')}/?crlf={cache_buster}"
                response = session.get(
                    test_url,
                    headers={"X-Forwarded-Host": payload},
                    timeout=10
                )

                # Check for injected headers in response
                if "X-Injected" in response.headers or "poisoned" in str(response.headers).lower():
                    findings.append({
                        "type": "header_injection",
                        "payload": payload[:50],
                        "evidence": "Header injected in response",
                    })

                # Check for response splitting
                if "\r\n" in response.text[:500] or "poisoned" in response.text.lower():
                    findings.append({
                        "type": "response_splitting",
                        "payload": payload[:50],
                    })

            except requests.RequestException:
                continue

        if findings:
            pytest.fail(f"CRLF injection detected (cache poisoning risk): {findings}")

    @pytest.mark.cache_poisoning
    @pytest.mark.security
    def test_cache_poisoning_dos(self, target_url, session):
        """Test for cache poisoning DoS via error caching."""
        findings = []

        # Try to poison cache with error responses
        dos_payloads = [
            {"X-Forwarded-Host": "nonexistent.invalid"},
            {"Host": ""},
            {"X-Original-URL": "/nonexistent-" + generate_cache_buster()},
        ]

        for payload in dos_payloads:
            cache_buster = generate_cache_buster()
            test_url = f"{target_url.rstrip('/')}/?dos={cache_buster}"

            try:
                # Request with DoS payload
                response1 = session.get(test_url, headers=payload, timeout=10)

                # Check if error response might be cached
                if response1.status_code >= 400:
                    cache_headers = self.get_cache_headers(response1)
                    if cache_headers:
                        # Verify by making clean request
                        time.sleep(0.5)
                        response2 = session.get(test_url, timeout=10)

                        if response2.status_code >= 400:
                            findings.append({
                                "payload": str(payload),
                                "error_code": response1.status_code,
                                "cache_headers": cache_headers,
                                "error_cached": True,
                            })

            except requests.RequestException:
                continue

        if findings:
            pytest.fail(f"Cache poisoning DoS risk detected: {findings}")
