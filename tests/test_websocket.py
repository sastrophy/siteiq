"""
WebSockets Security Tests

Tests for WebSocket security testing including:
- Cross-origin attacks
- Message injection
- Frame manipulation
- Authentication bypass
"""

import json

import pytest

from utils.scanner import SecurityScanner, Finding, Severity


@pytest.fixture
def websocket_scanner(test_config):
    """Create scanner for WebSocket tests."""
    return SecurityScanner(test_config)


class TestWebSockets:
    """WebSocket security test suite."""

    @pytest.mark.security
    @pytest.mark.websocket
    def test_origin_header_bypass(self, websocket_scanner, target_url, findings_collector):
        """Test for Origin header bypass in WebSocket."""
        origins = ["http://evil.com", "http://attacker.com", "null", "file://"]

        for origin in origins[:3]:
            headers = {"Origin": origin}

            resp = websocket_scanner.get(target_url, headers=headers)

            if resp and resp.status_code == 101:
                finding = Finding(
                    title="WebSocket Origin Header Accepted",
                    severity=Severity.MEDIUM,
                    description=f"WebSocket accepts arbitrary Origin header: {origin}",
                    url=target_url,
                    evidence=f"Origin: {origin} - Status: 101 (WebSocket Upgrade)",
                    remediation="Validate Origin header against whitelist. Reject unknown or untrusted origins.",
                    cwe_id="CWE-346",
                    owasp_category="A01:2021 - Broken Access Control",
                )
                findings_collector.add(finding)
                websocket_scanner.add_finding(finding)
                return

    @pytest.mark.security
    @pytest.mark.websocket
    def test_ws_message_injection(self, websocket_scanner, target_url, findings_collector):
        """Test for XSS via WebSocket message injection."""
        test_paths = ["/chat", "/ws", "/socket", "/api/ws"]

        for path in test_paths[:2]:
            url = f"{target_url}{path}"

            try:
                headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "test_key",
                    "Sec-WebSocket-Version": "13",
                }

                resp = websocket_scanner.get(url, headers=headers)

                if resp and resp.status_code == 101:
                    xss_payloads = [
                        '<script>alert(1)</script>',
                        '<img src=x onerror=alert(1)>',
                        'javascript:alert(1)',
                        'data:text/html,<script>alert(1)</script>',
                    ]

                    for payload in xss_payloads:
                        ws_message = json.dumps({"type": "message", "content": payload})

                        try:
                            test_resp = websocket_scanner.post(url, data=ws_message, headers=headers)

                            if test_resp and test_resp.status_code == 200:
                                finding = Finding(
                                    title="WebSocket Message XSS Possible",
                                    severity=Severity.HIGH,
                                    description=f"WebSocket endpoint accepts unfiltered messages - {payload[:100]}",
                                    url=url,
                                    evidence=f"XSS payload in WebSocket message",
                                    remediation="Validate WebSocket messages server-side. Sanitize and escape output.",
                                    cwe_id="CWE-79",
                                    owasp_category="A03:2021 - Injection",
                                )
                                findings_collector.add(finding)
                                websocket_scanner.add_finding(finding)
                        except Exception:
                            pass
            except Exception:
                pass

    @pytest.mark.security
    @pytest.mark.websocket
    def test_ws_authentication_bypass(self, websocket_scanner, target_url, findings_collector):
        """Test for weak WebSocket authentication."""
        test_paths = ["/ws", "/socket", "/api/websocket", "/chat"]

        for path in test_paths[:2]:
            url = f"{target_url}{path}"

            try:
                headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                }

                no_auth_payloads = [
                    {"auth": False},
                    {"token": ""},
                    {"session": "existing_session_id"},
                    {"user": "admin"},
                ]

                for payload in no_auth_payloads:
                    resp = websocket_scanner.post(url, json=payload, headers=headers)

                    if resp and resp.status_code in [200, 101]:
                        text = resp.text.lower()

                        if "accepted" in text or "connected" in text or "welcome" in text:
                            finding = Finding(
                                title="WebSocket Authentication Bypass",
                                severity=Severity.HIGH,
                                description=f"Weak WebSocket authentication - {payload}",
                                url=url,
                                evidence="No authentication required for WebSocket connection",
                                remediation="Implement proper WebSocket authentication. Require valid tokens.",
                                cwe_id="CWE-287",
                                owasp_category="A07:2021 - Identification and Authentication Failures",
                            )
                            findings_collector.add(finding)
                            websocket_scanner.add_finding(finding)
            except Exception:
                pass

    @pytest.mark.security
    @pytest.mark.websocket
    def test_ws_user_enumeration(self, websocket_scanner, target_url, findings_collector):
        """Test for user enumeration via WebSocket."""
        test_paths = ["/ws", "/socket", "/api/ws"]

        for path in test_paths[:2]:
            url = f"{target_url}{path}"

            try:
                headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                }

                enum_payloads = [
                    {"user": "admin"},
                    {"user": "root"},
                    {"user": "test_user_1"},
                    {"user": "test_user_2"},
                ]

                for payload in enum_payloads:
                    resp = websocket_scanner.post(url, json=payload, headers=headers)

                    if resp and resp.status_code in [200, 101]:
                        text = resp.text.lower()

                        if "welcome" in text or "hello" in text:
                            finding = Finding(
                                title="WebSocket User Enumeration",
                                severity=Severity.MEDIUM,
                                description=f"Weak WebSocket allows user enumeration - {payload}",
                                url=url,
                                evidence="User enumeration via WebSocket",
                                remediation="Limit WebSocket messages. Use generic responses without user-specific info.",
                                cwe_id="CWE-204",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            websocket_scanner.add_finding(finding)
            except Exception:
                pass

    @pytest.mark.security
    @pytest.mark.websocket
    def test_ws_resource_consumption(self, websocket_scanner, target_url, findings_collector):
        """Test for WebSocket resource consumption DoS."""
        test_paths = ["/ws", "/socket", "/api/ws"]

        for path in test_paths[:1]:
            url = f"{target_url}{path}"

            try:
                headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                }

                dos_payloads = [
                    {"type": "message_flood", "count": 10000},
                    {"type": "ping_flood", "count": 10000},
                    {"type": "connection_flood", "count": 10000},
                ]

                for payload in dos_payloads:
                    resp = websocket_scanner.post(url, json=payload, headers=headers)

                    if resp and resp.status_code in [200, 101]:
                        finding = Finding(
                            title="WebSocket Resource Consumption Possible",
                            severity=Severity.MEDIUM,
                            description=f"WebSocket may be vulnerable to resource consumption - {payload}",
                            url=url,
                            evidence="High frequency connection attempt",
                            remediation="Implement rate limiting. Limit messages per connection. Use connection timeouts.",
                            cwe_id="CWE-770",
                            owasp_category="A05:2021 - Security Misconfiguration",
                        )
                        findings_collector.add(finding)
                        websocket_scanner.add_finding(finding)
            except Exception:
                pass
