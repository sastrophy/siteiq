"""
Server-Side Request Forgery (SSRF) Tests

Tests for SSRF vulnerabilities including:
- Internal network access
- Cloud metadata service access (AWS, GCP, Azure)
- Protocol smuggling
- Blind SSRF detection
"""

import re
from urllib.parse import urljoin, urlencode, urlparse
from typing import List, Dict, Any, Optional

import pytest

from utils.scanner import SecurityScanner, Finding, Severity
from payloads.ssrf import (
    SSRF_LOCALHOST_PAYLOADS,
    SSRF_CLOUD_METADATA_PAYLOADS,
    SSRF_INTERNAL_NETWORK_PAYLOADS,
    SSRF_PROTOCOL_PAYLOADS,
    SSRF_VULNERABLE_PARAMS,
    SSRF_SUCCESS_SIGNATURES,
)


@pytest.fixture
def ssrf_scanner(test_config):
    """Create scanner for SSRF tests."""
    return SecurityScanner(test_config)


class TestSSRFVulnerabilities:
    """Server-Side Request Forgery test suite."""

    def _check_ssrf_response(self, response_text: str, signature_type: str) -> bool:
        """Check if response indicates successful SSRF."""
        if not response_text:
            return False

        signatures = SSRF_SUCCESS_SIGNATURES.get(signature_type, [])
        response_lower = response_text.lower()

        for sig in signatures:
            if sig.lower() in response_lower:
                return True
        return False

    def _find_url_parameters(self, scanner: SecurityScanner, target_url: str) -> List[Dict[str, Any]]:
        """Find parameters that might accept URLs."""
        found_params = []

        # Get the page and look for forms/links with URL-like parameters
        resp = scanner.request("GET", target_url)
        if not resp or resp.status_code != 200:
            return found_params

        # Check URL query parameters
        parsed = urlparse(target_url)
        if parsed.query:
            for param in parsed.query.split("&"):
                if "=" in param:
                    name = param.split("=")[0]
                    if name.lower() in [p.lower() for p in SSRF_VULNERABLE_PARAMS]:
                        found_params.append({"name": name, "method": "GET", "in_url": True})

        # Look for forms in response
        # Simple regex to find input fields
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(input_pattern, resp.text, re.IGNORECASE)
        for match in matches:
            if match.lower() in [p.lower() for p in SSRF_VULNERABLE_PARAMS]:
                found_params.append({"name": match, "method": "POST", "in_url": False})

        return found_params

    @pytest.mark.security
    @pytest.mark.ssrf
    @pytest.mark.ssrf_localhost
    def test_ssrf_localhost_access(self, ssrf_scanner, target_url, findings_collector):
        """Test for SSRF to localhost/127.0.0.1."""
        resp = ssrf_scanner.request("GET", target_url)
        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target URL")

        vulnerabilities = []

        # Test common vulnerable parameters
        for param in SSRF_VULNERABLE_PARAMS[:20]:
            for payload_info in SSRF_LOCALHOST_PAYLOADS[:15]:
                payload = payload_info["payload"]
                description = payload_info["description"]

                # Test via GET parameter
                test_url = f"{target_url}?{urlencode({param: payload})}"
                resp = ssrf_scanner.request("GET", test_url, timeout=10)

                if resp:
                    # Check for localhost access indicators
                    if self._check_ssrf_response(resp.text, "localhost_access"):
                        vulnerabilities.append({
                            "param": param,
                            "payload": payload,
                            "description": description,
                            "method": "GET",
                            "evidence": resp.text[:500],
                        })
                        break

                    # Check for internal service indicators
                    if self._check_ssrf_response(resp.text, "internal_services"):
                        vulnerabilities.append({
                            "param": param,
                            "payload": payload,
                            "description": description,
                            "method": "GET",
                            "evidence": resp.text[:500],
                        })
                        break

                # Test via POST
                resp = ssrf_scanner.request(
                    "POST",
                    target_url,
                    data={param: payload},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=10
                )

                if resp and self._check_ssrf_response(resp.text, "localhost_access"):
                    vulnerabilities.append({
                        "param": param,
                        "payload": payload,
                        "description": description,
                        "method": "POST",
                        "evidence": resp.text[:500],
                    })
                    break

        for vuln in vulnerabilities:
            finding = Finding(
                title=f"SSRF: Localhost Access ({vuln['description']})",
                severity=Severity.HIGH,
                description=f"The application is vulnerable to Server-Side Request Forgery. "
                           f"An attacker can force the server to make requests to localhost/internal services. "
                           f"Parameter: {vuln['param']}, Payload: {vuln['payload']}",
                url=target_url,
                evidence=f"Method: {vuln['method']} | Param: {vuln['param']} | Response snippet: {vuln['evidence'][:200]}",
                remediation="Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains. "
                           "Block requests to private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). "
                           "Disable unnecessary URL schemes (file://, gopher://, etc.).",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
            )
            findings_collector.add(finding)
            ssrf_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.ssrf
    @pytest.mark.ssrf_cloud
    def test_ssrf_cloud_metadata(self, ssrf_scanner, target_url, findings_collector):
        """Test for SSRF to cloud metadata services (AWS, GCP, Azure)."""
        resp = ssrf_scanner.request("GET", target_url)
        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target URL")

        vulnerabilities = []

        for param in SSRF_VULNERABLE_PARAMS[:15]:
            for payload_info in SSRF_CLOUD_METADATA_PAYLOADS:
                payload = payload_info["payload"]
                description = payload_info["description"]
                cloud = payload_info.get("cloud", "unknown")

                # Test via GET
                test_url = f"{target_url}?{urlencode({param: payload})}"

                # For GCP, add required header
                headers = {}
                if cloud == "gcp":
                    headers["Metadata-Flavor"] = "Google"

                resp = ssrf_scanner.request("GET", test_url, headers=headers, timeout=10)

                if resp:
                    signature_type = f"{cloud}_metadata"
                    if self._check_ssrf_response(resp.text, signature_type):
                        vulnerabilities.append({
                            "param": param,
                            "payload": payload,
                            "description": description,
                            "cloud": cloud,
                            "method": "GET",
                            "evidence": resp.text[:500],
                        })
                        break

        for vuln in vulnerabilities:
            finding = Finding(
                title=f"SSRF: Cloud Metadata Access ({vuln['cloud'].upper()})",
                severity=Severity.CRITICAL,
                description=f"CRITICAL: The application can access cloud metadata services. "
                           f"This can expose AWS credentials, GCP service account tokens, or Azure managed identity tokens. "
                           f"Cloud: {vuln['cloud'].upper()}, Endpoint: {vuln['payload']}",
                url=target_url,
                evidence=f"Param: {vuln['param']} | Cloud: {vuln['cloud']} | Response: {vuln['evidence'][:300]}",
                remediation="Block access to cloud metadata IPs (169.254.169.254, 100.100.100.200). "
                           "Use IMDSv2 on AWS which requires session tokens. "
                           "Implement strict URL validation with domain allowlists. "
                           "Consider using a metadata proxy that requires authentication.",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
            )
            findings_collector.add(finding)
            ssrf_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.ssrf
    @pytest.mark.ssrf_internal
    def test_ssrf_internal_network(self, ssrf_scanner, target_url, findings_collector):
        """Test for SSRF to internal network resources."""
        resp = ssrf_scanner.request("GET", target_url)
        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target URL")

        vulnerabilities = []

        for param in SSRF_VULNERABLE_PARAMS[:10]:
            for payload_info in SSRF_INTERNAL_NETWORK_PAYLOADS[:15]:
                payload = payload_info["payload"]
                description = payload_info["description"]

                test_url = f"{target_url}?{urlencode({param: payload})}"
                resp = ssrf_scanner.request("GET", test_url, timeout=5)

                if resp and resp.status_code == 200:
                    # Check for internal service indicators
                    if self._check_ssrf_response(resp.text, "internal_services"):
                        vulnerabilities.append({
                            "param": param,
                            "payload": payload,
                            "description": description,
                            "evidence": resp.text[:500],
                        })
                        break

                    # Check for any HTML content (might indicate internal web service)
                    if "<html" in resp.text.lower() or "<body" in resp.text.lower():
                        # Could be internal web service
                        if len(resp.text) > 100:
                            vulnerabilities.append({
                                "param": param,
                                "payload": payload,
                                "description": f"{description} - Potential internal web service",
                                "evidence": resp.text[:500],
                            })
                            break

        for vuln in vulnerabilities:
            finding = Finding(
                title=f"SSRF: Internal Network Access ({vuln['description']})",
                severity=Severity.HIGH,
                description=f"The application can make requests to internal network resources. "
                           f"This could allow port scanning, internal service discovery, or data exfiltration. "
                           f"Parameter: {vuln['param']}, Target: {vuln['payload']}",
                url=target_url,
                evidence=f"Param: {vuln['param']} | Payload: {vuln['payload']} | Response: {vuln['evidence'][:200]}",
                remediation="Implement URL validation with domain allowlists. "
                           "Block requests to private IP ranges. "
                           "Use network segmentation to isolate the application from internal services.",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
            )
            findings_collector.add(finding)
            ssrf_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.ssrf
    @pytest.mark.ssrf_protocol
    def test_ssrf_protocol_smuggling(self, ssrf_scanner, target_url, findings_collector):
        """Test for SSRF via protocol smuggling (file://, gopher://, etc.)."""
        resp = ssrf_scanner.request("GET", target_url)
        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target URL")

        vulnerabilities = []

        for param in SSRF_VULNERABLE_PARAMS[:10]:
            for payload_info in SSRF_PROTOCOL_PAYLOADS:
                payload = payload_info["payload"]
                description = payload_info["description"]
                protocol = payload_info.get("protocol", "unknown")

                test_url = f"{target_url}?{urlencode({param: payload})}"
                resp = ssrf_scanner.request("GET", test_url, timeout=10)

                if resp:
                    # Check for file read indicators
                    if protocol == "file" and self._check_ssrf_response(resp.text, "file_read"):
                        vulnerabilities.append({
                            "param": param,
                            "payload": payload,
                            "description": description,
                            "protocol": protocol,
                            "evidence": resp.text[:500],
                        })
                        break

                    # Check for internal service indicators (gopher/dict)
                    if protocol in ["gopher", "dict"] and self._check_ssrf_response(resp.text, "internal_services"):
                        vulnerabilities.append({
                            "param": param,
                            "payload": payload,
                            "description": description,
                            "protocol": protocol,
                            "evidence": resp.text[:500],
                        })
                        break

        for vuln in vulnerabilities:
            severity = Severity.CRITICAL if vuln["protocol"] == "file" else Severity.HIGH
            finding = Finding(
                title=f"SSRF: Protocol Smuggling ({vuln['protocol']}://)",
                severity=severity,
                description=f"The application is vulnerable to SSRF via the {vuln['protocol']}:// protocol. "
                           f"This can allow file reading, internal service access, or even code execution. "
                           f"Payload: {vuln['payload']}",
                url=target_url,
                evidence=f"Protocol: {vuln['protocol']} | Param: {vuln['param']} | Response: {vuln['evidence'][:200]}",
                remediation=f"Disable the {vuln['protocol']}:// protocol handler. "
                           "Only allow http:// and https:// schemes. "
                           "Implement strict URL parsing and validation.",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
            )
            findings_collector.add(finding)
            ssrf_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.ssrf
    @pytest.mark.ssrf_blind
    def test_ssrf_blind_detection(self, ssrf_scanner, target_url, findings_collector):
        """Test for blind SSRF via timing analysis."""
        resp = ssrf_scanner.request("GET", target_url)
        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target URL")

        # Blind SSRF detection via timing
        # Compare response times for reachable vs unreachable targets
        import time

        vulnerabilities = []

        for param in SSRF_VULNERABLE_PARAMS[:5]:
            # Baseline: request to valid external URL
            baseline_start = time.time()
            ssrf_scanner.request(
                "GET",
                f"{target_url}?{urlencode({param: 'http://example.com'})}",
                timeout=10
            )
            baseline_time = time.time() - baseline_start

            # Test: request to unreachable internal IP (should timeout or be slow)
            test_start = time.time()
            resp = ssrf_scanner.request(
                "GET",
                f"{target_url}?{urlencode({param: 'http://10.255.255.1/'})}",
                timeout=10
            )
            test_time = time.time() - test_start

            # If test takes significantly longer, might indicate blind SSRF
            # (server is actually trying to connect to the internal IP)
            if test_time > baseline_time + 3:  # 3 second difference threshold
                vulnerabilities.append({
                    "param": param,
                    "baseline_time": baseline_time,
                    "test_time": test_time,
                })

        for vuln in vulnerabilities:
            finding = Finding(
                title=f"Potential Blind SSRF Detected",
                severity=Severity.MEDIUM,
                description=f"The application shows timing differences when requesting internal vs external URLs, "
                           f"which may indicate blind SSRF. The server took {vuln['test_time']:.2f}s for internal IP "
                           f"vs {vuln['baseline_time']:.2f}s for external URL.",
                url=target_url,
                evidence=f"Parameter: {vuln['param']} | Baseline: {vuln['baseline_time']:.2f}s | Test: {vuln['test_time']:.2f}s",
                remediation="Investigate this parameter for SSRF vulnerabilities. "
                           "Use out-of-band (OOB) testing with a callback server to confirm. "
                           "Implement URL validation and block internal IP ranges.",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
            )
            findings_collector.add(finding)
            ssrf_scanner.add_finding(finding)
