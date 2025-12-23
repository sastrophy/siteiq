"""
Server-Side Template Injection (SSTI) Tests

Tests for template injection vulnerabilities across various
template engines that can lead to RCE.
"""

import pytest
from urllib.parse import urljoin, urlencode

from utils.scanner import SecurityScanner, Finding, Severity
from payloads.ssti import (
    SSTI_DETECTION_PAYLOADS,
    JINJA2_PAYLOADS,
    TWIG_PAYLOADS,
    FREEMARKER_PAYLOADS,
    SMARTY_PAYLOADS,
    ERB_PAYLOADS,
    POLYGLOT_PAYLOADS,
    SSTI_VULNERABLE_PARAMS,
)


@pytest.fixture
def ssti_scanner(test_config):
    """Create scanner for SSTI tests."""
    return SecurityScanner(test_config)


class TestSSTIVulnerabilities:
    """Server-Side Template Injection test suite."""

    def _check_ssti_response(self, response_text: str, expected: str) -> bool:
        """Check if SSTI payload was executed."""
        if not response_text:
            return False
        return expected in response_text

    @pytest.mark.security
    @pytest.mark.ssti
    @pytest.mark.ssti_detection
    def test_ssti_arithmetic_detection(self, ssti_scanner, target_url, findings_collector):
        """Test for SSTI using arithmetic evaluation."""
        # Get the main page to find form inputs and URL parameters
        resp = ssti_scanner.request("GET", target_url)
        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target URL")

        vulnerable_params = []

        # Test common vulnerable parameters
        for param in SSTI_VULNERABLE_PARAMS[:15]:
            for payload_info in SSTI_DETECTION_PAYLOADS[:5]:
                payload = payload_info["payload"]
                expected = payload_info["expected"]
                engines = payload_info.get("engines", [])

                # Test via GET parameter
                test_url = f"{target_url}?{urlencode({param: payload})}"
                resp = ssti_scanner.request("GET", test_url)

                if resp and self._check_ssti_response(resp.text, expected):
                    vulnerable_params.append({
                        "param": param,
                        "payload": payload,
                        "expected": expected,
                        "engines": engines,
                        "method": "GET",
                    })
                    break

                # Test via POST
                resp = ssti_scanner.request(
                    "POST",
                    target_url,
                    data={param: payload},
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )

                if resp and self._check_ssti_response(resp.text, expected):
                    vulnerable_params.append({
                        "param": param,
                        "payload": payload,
                        "expected": expected,
                        "engines": engines,
                        "method": "POST",
                    })
                    break

        if vulnerable_params:
            vuln = vulnerable_params[0]
            finding = Finding(
                title="Server-Side Template Injection (SSTI)",
                severity=Severity.CRITICAL,
                description=f"SSTI vulnerability detected in parameter '{vuln['param']}'. The server executed the arithmetic expression, indicating template injection is possible. Potential engines: {', '.join(vuln['engines'])}",
                url=target_url,
                evidence=f"Parameter: {vuln['param']}, Method: {vuln['method']}, Payload: {vuln['payload']}, Expected: {vuln['expected']}",
                remediation="Never pass user input directly to template engines. Use parameterized templates. Implement input validation and output encoding. Consider using logic-less templates.",
                cwe_id="CWE-94",
                owasp_category="A03:2021 - Injection",
            )
            findings_collector.add(finding)
            ssti_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.ssti
    @pytest.mark.jinja2
    def test_jinja2_ssti(self, ssti_scanner, target_url, findings_collector):
        """Test for Jinja2-specific SSTI vulnerabilities."""
        for param in SSTI_VULNERABLE_PARAMS[:10]:
            for payload_info in JINJA2_PAYLOADS[:5]:
                payload = payload_info["payload"]
                check = payload_info["check"]

                # Test GET
                test_url = f"{target_url}?{urlencode({param: payload})}"
                resp = ssti_scanner.request("GET", test_url)

                if resp and check.lower() in resp.text.lower():
                    finding = Finding(
                        title=f"Jinja2 SSTI - {payload_info['description']}",
                        severity=Severity.CRITICAL,
                        description=f"Jinja2 template injection detected. {payload_info['description']}. This can potentially lead to Remote Code Execution.",
                        url=target_url,
                        evidence=f"Parameter: {param}, Payload: {payload[:50]}..., Found: {check}",
                        remediation="Use Jinja2's sandboxed environment. Never pass untrusted input to render(). Enable autoescape. Use template.module for safe rendering.",
                        cwe_id="CWE-94",
                        owasp_category="A03:2021 - Injection",
                    )
                    findings_collector.add(finding)
                    ssti_scanner.add_finding(finding)
                    return

                # Test POST
                resp = ssti_scanner.request(
                    "POST",
                    target_url,
                    data={param: payload},
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )

                if resp and check.lower() in resp.text.lower():
                    finding = Finding(
                        title=f"Jinja2 SSTI (POST) - {payload_info['description']}",
                        severity=Severity.CRITICAL,
                        description=f"Jinja2 template injection detected via POST. {payload_info['description']}.",
                        url=target_url,
                        evidence=f"Parameter: {param}, Method: POST, Found: {check}",
                        remediation="Use sandboxed Jinja2 environment. Validate and sanitize all user inputs before template rendering.",
                        cwe_id="CWE-94",
                        owasp_category="A03:2021 - Injection",
                    )
                    findings_collector.add(finding)
                    ssti_scanner.add_finding(finding)
                    return

    @pytest.mark.security
    @pytest.mark.ssti
    @pytest.mark.twig
    def test_twig_ssti(self, ssti_scanner, target_url, findings_collector):
        """Test for Twig (PHP) SSTI vulnerabilities."""
        for param in SSTI_VULNERABLE_PARAMS[:10]:
            for payload_info in TWIG_PAYLOADS[:3]:
                payload = payload_info["payload"]
                check = payload_info["check"]

                test_url = f"{target_url}?{urlencode({param: payload})}"
                resp = ssti_scanner.request("GET", test_url)

                if resp and check.lower() in resp.text.lower():
                    finding = Finding(
                        title=f"Twig SSTI - {payload_info['description']}",
                        severity=Severity.CRITICAL,
                        description=f"Twig template injection detected. {payload_info['description']}.",
                        url=target_url,
                        evidence=f"Parameter: {param}, Payload: {payload[:50]}..., Found: {check}",
                        remediation="Use Twig's sandbox extension. Disable dangerous filters and functions. Never pass user input directly to Twig templates.",
                        cwe_id="CWE-94",
                        owasp_category="A03:2021 - Injection",
                    )
                    findings_collector.add(finding)
                    ssti_scanner.add_finding(finding)
                    return

    @pytest.mark.security
    @pytest.mark.ssti
    @pytest.mark.freemarker
    def test_freemarker_ssti(self, ssti_scanner, target_url, findings_collector):
        """Test for FreeMarker (Java) SSTI vulnerabilities."""
        for param in SSTI_VULNERABLE_PARAMS[:10]:
            for payload_info in FREEMARKER_PAYLOADS[:3]:
                payload = payload_info["payload"]
                check = payload_info["check"]

                test_url = f"{target_url}?{urlencode({param: payload})}"
                resp = ssti_scanner.request("GET", test_url)

                if resp and check.lower() in resp.text.lower():
                    finding = Finding(
                        title=f"FreeMarker SSTI - {payload_info['description']}",
                        severity=Severity.CRITICAL,
                        description=f"FreeMarker template injection detected. {payload_info['description']}. This typically leads to RCE on Java applications.",
                        url=target_url,
                        evidence=f"Parameter: {param}, Payload: {payload[:50]}..., Found: {check}",
                        remediation="Disable new() built-in. Use TemplateClassResolver.SAFER_RESOLVER. Sandbox the template environment.",
                        cwe_id="CWE-94",
                        owasp_category="A03:2021 - Injection",
                    )
                    findings_collector.add(finding)
                    ssti_scanner.add_finding(finding)
                    return

    @pytest.mark.security
    @pytest.mark.ssti
    @pytest.mark.smarty
    def test_smarty_ssti(self, ssti_scanner, target_url, findings_collector):
        """Test for Smarty (PHP) SSTI vulnerabilities."""
        for param in SSTI_VULNERABLE_PARAMS[:10]:
            for payload_info in SMARTY_PAYLOADS[:3]:
                payload = payload_info["payload"]
                check = payload_info["check"]

                test_url = f"{target_url}?{urlencode({param: payload})}"
                resp = ssti_scanner.request("GET", test_url)

                if resp and check.lower() in resp.text.lower():
                    finding = Finding(
                        title=f"Smarty SSTI - {payload_info['description']}",
                        severity=Severity.CRITICAL,
                        description=f"Smarty template injection detected. {payload_info['description']}.",
                        url=target_url,
                        evidence=f"Parameter: {param}, Payload: {payload[:50]}..., Found: {check}",
                        remediation="Disable PHP tags in Smarty. Use $smarty->security_policy. Validate all user inputs.",
                        cwe_id="CWE-94",
                        owasp_category="A03:2021 - Injection",
                    )
                    findings_collector.add(finding)
                    ssti_scanner.add_finding(finding)
                    return

    @pytest.mark.security
    @pytest.mark.ssti
    @pytest.mark.erb
    def test_erb_ssti(self, ssti_scanner, target_url, findings_collector):
        """Test for ERB (Ruby) SSTI vulnerabilities."""
        for param in SSTI_VULNERABLE_PARAMS[:10]:
            for payload_info in ERB_PAYLOADS[:3]:
                payload = payload_info["payload"]
                check = payload_info["check"]

                test_url = f"{target_url}?{urlencode({param: payload})}"
                resp = ssti_scanner.request("GET", test_url)

                if resp and check.lower() in resp.text.lower():
                    finding = Finding(
                        title=f"ERB SSTI - {payload_info['description']}",
                        severity=Severity.CRITICAL,
                        description=f"ERB template injection detected. {payload_info['description']}. This allows Ruby code execution.",
                        url=target_url,
                        evidence=f"Parameter: {param}, Payload: {payload[:50]}..., Found: {check}",
                        remediation="Never use ERB.new with user input. Use ERB.new(template).result(binding) with sanitized binding. Consider using safer templating alternatives.",
                        cwe_id="CWE-94",
                        owasp_category="A03:2021 - Injection",
                    )
                    findings_collector.add(finding)
                    ssti_scanner.add_finding(finding)
                    return

    @pytest.mark.security
    @pytest.mark.ssti
    @pytest.mark.polyglot
    def test_ssti_polyglot(self, ssti_scanner, target_url, findings_collector):
        """Test for SSTI using polyglot payloads that work across multiple engines."""
        for param in SSTI_VULNERABLE_PARAMS[:10]:
            for payload_info in POLYGLOT_PAYLOADS:
                payload = payload_info["payload"]
                check = payload_info["check"]

                test_url = f"{target_url}?{urlencode({param: payload})}"
                resp = ssti_scanner.request("GET", test_url)

                if resp and check in resp.text:
                    finding = Finding(
                        title="SSTI Detected (Polyglot)",
                        severity=Severity.CRITICAL,
                        description=f"Template injection detected using polyglot payload. {payload_info['description']}",
                        url=target_url,
                        evidence=f"Parameter: {param}, Polyglot payload triggered",
                        remediation="Identify the specific template engine and apply appropriate mitigations. Never pass user input directly to template rendering.",
                        cwe_id="CWE-94",
                        owasp_category="A03:2021 - Injection",
                    )
                    findings_collector.add(finding)
                    ssti_scanner.add_finding(finding)
                    return

    @pytest.mark.security
    @pytest.mark.ssti
    @pytest.mark.ssti_error
    def test_ssti_error_based(self, ssti_scanner, target_url, findings_collector):
        """Test for SSTI via error messages."""
        error_payloads = [
            {"payload": "{{", "engine": "Jinja2/Twig"},
            {"payload": "${", "engine": "FreeMarker"},
            {"payload": "<%", "engine": "ERB/JSP"},
            {"payload": "{%", "engine": "Jinja2/Twig"},
            {"payload": "#{", "engine": "Pug/Thymeleaf"},
        ]

        error_indicators = [
            "TemplateSyntaxError",
            "template error",
            "parsing error",
            "unexpected token",
            "SyntaxError",
            "FreeMarkerException",
            "ParseException",
            "TemplateError",
            "Twig_Error",
            "erb:",
            "ActionView::Template::Error",
        ]

        for param in SSTI_VULNERABLE_PARAMS[:10]:
            for error_payload in error_payloads:
                payload = error_payload["payload"]
                engine = error_payload["engine"]

                test_url = f"{target_url}?{urlencode({param: payload})}"
                resp = ssti_scanner.request("GET", test_url)

                if resp:
                    resp_text = resp.text.lower()
                    for indicator in error_indicators:
                        if indicator.lower() in resp_text:
                            finding = Finding(
                                title=f"SSTI Indicated by Error ({engine})",
                                severity=Severity.MEDIUM,
                                description=f"Template error triggered by malformed payload suggests {engine} template engine. Further testing recommended.",
                                url=target_url,
                                evidence=f"Parameter: {param}, Payload: {payload}, Error indicator: {indicator}",
                                remediation="Even if full exploitation wasn't achieved, the presence of template errors indicates potential SSTI. Review and sanitize template inputs.",
                                cwe_id="CWE-94",
                                owasp_category="A03:2021 - Injection",
                            )
                            findings_collector.add(finding)
                            ssti_scanner.add_finding(finding)
                            return
