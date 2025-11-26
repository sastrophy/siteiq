"""
Cross-Site Scripting (XSS) Security Tests

Tests for XSS vulnerabilities including:
- Reflected XSS
- Stored XSS detection points
- DOM-based XSS vectors
- Filter bypass techniques
"""

import re
from urllib.parse import quote

import pytest

from utils.scanner import SecurityScanner, Finding, Severity, extract_forms, check_reflection
from payloads.xss import (
    BASIC_XSS,
    EVENT_XSS,
    ENCODED_XSS,
    BYPASS_XSS,
    TEMPLATE_INJECTION,
    XSS_CANARIES,
    DOM_XSS,
)


@pytest.fixture
def xss_scanner(test_config):
    """Create scanner for XSS tests."""
    return SecurityScanner(test_config)


class TestReflectedXSS:
    """Tests for reflected XSS vulnerabilities."""

    @pytest.mark.xss
    def test_basic_reflected_xss(self, xss_scanner, target_url, findings_collector):
        """Test for basic reflected XSS in URL parameters."""
        # First test with canary to detect reflection
        test_endpoints = [
            f"{target_url}/search",
            f"{target_url}/",
            f"{target_url}/products",
            f"{target_url}/error",
            f"{target_url}/404",
        ]

        for endpoint in test_endpoints:
            # Test reflection first
            for canary in XSS_CANARIES:
                test_url = f"{endpoint}?q={canary}&search={canary}&query={canary}"
                resp = xss_scanner.get(test_url)

                if resp and canary in resp.text:
                    # Reflection detected, now test XSS payloads
                    self._test_xss_payloads(
                        xss_scanner, endpoint, canary, resp.text, findings_collector
                    )
                    break

    @pytest.mark.xss
    def test_xss_in_forms(self, xss_scanner, target_url, findings_collector):
        """Test for XSS vulnerabilities in form inputs."""
        resp = xss_scanner.get(target_url)
        if not resp:
            return

        forms = extract_forms(resp.text, target_url)

        for form in forms:
            for canary in XSS_CANARIES[:2]:  # Test with first two canaries
                form_data = {inp["name"]: canary for inp in form["inputs"]}

                if form["method"] == "POST":
                    form_resp = xss_scanner.post(form["action"], data=form_data)
                else:
                    form_resp = xss_scanner.get(form["action"], params=form_data)

                if form_resp and canary in form_resp.text:
                    # Test actual XSS payloads
                    for payload in BASIC_XSS[:5] + EVENT_XSS[:5]:
                        form_data = {inp["name"]: payload for inp in form["inputs"]}

                        if form["method"] == "POST":
                            xss_resp = xss_scanner.post(form["action"], data=form_data)
                        else:
                            xss_resp = xss_scanner.get(form["action"], params=form_data)

                        if xss_resp and self._check_xss_reflection(payload, xss_resp.text):
                            finding = Finding(
                                title="Reflected XSS in Form Input",
                                severity=Severity.HIGH,
                                description="XSS payload reflected without proper encoding in form",
                                url=form["action"],
                                evidence=f"Payload: {payload[:100]}, Fields: {[i['name'] for i in form['inputs']]}",
                                remediation="Encode all user input before rendering. Use Content-Security-Policy header.",
                                cwe_id="CWE-79",
                                owasp_category="A03:2021 - Injection",
                            )
                            findings_collector.add(finding)

    @pytest.mark.xss
    def test_xss_in_headers(self, xss_scanner, target_url, findings_collector):
        """Test for XSS via HTTP headers."""
        test_headers = {
            "User-Agent": "<script>alert(1)</script>",
            "Referer": "<script>alert(1)</script>",
            "X-Forwarded-For": "<script>alert(1)</script>",
            "X-Forwarded-Host": "<script>alert(1)</script>",
        }

        for header_name, payload in test_headers.items():
            resp = xss_scanner.get(target_url, headers={header_name: payload})

            if resp and self._check_xss_reflection(payload, resp.text):
                finding = Finding(
                    title=f"Reflected XSS via {header_name} Header",
                    severity=Severity.HIGH,
                    description=f"XSS payload in {header_name} header reflected in response",
                    url=target_url,
                    evidence=f"Header: {header_name}, Payload: {payload}",
                    remediation="Never reflect HTTP headers in responses without proper encoding.",
                    cwe_id="CWE-79",
                    owasp_category="A03:2021 - Injection",
                )
                findings_collector.add(finding)

    @pytest.mark.xss
    def test_xss_filter_bypass(self, xss_scanner, target_url, findings_collector, test_config):
        """Test XSS filter bypass techniques."""
        if test_config.intensity == "light":
            pytest.skip("Filter bypass tests skipped in light intensity mode")

        # Find reflective endpoints first
        reflective_endpoints = []
        test_endpoints = [
            f"{target_url}/search?q=REFLECTION_TEST",
            f"{target_url}/?s=REFLECTION_TEST",
            f"{target_url}/error?msg=REFLECTION_TEST",
        ]

        for endpoint in test_endpoints:
            resp = xss_scanner.get(endpoint)
            if resp and "REFLECTION_TEST" in resp.text:
                reflective_endpoints.append(endpoint.replace("REFLECTION_TEST", "{payload}"))

        # Test bypass payloads
        for endpoint_template in reflective_endpoints:
            for payload in BYPASS_XSS + ENCODED_XSS:
                url = endpoint_template.replace("{payload}", quote(payload))
                resp = xss_scanner.get(url)

                if resp and self._check_xss_reflection(payload, resp.text):
                    finding = Finding(
                        title="XSS Filter Bypass Detected",
                        severity=Severity.HIGH,
                        description="XSS payload bypassed input filters",
                        url=url[:200],
                        evidence=f"Bypass payload: {payload[:100]}",
                        remediation="Use context-aware output encoding. Implement Content-Security-Policy.",
                        cwe_id="CWE-79",
                        owasp_category="A03:2021 - Injection",
                    )
                    findings_collector.add(finding)

    def _test_xss_payloads(self, scanner, endpoint, canary, baseline_text, findings_collector):
        """Test various XSS payloads on a reflective endpoint."""
        payloads_to_test = BASIC_XSS[:5] + EVENT_XSS[:5]

        for payload in payloads_to_test:
            test_url = f"{endpoint}?q={quote(payload)}&search={quote(payload)}"
            resp = scanner.get(test_url)

            if resp and self._check_xss_reflection(payload, resp.text):
                finding = Finding(
                    title="Reflected XSS Vulnerability",
                    severity=Severity.HIGH,
                    description="XSS payload reflected without proper sanitization",
                    url=test_url[:200],
                    evidence=f"Payload: {payload[:100]}",
                    remediation="Implement proper output encoding based on context. Use CSP headers.",
                    cwe_id="CWE-79",
                    owasp_category="A03:2021 - Injection",
                )
                findings_collector.add(finding)

    def _check_xss_reflection(self, payload: str, response_text: str) -> bool:
        """Check if XSS payload is reflected without encoding."""
        if not response_text:
            return False

        # Check for exact reflection (dangerous)
        if payload in response_text:
            return True

        # Check for partial reflection of key XSS components
        dangerous_patterns = [
            r'<script[^>]*>',
            r'onerror\s*=',
            r'onload\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',
            r'javascript:',
            r'<svg[^>]*onload',
            r'<img[^>]*onerror',
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                # Verify it's from our payload, not existing page content
                if any(trigger in payload.lower() for trigger in ['script', 'onerror', 'onload', 'svg', 'img']):
                    return True

        return False


class TestDOMBasedXSS:
    """Tests for DOM-based XSS vulnerabilities."""

    @pytest.mark.xss
    def test_dom_xss_sources(self, xss_scanner, target_url, findings_collector):
        """Identify potential DOM XSS sources in JavaScript."""
        resp = xss_scanner.get(target_url)
        if not resp:
            return

        # DOM XSS source patterns
        source_patterns = [
            (r'document\.location', "document.location"),
            (r'document\.URL', "document.URL"),
            (r'document\.referrer', "document.referrer"),
            (r'window\.location', "window.location"),
            (r'location\.hash', "location.hash"),
            (r'location\.search', "location.search"),
            (r'location\.href', "location.href"),
            (r'document\.cookie', "document.cookie"),
            (r'window\.name', "window.name"),
        ]

        # DOM XSS sink patterns
        sink_patterns = [
            (r'\.innerHTML\s*=', "innerHTML"),
            (r'\.outerHTML\s*=', "outerHTML"),
            (r'document\.write\s*\(', "document.write"),
            (r'document\.writeln\s*\(', "document.writeln"),
            (r'eval\s*\(', "eval"),
            (r'setTimeout\s*\([^,]*,', "setTimeout"),
            (r'setInterval\s*\([^,]*,', "setInterval"),
            (r'\.src\s*=', "src assignment"),
            (r'\.href\s*=', "href assignment"),
        ]

        content = resp.text

        found_sources = []
        found_sinks = []

        for pattern, name in source_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_sources.append(name)

        for pattern, name in sink_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_sinks.append(name)

        if found_sources and found_sinks:
            finding = Finding(
                title="Potential DOM-Based XSS Vectors",
                severity=Severity.MEDIUM,
                description="JavaScript contains DOM XSS sources and sinks that may be vulnerable",
                url=target_url,
                evidence=f"Sources: {found_sources}, Sinks: {found_sinks}",
                remediation="Review JavaScript for unsafe DOM manipulation. Use textContent instead of innerHTML.",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
            )
            findings_collector.add(finding)

    @pytest.mark.xss
    def test_hash_based_dom_xss(self, xss_scanner, target_url, findings_collector):
        """Test for DOM XSS via URL hash."""
        # These payloads target hash-based routing vulnerabilities
        for payload in DOM_XSS:
            test_url = f"{target_url}{payload}"
            resp = xss_scanner.get(test_url)

            # Note: DOM XSS won't be visible in response, but we document the test points
            if resp and resp.status_code == 200:
                # Check if page uses hash-based routing
                if "location.hash" in resp.text or "hashchange" in resp.text:
                    finding = Finding(
                        title="Potential Hash-Based DOM XSS",
                        severity=Severity.MEDIUM,
                        description="Application uses URL hash which may be vulnerable to DOM XSS",
                        url=test_url,
                        evidence="Manual testing with browser required to confirm",
                        remediation="Sanitize hash values before using in DOM operations.",
                        cwe_id="CWE-79",
                        owasp_category="A03:2021 - Injection",
                    )
                    findings_collector.add(finding)
                    break


class TestStoredXSSLocations:
    """Identify locations where stored XSS could occur."""

    @pytest.mark.xss
    def test_stored_xss_entry_points(self, xss_scanner, target_url, findings_collector):
        """Identify entry points for potential stored XSS."""
        # Common stored XSS entry points
        entry_points = [
            ("/comment", "Comment form"),
            ("/review", "Review form"),
            ("/feedback", "Feedback form"),
            ("/contact", "Contact form"),
            ("/profile", "Profile update"),
            ("/settings", "Settings page"),
            ("/post", "Post creation"),
            ("/message", "Message form"),
            ("/forum", "Forum post"),
            ("/guestbook", "Guestbook"),
        ]

        for path, description in entry_points:
            url = f"{target_url}{path}"
            resp = xss_scanner.get(url)

            if resp and resp.status_code in [200, 302]:
                forms = extract_forms(resp.text, url)
                if forms:
                    finding = Finding(
                        title=f"Potential Stored XSS Entry Point: {description}",
                        severity=Severity.INFO,
                        description=f"Form found that may store user input: {description}",
                        url=url,
                        evidence=f"Form fields: {[i['name'] for f in forms for i in f['inputs']]}",
                        remediation="Ensure all stored user input is properly sanitized and encoded on output.",
                        cwe_id="CWE-79",
                        owasp_category="A03:2021 - Injection",
                    )
                    findings_collector.add(finding)


class TestTemplateInjection:
    """Tests for client-side template injection."""

    @pytest.mark.xss
    def test_template_injection(self, xss_scanner, target_url, findings_collector, test_config):
        """Test for client-side template injection vulnerabilities."""
        if test_config.intensity == "light":
            pytest.skip("Template injection tests skipped in light intensity mode")

        # First detect if any template frameworks are used
        resp = xss_scanner.get(target_url)
        if not resp:
            return

        frameworks_detected = []
        framework_signatures = {
            "Angular": [r'ng-app', r'ng-model', r'\[\[.*\]\]', r'\{\{.*\}\}'],
            "Vue": [r'v-model', r'v-bind', r'v-on', r'\{\{.*\}\}'],
            "React": [r'data-reactroot', r'__REACT'],
            "Handlebars": [r'\{\{#.*\}\}', r'\{\{/.*\}\}'],
        }

        for framework, patterns in framework_signatures.items():
            for pattern in patterns:
                if re.search(pattern, resp.text):
                    frameworks_detected.append(framework)
                    break

        if not frameworks_detected:
            return

        # Test template injection payloads
        test_endpoints = [
            f"{target_url}/search?q={{payload}}",
            f"{target_url}/?name={{payload}}",
        ]

        for payload in TEMPLATE_INJECTION:
            for endpoint_template in test_endpoints:
                url = endpoint_template.replace("{payload}", quote(payload))
                resp = xss_scanner.get(url)

                if resp and self._check_template_execution(payload, resp.text):
                    finding = Finding(
                        title="Client-Side Template Injection",
                        severity=Severity.HIGH,
                        description=f"Template injection detected in {frameworks_detected}",
                        url=url[:200],
                        evidence=f"Payload: {payload[:100]}, Frameworks: {frameworks_detected}",
                        remediation="Sanitize user input in template expressions. Use safe interpolation methods.",
                        cwe_id="CWE-94",
                        owasp_category="A03:2021 - Injection",
                    )
                    findings_collector.add(finding)

    def _check_template_execution(self, payload: str, response_text: str) -> bool:
        """Check if template injection was executed."""
        # Look for signs of execution vs. reflection
        execution_indicators = [
            "alert(1)",  # If this appears as text, template was executed
            "[object Object]",
            "undefined",
            "function",
        ]

        # If payload is reflected as-is, it wasn't executed
        if payload in response_text:
            return False

        # Check for execution indicators
        return any(indicator in response_text for indicator in execution_indicators)
