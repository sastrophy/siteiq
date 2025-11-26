"""
CSRF and Other OWASP Top 10 Tests

Tests for various OWASP Top 10 vulnerabilities including:
- Cross-Site Request Forgery (CSRF)
- Insecure Direct Object References (IDOR)
- Security Misconfiguration
- Sensitive Data Exposure
- Server-Side Request Forgery (SSRF)
- Open Redirects
- Command Injection
"""

import re
from urllib.parse import quote, urlparse

import pytest

from utils.scanner import SecurityScanner, Finding, Severity, extract_forms


@pytest.fixture
def owasp_scanner(test_config):
    """Create scanner for OWASP tests."""
    return SecurityScanner(test_config)


class TestCSRF:
    """Tests for Cross-Site Request Forgery vulnerabilities."""

    @pytest.mark.csrf
    def test_csrf_token_presence(self, owasp_scanner, target_url, findings_collector):
        """Test for CSRF protection on forms."""
        resp = owasp_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        forms = extract_forms(resp.text, target_url)

        for form in forms:
            if form["method"].upper() == "GET":
                continue  # GET forms don't typically need CSRF protection

            # Check for CSRF token in form
            has_csrf = False
            csrf_names = ["csrf", "token", "_token", "csrfmiddlewaretoken", "authenticity_token", "nonce"]

            for inp in form["inputs"]:
                input_name = inp["name"].lower()
                if any(csrf_name in input_name for csrf_name in csrf_names):
                    has_csrf = True
                    break

            # Also check for hidden inputs that might be tokens
            hidden_pattern = r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']'
            hidden_inputs = re.findall(hidden_pattern, resp.text, re.IGNORECASE)

            for hidden in hidden_inputs:
                if any(csrf_name in hidden.lower() for csrf_name in csrf_names):
                    has_csrf = True
                    break

            if not has_csrf:
                finding = Finding(
                    title="Form Missing CSRF Protection",
                    severity=Severity.MEDIUM,
                    description=f"POST form lacks CSRF token at {form['action']}",
                    url=form["action"],
                    evidence=f"Form inputs: {[i['name'] for i in form['inputs']]}",
                    remediation="Implement CSRF tokens for all state-changing forms",
                    cwe_id="CWE-352",
                    owasp_category="A01:2021 - Broken Access Control",
                )
                findings_collector.add(finding)

    @pytest.mark.csrf
    def test_csrf_token_validation(self, owasp_scanner, target_url, findings_collector):
        """Test if CSRF tokens are actually validated."""
        resp = owasp_scanner.get(target_url)
        if not resp:
            return

        forms = extract_forms(resp.text, target_url)

        for form in forms:
            if form["method"].upper() == "GET":
                continue

            # Find CSRF token field
            csrf_field = None
            csrf_names = ["csrf", "token", "_token", "csrfmiddlewaretoken"]

            for inp in form["inputs"]:
                if any(name in inp["name"].lower() for name in csrf_names):
                    csrf_field = inp["name"]
                    break

            if not csrf_field:
                continue

            # Try submitting with invalid token
            form_data = {inp["name"]: "test_value" for inp in form["inputs"]}
            form_data[csrf_field] = "invalid_token_12345"

            invalid_resp = owasp_scanner.post(form["action"], data=form_data)

            if invalid_resp and invalid_resp.status_code == 200:
                # Form accepted invalid token - this is bad
                if "error" not in invalid_resp.text.lower() and "invalid" not in invalid_resp.text.lower():
                    finding = Finding(
                        title="CSRF Token Not Validated",
                        severity=Severity.HIGH,
                        description="Form accepts invalid CSRF tokens",
                        url=form["action"],
                        evidence="Form submission with invalid token was accepted",
                        remediation="Ensure CSRF tokens are validated server-side",
                        cwe_id="CWE-352",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)

            break  # Only test first form with CSRF


class TestIDOR:
    """Tests for Insecure Direct Object Reference vulnerabilities."""

    @pytest.mark.auth
    def test_idor_sequential_ids(self, owasp_scanner, target_url, findings_collector):
        """Test for IDOR via sequential IDs."""
        idor_paths = [
            "/user/{id}",
            "/profile/{id}",
            "/account/{id}",
            "/order/{id}",
            "/invoice/{id}",
            "/document/{id}",
            "/file/{id}",
            "/api/users/{id}",
            "/api/orders/{id}",
        ]

        for path_template in idor_paths:
            # Test sequential access
            responses = []
            for id_val in [1, 2, 3, 100, 999]:
                path = path_template.replace("{id}", str(id_val))
                url = f"{target_url}{path}"
                resp = owasp_scanner.get(url)

                if resp:
                    responses.append((id_val, resp.status_code, len(resp.text)))

            # Check if we can access multiple IDs
            successful = [r for r in responses if r[1] == 200]
            if len(successful) > 1:
                finding = Finding(
                    title=f"Potential IDOR: {path_template}",
                    severity=Severity.MEDIUM,
                    description="Multiple object IDs accessible without apparent authorization",
                    url=f"{target_url}{path_template}",
                    evidence=f"Accessible IDs: {[r[0] for r in successful]}",
                    remediation="Implement proper authorization checks for object access",
                    cwe_id="CWE-639",
                    owasp_category="A01:2021 - Broken Access Control",
                )
                findings_collector.add(finding)


class TestSSRF:
    """Tests for Server-Side Request Forgery vulnerabilities."""

    @pytest.mark.traversal
    def test_ssrf_url_parameters(self, owasp_scanner, target_url, findings_collector):
        """Test for SSRF via URL parameters."""
        ssrf_params = ["url", "uri", "path", "dest", "redirect", "site", "html", "data", "src", "target", "fetch"]

        ssrf_payloads = [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://169.254.169.254/",  # AWS metadata
            "http://metadata.google.internal/",  # GCP metadata
        ]

        for param in ssrf_params:
            for payload in ssrf_payloads:
                url = f"{target_url}?{param}={quote(payload)}"
                resp = owasp_scanner.get(url, timeout=5)

                if resp:
                    # Check for signs of SSRF
                    ssrf_indicators = [
                        "localhost", "127.0.0.1", "internal",
                        "metadata", "instance-id", "ami-id",
                        "computeMetadata", "project-id",
                    ]

                    if any(ind in resp.text.lower() for ind in ssrf_indicators):
                        finding = Finding(
                            title="Server-Side Request Forgery (SSRF)",
                            severity=Severity.HIGH,
                            description=f"SSRF vulnerability via '{param}' parameter",
                            url=url[:200],
                            evidence=f"Payload: {payload}",
                            remediation="Validate and whitelist allowed URLs. Block internal addresses.",
                            cwe_id="CWE-918",
                            owasp_category="A10:2021 - Server-Side Request Forgery",
                        )
                        findings_collector.add(finding)
                        return

    @pytest.mark.traversal
    def test_ssrf_webhook_endpoints(self, owasp_scanner, target_url, findings_collector):
        """Test webhook endpoints for SSRF."""
        webhook_paths = [
            "/webhook",
            "/callback",
            "/api/webhook",
            "/api/callback",
            "/notify",
        ]

        for path in webhook_paths:
            url = f"{target_url}{path}"
            resp = owasp_scanner.get(url)

            if resp and resp.status_code in [200, 405]:  # Endpoint exists
                finding = Finding(
                    title=f"Webhook Endpoint Found: {path}",
                    severity=Severity.INFO,
                    description="Webhook endpoint may be vulnerable to SSRF if it fetches URLs",
                    url=url,
                    evidence="Endpoint exists and should be tested for SSRF",
                    remediation="Validate webhook URLs. Use allowlists for external services.",
                    cwe_id="CWE-918",
                    owasp_category="A10:2021 - Server-Side Request Forgery",
                )
                findings_collector.add(finding)


class TestOpenRedirect:
    """Tests for Open Redirect vulnerabilities."""

    @pytest.mark.xss
    def test_open_redirect_parameters(self, owasp_scanner, target_url, findings_collector):
        """Test for open redirect via URL parameters."""
        redirect_params = [
            "redirect", "url", "next", "return", "returnUrl",
            "goto", "destination", "redir", "redirect_uri",
            "continue", "return_to", "target",
        ]

        evil_urls = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com/%2f..",
            "/\\evil.com",
            "https://target.com@evil.com",
        ]

        for param in redirect_params:
            for evil_url in evil_urls:
                url = f"{target_url}?{param}={quote(evil_url)}"
                resp = owasp_scanner.get(url, allow_redirects=False)

                if resp and resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get("Location", "")

                    if "evil.com" in location:
                        finding = Finding(
                            title="Open Redirect Vulnerability",
                            severity=Severity.MEDIUM,
                            description=f"Open redirect via '{param}' parameter",
                            url=url[:200],
                            evidence=f"Redirects to: {location}",
                            remediation="Validate redirect URLs against whitelist. Use relative URLs.",
                            cwe_id="CWE-601",
                            owasp_category="A01:2021 - Broken Access Control",
                        )
                        findings_collector.add(finding)
                        return

    @pytest.mark.xss
    def test_javascript_redirect(self, owasp_scanner, target_url, findings_collector):
        """Test for JavaScript-based open redirects."""
        redirect_params = ["redirect", "url", "next", "goto"]

        js_redirect_patterns = [
            r'window\.location\s*=',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
            r'window\.location\.assign\s*\(',
        ]

        for param in redirect_params:
            url = f"{target_url}?{param}=https://evil.com"
            resp = owasp_scanner.get(url)

            if resp:
                for pattern in js_redirect_patterns:
                    if re.search(pattern, resp.text):
                        # Check if evil.com appears after the redirect pattern
                        if "evil.com" in resp.text:
                            finding = Finding(
                                title="JavaScript Open Redirect",
                                severity=Severity.MEDIUM,
                                description=f"JavaScript redirect with user-controlled URL",
                                url=url[:200],
                                evidence=f"JavaScript redirect pattern found with evil.com",
                                remediation="Validate redirect URLs server-side before rendering",
                                cwe_id="CWE-601",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            return


class TestCommandInjection:
    """Tests for Command Injection vulnerabilities."""

    @pytest.mark.sql_injection
    def test_command_injection(self, owasp_scanner, target_url, findings_collector, test_config):
        """Test for OS command injection."""
        if test_config.intensity == "light":
            pytest.skip("Command injection tests skipped in light intensity mode")

        cmd_params = ["cmd", "exec", "command", "ping", "host", "ip", "query", "arg"]

        cmd_payloads = [
            "; id",
            "| id",
            "|| id",
            "&& id",
            "`id`",
            "$(id)",
            "; whoami",
            "| whoami",
            "; cat /etc/passwd",
            "& dir",
            "| dir",
        ]

        cmd_success_patterns = [
            r"uid=\d+",
            r"gid=\d+",
            r"root:",
            r"daemon:",
            r"Directory of",
            r"Volume Serial Number",
        ]

        for param in cmd_params:
            for payload in cmd_payloads[:5]:  # Test first 5
                url = f"{target_url}?{param}={quote(payload)}"
                resp = owasp_scanner.get(url, timeout=10)

                if resp:
                    for pattern in cmd_success_patterns:
                        if re.search(pattern, resp.text):
                            finding = Finding(
                                title="OS Command Injection",
                                severity=Severity.CRITICAL,
                                description=f"Command injection via '{param}' parameter",
                                url=url[:200],
                                evidence=f"Payload: {payload}",
                                remediation="Never pass user input to shell commands. Use safe APIs.",
                                cwe_id="CWE-78",
                                owasp_category="A03:2021 - Injection",
                            )
                            findings_collector.add(finding)
                            return


class TestSecurityMisconfiguration:
    """Tests for security misconfigurations."""

    @pytest.mark.headers
    def test_debug_mode(self, owasp_scanner, target_url, findings_collector):
        """Test for debug mode indicators."""
        resp = owasp_scanner.get(target_url)
        if not resp:
            return

        debug_indicators = [
            "DEBUG = True",
            "FLASK_DEBUG",
            "development mode",
            "debug mode",
            "stack trace",
            "Traceback (most recent call last)",
            "Django Debug Toolbar",
            "Werkzeug Debugger",
            "Xdebug",
            "var_dump(",
            "print_r(",
        ]

        content = resp.text
        found_indicators = [ind for ind in debug_indicators if ind.lower() in content.lower()]

        if found_indicators:
            finding = Finding(
                title="Debug Mode Enabled",
                severity=Severity.HIGH,
                description="Application appears to be running in debug mode",
                url=target_url,
                evidence=f"Debug indicators found: {found_indicators}",
                remediation="Disable debug mode in production environments",
                cwe_id="CWE-215",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)

    @pytest.mark.headers
    def test_error_handling(self, owasp_scanner, target_url, findings_collector):
        """Test for verbose error messages."""
        error_urls = [
            f"{target_url}/nonexistent_page_12345",
            f"{target_url}/?id='",
            f"{target_url}/../../../etc/passwd",
            f"{target_url}/%00",
        ]

        error_patterns = [
            (r"Stack trace:", "Stack trace exposed"),
            (r"at [\w.]+\([\w.]+:\d+\)", "Code location in stack trace"),
            (r"File \"[^\"]+\", line \d+", "Python traceback"),
            (r"<b>Warning</b>:.*on line <b>\d+</b>", "PHP warning"),
            (r"<b>Fatal error</b>:", "PHP fatal error"),
            (r"Exception in thread", "Java exception"),
            (r"System\.[\w.]+Exception", ".NET exception"),
            (r"ORA-\d+:", "Oracle error"),
            (r"ODBC.*Driver.*Error", "ODBC error"),
        ]

        for url in error_urls:
            resp = owasp_scanner.get(url)
            if not resp:
                continue

            for pattern, description in error_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    finding = Finding(
                        title=f"Verbose Error Message: {description}",
                        severity=Severity.LOW,
                        description="Error messages reveal internal details",
                        url=url[:200],
                        evidence=description,
                        remediation="Implement custom error pages. Log errors server-side only.",
                        cwe_id="CWE-209",
                        owasp_category="A05:2021 - Security Misconfiguration",
                    )
                    findings_collector.add(finding)
                    break

    @pytest.mark.headers
    def test_default_pages(self, owasp_scanner, target_url, findings_collector):
        """Test for default installation pages."""
        default_pages = [
            ("/phpinfo.php", "PHP info page"),
            ("/info.php", "PHP info page"),
            ("/test.php", "PHP test page"),
            ("/iisstart.htm", "IIS default page"),
            ("/default.asp", "IIS default page"),
            ("/cgi-bin/", "CGI directory"),
            ("/examples/", "Example applications"),
            ("/docs/", "Documentation"),
            ("/manual/", "Server manual"),
            ("/server-status", "Apache status"),
            ("/server-info", "Apache info"),
        ]

        for path, description in default_pages:
            url = f"{target_url}{path}"
            resp = owasp_scanner.get(url)

            if resp and resp.status_code == 200:
                finding = Finding(
                    title=f"Default Page Exposed: {description}",
                    severity=Severity.LOW,
                    description=f"{description} is publicly accessible at {path}",
                    url=url,
                    evidence=f"Status: {resp.status_code}",
                    remediation="Remove or restrict access to default pages",
                    cwe_id="CWE-538",
                    owasp_category="A05:2021 - Security Misconfiguration",
                )
                findings_collector.add(finding)


class TestHTTPMethods:
    """Tests for HTTP method vulnerabilities."""

    @pytest.mark.headers
    def test_dangerous_methods(self, owasp_scanner, target_url, findings_collector):
        """Test for dangerous HTTP methods."""
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "OPTIONS"]

        for method in dangerous_methods:
            resp = owasp_scanner.request(method, target_url)

            if resp:
                if method == "OPTIONS" and resp.status_code == 200:
                    allow_header = resp.headers.get("Allow", "")
                    dangerous_allowed = [m for m in ["PUT", "DELETE", "TRACE"] if m in allow_header]

                    if dangerous_allowed:
                        finding = Finding(
                            title=f"Dangerous HTTP Methods Allowed: {dangerous_allowed}",
                            severity=Severity.MEDIUM,
                            description=f"Server allows dangerous HTTP methods",
                            url=target_url,
                            evidence=f"Allow: {allow_header}",
                            remediation="Disable unnecessary HTTP methods",
                            cwe_id="CWE-749",
                            owasp_category="A05:2021 - Security Misconfiguration",
                        )
                        findings_collector.add(finding)

                elif method == "TRACE" and resp.status_code == 200:
                    if "TRACE" in resp.text:
                        finding = Finding(
                            title="HTTP TRACE Method Enabled",
                            severity=Severity.LOW,
                            description="TRACE method enabled (potential XST attack vector)",
                            url=target_url,
                            evidence="TRACE request was successful",
                            remediation="Disable TRACE method on the server",
                            cwe_id="CWE-693",
                            owasp_category="A05:2021 - Security Misconfiguration",
                        )
                        findings_collector.add(finding)
