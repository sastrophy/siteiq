"""
Security Headers Tests

Tests for HTTP security headers including:
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Strict-Transport-Security (HSTS)
- Referrer-Policy
- Permissions-Policy
- Cache-Control
"""

import re

import pytest

from utils.scanner import SecurityScanner, Finding, Severity


@pytest.fixture
def headers_scanner(test_config):
    """Create scanner for header tests."""
    return SecurityScanner(test_config)


class TestSecurityHeaders:
    """Tests for security headers."""

    @pytest.mark.headers
    def test_content_security_policy(self, headers_scanner, target_url, findings_collector):
        """Test for Content-Security-Policy header."""
        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        csp = resp.headers.get("Content-Security-Policy", "")
        csp_report = resp.headers.get("Content-Security-Policy-Report-Only", "")

        if not csp and not csp_report:
            finding = Finding(
                title="Missing Content-Security-Policy Header",
                severity=Severity.MEDIUM,
                description="No CSP header found. CSP helps prevent XSS and data injection attacks.",
                url=target_url,
                evidence="Header not present",
                remediation="Implement a Content-Security-Policy header. Start with a report-only policy.",
                cwe_id="CWE-1021",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)
            return

        # Check for weak CSP directives
        weak_directives = []

        if "unsafe-inline" in csp:
            weak_directives.append("unsafe-inline (allows inline scripts)")
        if "unsafe-eval" in csp:
            weak_directives.append("unsafe-eval (allows eval())")
        if "'*'" in csp or " * " in csp or csp.endswith(" *"):
            weak_directives.append("wildcard source (allows any origin)")
        if "data:" in csp:
            weak_directives.append("data: URI (can be abused for XSS)")
        if "blob:" in csp:
            weak_directives.append("blob: URI (can be abused)")

        # Check for missing directives
        missing_directives = []
        important_directives = [
            "default-src",
            "script-src",
            "style-src",
            "img-src",
            "frame-ancestors",
        ]

        for directive in important_directives:
            if directive not in csp:
                missing_directives.append(directive)

        if weak_directives:
            finding = Finding(
                title="Weak Content-Security-Policy",
                severity=Severity.MEDIUM,
                description=f"CSP contains weak directives: {', '.join(weak_directives)}",
                url=target_url,
                evidence=f"CSP: {csp[:200]}",
                remediation="Remove unsafe-inline and unsafe-eval. Use nonces or hashes for inline scripts.",
                cwe_id="CWE-1021",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)

        if missing_directives:
            finding = Finding(
                title="Incomplete Content-Security-Policy",
                severity=Severity.LOW,
                description=f"CSP missing important directives: {', '.join(missing_directives)}",
                url=target_url,
                evidence=f"CSP: {csp[:200]}",
                remediation=f"Add missing directives: {', '.join(missing_directives)}",
                cwe_id="CWE-1021",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)

    @pytest.mark.headers
    def test_x_frame_options(self, headers_scanner, target_url, findings_collector):
        """Test for X-Frame-Options header (clickjacking protection)."""
        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        xfo = resp.headers.get("X-Frame-Options", "").upper()
        csp = resp.headers.get("Content-Security-Policy", "")

        # Check if frame-ancestors is set in CSP (supersedes X-Frame-Options)
        has_frame_ancestors = "frame-ancestors" in csp

        if not xfo and not has_frame_ancestors:
            finding = Finding(
                title="Missing Clickjacking Protection",
                severity=Severity.MEDIUM,
                description="No X-Frame-Options or CSP frame-ancestors directive found",
                url=target_url,
                evidence="Neither X-Frame-Options nor frame-ancestors present",
                remediation="Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors 'none''",
                cwe_id="CWE-1021",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)
        elif xfo and xfo not in ["DENY", "SAMEORIGIN"]:
            finding = Finding(
                title="Invalid X-Frame-Options Value",
                severity=Severity.LOW,
                description=f"X-Frame-Options has invalid value: {xfo}",
                url=target_url,
                evidence=f"X-Frame-Options: {xfo}",
                remediation="Use 'DENY' or 'SAMEORIGIN' for X-Frame-Options",
                cwe_id="CWE-1021",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)

    @pytest.mark.headers
    def test_x_content_type_options(self, headers_scanner, target_url, findings_collector):
        """Test for X-Content-Type-Options header (MIME sniffing protection)."""
        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        xcto = resp.headers.get("X-Content-Type-Options", "").lower()

        if not xcto:
            finding = Finding(
                title="Missing X-Content-Type-Options Header",
                severity=Severity.LOW,
                description="No X-Content-Type-Options header. Browser may perform MIME sniffing.",
                url=target_url,
                evidence="Header not present",
                remediation="Add 'X-Content-Type-Options: nosniff'",
                cwe_id="CWE-16",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)
        elif xcto != "nosniff":
            finding = Finding(
                title="Invalid X-Content-Type-Options Value",
                severity=Severity.LOW,
                description=f"X-Content-Type-Options should be 'nosniff', got: {xcto}",
                url=target_url,
                evidence=f"X-Content-Type-Options: {xcto}",
                remediation="Set 'X-Content-Type-Options: nosniff'",
                cwe_id="CWE-16",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)

    @pytest.mark.headers
    def test_strict_transport_security(self, headers_scanner, target_url, findings_collector):
        """Test for Strict-Transport-Security header (HSTS)."""
        if not target_url.startswith("https://"):
            pytest.skip("HSTS only applies to HTTPS")

        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        hsts = resp.headers.get("Strict-Transport-Security", "")

        if not hsts:
            finding = Finding(
                title="Missing Strict-Transport-Security Header",
                severity=Severity.MEDIUM,
                description="No HSTS header. Site may be vulnerable to SSL stripping attacks.",
                url=target_url,
                evidence="Header not present",
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
                cwe_id="CWE-523",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)
            return

        # Check max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                finding = Finding(
                    title="Weak HSTS max-age",
                    severity=Severity.LOW,
                    description=f"HSTS max-age is {max_age} seconds. Recommended: at least 31536000 (1 year)",
                    url=target_url,
                    evidence=f"Strict-Transport-Security: {hsts}",
                    remediation="Set max-age to at least 31536000 (1 year)",
                    cwe_id="CWE-523",
                    owasp_category="A05:2021 - Security Misconfiguration",
                )
                findings_collector.add(finding)

        # Check for includeSubDomains
        if "includesubdomains" not in hsts.lower():
            finding = Finding(
                title="HSTS Missing includeSubDomains",
                severity=Severity.LOW,
                description="HSTS does not include subdomains",
                url=target_url,
                evidence=f"Strict-Transport-Security: {hsts}",
                remediation="Add 'includeSubDomains' to HSTS header",
                cwe_id="CWE-523",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)

    @pytest.mark.headers
    def test_referrer_policy(self, headers_scanner, target_url, findings_collector):
        """Test for Referrer-Policy header."""
        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        referrer_policy = resp.headers.get("Referrer-Policy", "")

        safe_policies = [
            "no-referrer",
            "no-referrer-when-downgrade",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        ]

        if not referrer_policy:
            finding = Finding(
                title="Missing Referrer-Policy Header",
                severity=Severity.LOW,
                description="No Referrer-Policy header. Referrer information may leak to third parties.",
                url=target_url,
                evidence="Header not present",
                remediation="Add 'Referrer-Policy: strict-origin-when-cross-origin'",
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)
        elif referrer_policy.lower() == "unsafe-url":
            finding = Finding(
                title="Unsafe Referrer-Policy",
                severity=Severity.MEDIUM,
                description="Referrer-Policy set to 'unsafe-url' leaks full URL to all destinations",
                url=target_url,
                evidence=f"Referrer-Policy: {referrer_policy}",
                remediation="Change to 'strict-origin-when-cross-origin' or more restrictive policy",
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)

    @pytest.mark.headers
    def test_permissions_policy(self, headers_scanner, target_url, findings_collector):
        """Test for Permissions-Policy (formerly Feature-Policy) header."""
        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        permissions = resp.headers.get("Permissions-Policy", "")
        feature = resp.headers.get("Feature-Policy", "")  # Legacy header

        if not permissions and not feature:
            finding = Finding(
                title="Missing Permissions-Policy Header",
                severity=Severity.LOW,
                description="No Permissions-Policy header. Browser features not restricted.",
                url=target_url,
                evidence="Header not present",
                remediation="Add Permissions-Policy to restrict unnecessary browser features",
                cwe_id="CWE-16",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)

    @pytest.mark.headers
    def test_cache_control(self, headers_scanner, target_url, findings_collector):
        """Test for Cache-Control header on sensitive pages."""
        # Test login and other sensitive pages
        sensitive_pages = [
            "/login",
            "/signin",
            "/account",
            "/profile",
            "/settings",
            "/admin",
            "/dashboard",
        ]

        for page in sensitive_pages:
            url = f"{target_url}{page}"
            resp = headers_scanner.get(url)

            if not resp or resp.status_code == 404:
                continue

            cache_control = resp.headers.get("Cache-Control", "").lower()
            pragma = resp.headers.get("Pragma", "").lower()

            secure_cache = (
                "no-store" in cache_control or
                "no-cache" in cache_control or
                "private" in cache_control
            )

            if not secure_cache:
                finding = Finding(
                    title=f"Sensitive Page May Be Cached: {page}",
                    severity=Severity.LOW,
                    description="Sensitive page does not have proper cache control headers",
                    url=url,
                    evidence=f"Cache-Control: {cache_control or 'not set'}",
                    remediation="Add 'Cache-Control: no-store, no-cache, must-revalidate, private'",
                    cwe_id="CWE-525",
                    owasp_category="A05:2021 - Security Misconfiguration",
                )
                findings_collector.add(finding)


class TestServerInformationDisclosure:
    """Tests for server information disclosure."""

    @pytest.mark.headers
    def test_server_header(self, headers_scanner, target_url, findings_collector):
        """Test for Server header information disclosure."""
        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        server = resp.headers.get("Server", "")

        if server:
            # Check for version information
            version_patterns = [
                r'\d+\.\d+',  # Version numbers
                r'Apache/\d',
                r'nginx/\d',
                r'IIS/\d',
                r'PHP/\d',
            ]

            has_version = any(re.search(p, server) for p in version_patterns)

            if has_version:
                finding = Finding(
                    title="Server Version Disclosure",
                    severity=Severity.LOW,
                    description="Server header reveals version information",
                    url=target_url,
                    evidence=f"Server: {server}",
                    remediation="Configure server to hide version information",
                    cwe_id="CWE-200",
                    owasp_category="A05:2021 - Security Misconfiguration",
                )
                findings_collector.add(finding)

    @pytest.mark.headers
    def test_x_powered_by(self, headers_scanner, target_url, findings_collector):
        """Test for X-Powered-By header information disclosure."""
        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        powered_by = resp.headers.get("X-Powered-By", "")

        if powered_by:
            finding = Finding(
                title="X-Powered-By Header Disclosure",
                severity=Severity.LOW,
                description=f"X-Powered-By header reveals technology stack: {powered_by}",
                url=target_url,
                evidence=f"X-Powered-By: {powered_by}",
                remediation="Remove X-Powered-By header from responses",
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)

    @pytest.mark.headers
    def test_x_aspnet_version(self, headers_scanner, target_url, findings_collector):
        """Test for X-AspNet-Version header."""
        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        aspnet_version = resp.headers.get("X-AspNet-Version", "")
        aspnetmvc_version = resp.headers.get("X-AspNetMvc-Version", "")

        if aspnet_version or aspnetmvc_version:
            finding = Finding(
                title="ASP.NET Version Disclosure",
                severity=Severity.LOW,
                description="ASP.NET version header reveals technology information",
                url=target_url,
                evidence=f"X-AspNet-Version: {aspnet_version}, X-AspNetMvc-Version: {aspnetmvc_version}",
                remediation="Disable version headers in web.config",
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)


class TestCORSHeaders:
    """Tests for CORS misconfiguration."""

    @pytest.mark.headers
    def test_cors_wildcard(self, headers_scanner, target_url, findings_collector):
        """Test for overly permissive CORS configuration."""
        # Send request with Origin header
        resp = headers_scanner.get(
            target_url,
            headers={"Origin": "https://evil.com"}
        )
        if not resp:
            pytest.skip("Could not connect to target")

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            if acac.lower() == "true":
                finding = Finding(
                    title="Critical CORS Misconfiguration",
                    severity=Severity.HIGH,
                    description="CORS allows any origin with credentials - extremely dangerous",
                    url=target_url,
                    evidence=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                    remediation="Never use '*' with credentials. Whitelist specific trusted origins.",
                    cwe_id="CWE-942",
                    owasp_category="A05:2021 - Security Misconfiguration",
                )
                findings_collector.add(finding)
            else:
                finding = Finding(
                    title="Permissive CORS Configuration",
                    severity=Severity.LOW,
                    description="CORS allows any origin (wildcard)",
                    url=target_url,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="Restrict Access-Control-Allow-Origin to trusted domains",
                    cwe_id="CWE-942",
                    owasp_category="A05:2021 - Security Misconfiguration",
                )
                findings_collector.add(finding)

    @pytest.mark.headers
    def test_cors_origin_reflection(self, headers_scanner, target_url, findings_collector):
        """Test for CORS origin reflection vulnerability."""
        evil_origin = "https://evil.com"

        resp = headers_scanner.get(
            target_url,
            headers={"Origin": evil_origin}
        )
        if not resp:
            pytest.skip("Could not connect to target")

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == evil_origin:
            severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
            finding = Finding(
                title="CORS Origin Reflection",
                severity=severity,
                description="Server reflects arbitrary Origin header in CORS response",
                url=target_url,
                evidence=f"Reflected Origin: {acao}, Credentials: {acac}",
                remediation="Validate Origin against a whitelist of trusted domains",
                cwe_id="CWE-942",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)


# =============================================================================
# 2026 SECURITY HEADERS - Modern Standards
# =============================================================================

class TestModernSecurityHeaders:
    """Tests for modern security headers (2024-2026 standards)."""

    @pytest.mark.headers
    def test_cross_origin_opener_policy(self, headers_scanner, target_url, findings_collector):
        """Test for Cross-Origin-Opener-Policy (COOP) header."""
        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        coop = resp.headers.get("Cross-Origin-Opener-Policy", "")

        if not coop:
            finding = Finding(
                title="Missing Cross-Origin-Opener-Policy Header",
                severity=Severity.LOW,
                description="No COOP header. COOP prevents cross-origin attacks like Spectre.",
                url=target_url,
                evidence="Header not present",
                remediation="Add 'Cross-Origin-Opener-Policy: same-origin' for sensitive pages",
                cwe_id="CWE-1021",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)
        else:
            valid_values = ["same-origin", "same-origin-allow-popups", "unsafe-none"]
            if coop not in valid_values:
                finding = Finding(
                    title="Invalid Cross-Origin-Opener-Policy Value",
                    severity=Severity.LOW,
                    description=f"COOP has invalid value: {coop}",
                    url=target_url,
                    evidence=f"Cross-Origin-Opener-Policy: {coop}",
                    remediation=f"Use valid COOP value: {valid_values}",
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021 - Security Misconfiguration",
                )
                findings_collector.add(finding)

    @pytest.mark.headers
    def test_cross_origin_embedder_policy(self, headers_scanner, target_url, findings_collector):
        """Test for Cross-Origin-Embedder-Policy (COEP) header."""
        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        coep = resp.headers.get("Cross-Origin-Embedder-Policy", "")

        if not coep:
            finding = Finding(
                title="Missing Cross-Origin-Embedder-Policy Header",
                severity=Severity.LOW,
                description="No COEP header. COEP is required for cross-origin isolation (SharedArrayBuffer).",
                url=target_url,
                evidence="Header not present",
                remediation="Add 'Cross-Origin-Embedder-Policy: require-corp' if cross-origin isolation is needed",
                cwe_id="CWE-1021",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)

    @pytest.mark.headers
    def test_trusted_types_csp(self, headers_scanner, target_url, findings_collector):
        """Test for Trusted Types in CSP (DOM XSS prevention)."""
        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        csp = resp.headers.get("Content-Security-Policy", "")

        if csp and "require-trusted-types-for" not in csp and "trusted-types" not in csp:
            finding = Finding(
                title="CSP Missing Trusted Types",
                severity=Severity.INFO,
                description="CSP does not enforce Trusted Types. Trusted Types prevent DOM XSS attacks.",
                url=target_url,
                evidence=f"CSP: {csp[:200]}",
                remediation="Add 'require-trusted-types-for 'script'' to CSP for DOM XSS protection",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
            )
            findings_collector.add(finding)

    @pytest.mark.headers
    def test_sec_fetch_headers(self, headers_scanner, target_url, findings_collector):
        """Check server handling of Sec-Fetch-* headers (Fetch Metadata)."""
        # Send request with Sec-Fetch headers simulating cross-origin attack
        resp = headers_scanner.get(
            target_url,
            headers={
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
            }
        )
        if not resp:
            pytest.skip("Could not connect to target")

        # If server accepts cross-site navigations without validation, note it
        if resp.status_code == 200:
            # This is informational - server should ideally validate these
            finding = Finding(
                title="Fetch Metadata Headers Not Enforced",
                severity=Severity.INFO,
                description="Server accepts cross-site requests. Consider validating Sec-Fetch-* headers.",
                url=target_url,
                evidence="Server returned 200 for cross-site Sec-Fetch-Site request",
                remediation="Implement Fetch Metadata request validation to prevent CSRF-like attacks",
                cwe_id="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
            )
            findings_collector.add(finding)

    @pytest.mark.headers
    def test_reporting_endpoints(self, headers_scanner, target_url, findings_collector):
        """Test for Reporting-Endpoints header (modern reporting API)."""
        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        reporting_endpoints = resp.headers.get("Reporting-Endpoints", "")
        report_to = resp.headers.get("Report-To", "")  # Legacy

        if not reporting_endpoints and not report_to:
            finding = Finding(
                title="Missing Security Reporting Configuration",
                severity=Severity.INFO,
                description="No Reporting-Endpoints header. Security violations won't be reported.",
                url=target_url,
                evidence="Neither Reporting-Endpoints nor Report-To headers present",
                remediation="Add 'Reporting-Endpoints: default=\"https://your-endpoint.com/reports\"' to collect CSP/NEL violations",
                cwe_id="CWE-778",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
            )
            findings_collector.add(finding)

    @pytest.mark.headers
    def test_nel_header(self, headers_scanner, target_url, findings_collector):
        """Test for Network Error Logging (NEL) header."""
        resp = headers_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        nel = resp.headers.get("NEL", "")

        if nel:
            # NEL is configured - good for monitoring
            print(f"INFO: NEL configured: {nel[:100]}")
        # NEL is optional, so not having it is not a finding

    @pytest.mark.headers
    def test_private_network_access(self, headers_scanner, target_url, findings_collector):
        """Test Private Network Access (CORS-RFC1918) handling."""
        # Simulate a preflight for private network access
        resp = headers_scanner.options(
            target_url,
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Private-Network": "true",
                "Access-Control-Request-Method": "GET",
            }
        )
        if not resp:
            pytest.skip("Could not connect to target")

        # Check if server allows private network access from external origins
        allow_private = resp.headers.get("Access-Control-Allow-Private-Network", "")

        if allow_private.lower() == "true":
            finding = Finding(
                title="Private Network Access Allowed from External Origins",
                severity=Severity.MEDIUM,
                description="Server allows private network access from external websites (CORS-RFC1918)",
                url=target_url,
                evidence=f"Access-Control-Allow-Private-Network: {allow_private}",
                remediation="Restrict private network access to trusted origins only",
                cwe_id="CWE-284",
                owasp_category="A01:2021 - Broken Access Control",
            )
            findings_collector.add(finding)
