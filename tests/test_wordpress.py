"""
WordPress Security Tests

Comprehensive security tests for WordPress installations including:
- Version detection and known vulnerabilities
- User enumeration
- XML-RPC vulnerabilities
- Plugin and theme vulnerabilities
- Configuration issues
"""

import re

import pytest

from utils.scanner import SecurityScanner, Finding, Severity
from payloads.wordpress import (
    WP_SENSITIVE_PATHS,
    VULNERABLE_PLUGINS,
    XMLRPC_PAYLOADS,
    COMMON_WP_USERNAMES,
    WP_REST_ENDPOINTS,
    WP_VERSION_PATTERNS,
    WP_SIGNATURES,
    generate_plugin_paths,
)


@pytest.fixture
def wp_scanner(test_config):
    """Create scanner for WordPress tests."""
    return SecurityScanner(test_config)


class TestWordPressDetection:
    """Tests for WordPress detection and version."""

    @pytest.mark.wordpress
    def test_wordpress_detection(self, wp_scanner, wordpress_url, findings_collector):
        """Detect if WordPress is installed."""
        resp = wp_scanner.get(wordpress_url)
        if not resp:
            pytest.skip("Could not connect to WordPress URL")

        is_wordpress = False
        for signature in WP_SIGNATURES:
            if signature in resp.text:
                is_wordpress = True
                break

        if not is_wordpress:
            pytest.skip("WordPress not detected at this URL")

        return True

    @pytest.mark.wordpress
    def test_wordpress_version(self, wp_scanner, wordpress_url, findings_collector):
        """Detect WordPress version and check for known vulnerabilities."""
        resp = wp_scanner.get(wordpress_url)
        if not resp:
            return

        version = None

        # Try to find version from various sources
        for pattern in WP_VERSION_PATTERNS:
            match = re.search(pattern, resp.text)
            if match:
                version = match.group(1)
                break

        # Also check readme.html
        readme_resp = wp_scanner.get(f"{wordpress_url}/readme.html")
        if readme_resp and readme_resp.status_code == 200:
            version_match = re.search(r'Version\s+(\d+\.\d+(?:\.\d+)?)', readme_resp.text)
            if version_match:
                version = version_match.group(1)

        if version:
            finding = Finding(
                title="WordPress Version Detected",
                severity=Severity.INFO,
                description=f"WordPress version {version} detected",
                url=wordpress_url,
                evidence=f"Version: {version}",
                remediation="Keep WordPress updated to the latest version",
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)

            # Check if version is known to be vulnerable
            major_version = ".".join(version.split(".")[:2])
            if float(major_version) < 6.0:
                finding = Finding(
                    title="Outdated WordPress Version",
                    severity=Severity.HIGH,
                    description=f"WordPress {version} is outdated and may have security vulnerabilities",
                    url=wordpress_url,
                    evidence=f"Version: {version}",
                    remediation="Update WordPress to the latest stable version",
                    cwe_id="CWE-1104",
                    owasp_category="A06:2021 - Vulnerable and Outdated Components",
                )
                findings_collector.add(finding)


class TestWordPressUserEnumeration:
    """Tests for WordPress user enumeration."""

    @pytest.mark.wordpress
    def test_user_enumeration_rest_api(self, wp_scanner, wordpress_url, findings_collector):
        """Test for user enumeration via REST API."""
        users_url = f"{wordpress_url}/wp-json/wp/v2/users"
        resp = wp_scanner.get(users_url)

        if resp and resp.status_code == 200:
            try:
                users = resp.json()
                if isinstance(users, list) and len(users) > 0:
                    usernames = [u.get("slug", u.get("name", "unknown")) for u in users]
                    finding = Finding(
                        title="WordPress User Enumeration via REST API",
                        severity=Severity.MEDIUM,
                        description=f"REST API exposes {len(users)} user(s)",
                        url=users_url,
                        evidence=f"Usernames found: {usernames[:5]}",
                        remediation="Disable REST API user endpoint or restrict access",
                        cwe_id="CWE-200",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)
            except Exception:
                pass

    @pytest.mark.wordpress
    def test_user_enumeration_author_parameter(self, wp_scanner, wordpress_url, findings_collector):
        """Test for user enumeration via author parameter."""
        found_users = []

        for author_id in range(1, 6):
            url = f"{wordpress_url}/?author={author_id}"
            resp = wp_scanner.get(url, allow_redirects=True)

            if resp:
                # Check for redirect to author page
                if "/author/" in str(resp.url):
                    username = str(resp.url).split("/author/")[-1].rstrip("/")
                    found_users.append(username)

                # Check page content for author info
                author_match = re.search(r'/author/([^/"\']+)', resp.text)
                if author_match:
                    found_users.append(author_match.group(1))

        if found_users:
            unique_users = list(set(found_users))
            finding = Finding(
                title="WordPress User Enumeration via Author Parameter",
                severity=Severity.MEDIUM,
                description=f"Author parameter reveals {len(unique_users)} username(s)",
                url=f"{wordpress_url}/?author=1",
                evidence=f"Usernames: {unique_users}",
                remediation="Block author enumeration via .htaccess or security plugin",
                cwe_id="CWE-200",
                owasp_category="A01:2021 - Broken Access Control",
            )
            findings_collector.add(finding)

    @pytest.mark.wordpress
    def test_user_enumeration_login_error(self, wp_scanner, wordpress_url, findings_collector):
        """Test for user enumeration via login error messages."""
        login_url = f"{wordpress_url}/wp-login.php"

        # Test with known common username
        for username in COMMON_WP_USERNAMES[:3]:
            resp = wp_scanner.post(login_url, data={
                "log": username,
                "pwd": "wrongpassword123",
                "wp-submit": "Log In",
            })

            if resp:
                # WordPress gives different errors for valid vs invalid users
                if "incorrect password" in resp.text.lower():
                    finding = Finding(
                        title=f"WordPress Username Confirmed: {username}",
                        severity=Severity.MEDIUM,
                        description="Login error message confirms username exists",
                        url=login_url,
                        evidence=f"Username '{username}' exists (password error shown)",
                        remediation="Use a security plugin to standardize error messages",
                        cwe_id="CWE-204",
                        owasp_category="A07:2021 - Identification and Authentication Failures",
                    )
                    findings_collector.add(finding)


class TestWordPressXMLRPC:
    """Tests for XML-RPC vulnerabilities."""

    @pytest.mark.wordpress
    def test_xmlrpc_enabled(self, wp_scanner, wordpress_url, findings_collector):
        """Test if XML-RPC is enabled."""
        xmlrpc_url = f"{wordpress_url}/xmlrpc.php"

        # POST to xmlrpc to check if enabled
        resp = wp_scanner.post(
            xmlrpc_url,
            data=XMLRPC_PAYLOADS["list_methods"],
            headers={"Content-Type": "application/xml"}
        )

        if resp and resp.status_code == 200:
            if "system.listMethods" in resp.text or "<methodResponse>" in resp.text:
                finding = Finding(
                    title="WordPress XML-RPC Enabled",
                    severity=Severity.MEDIUM,
                    description="XML-RPC is enabled and can be abused for brute force or DDoS",
                    url=xmlrpc_url,
                    evidence="XML-RPC responding to requests",
                    remediation="Disable XML-RPC if not needed, or restrict access",
                    cwe_id="CWE-287",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                )
                findings_collector.add(finding)

                # Test for specific dangerous methods
                if "pingback.ping" in resp.text:
                    finding = Finding(
                        title="WordPress Pingback Enabled",
                        severity=Severity.MEDIUM,
                        description="Pingback can be abused for DDoS amplification and port scanning",
                        url=xmlrpc_url,
                        evidence="pingback.ping method available",
                        remediation="Disable pingback functionality",
                        cwe_id="CWE-918",
                        owasp_category="A10:2021 - Server-Side Request Forgery",
                    )
                    findings_collector.add(finding)

    @pytest.mark.wordpress
    def test_xmlrpc_multicall(self, wp_scanner, wordpress_url, findings_collector):
        """Test for XML-RPC multicall brute force vulnerability."""
        xmlrpc_url = f"{wordpress_url}/xmlrpc.php"

        # Check if multicall is available (used for amplified brute force)
        resp = wp_scanner.post(
            xmlrpc_url,
            data=XMLRPC_PAYLOADS["list_methods"],
            headers={"Content-Type": "application/xml"}
        )

        if resp and "system.multicall" in resp.text:
            finding = Finding(
                title="WordPress XML-RPC Multicall Available",
                severity=Severity.HIGH,
                description="system.multicall allows amplified brute force attacks",
                url=xmlrpc_url,
                evidence="system.multicall method available",
                remediation="Disable XML-RPC or block system.multicall",
                cwe_id="CWE-307",
                owasp_category="A07:2021 - Identification and Authentication Failures",
            )
            findings_collector.add(finding)


class TestWordPressConfigExposure:
    """Tests for WordPress configuration exposure."""

    @pytest.mark.wordpress
    def test_sensitive_files_exposed(self, wp_scanner, wordpress_url, findings_collector):
        """Test for exposed sensitive WordPress files."""
        sensitive_files = [
            ("/wp-config.php", "WordPress configuration file"),
            ("/wp-config.php.bak", "WordPress config backup"),
            ("/wp-config.php~", "WordPress config backup"),
            ("/wp-config.txt", "WordPress config text"),
            ("/.wp-config.php.swp", "WordPress config swap file"),
            ("/wp-content/debug.log", "WordPress debug log"),
            ("/error_log", "Error log file"),
            ("/debug.log", "Debug log file"),
        ]

        for path, description in sensitive_files:
            url = f"{wordpress_url}{path}"
            resp = wp_scanner.get(url)

            if resp and resp.status_code == 200:
                # Check if it contains sensitive data
                sensitive_patterns = [
                    "DB_NAME", "DB_USER", "DB_PASSWORD",
                    "AUTH_KEY", "SECURE_AUTH_KEY",
                    "define(", "<?php",
                    "PHP Fatal error", "PHP Warning",
                ]

                is_sensitive = any(p in resp.text for p in sensitive_patterns)

                if is_sensitive:
                    finding = Finding(
                        title=f"Sensitive File Exposed: {path}",
                        severity=Severity.CRITICAL,
                        description=f"{description} is publicly accessible",
                        url=url,
                        evidence=f"File accessible and contains sensitive data",
                        remediation="Block access to sensitive files via .htaccess or server config",
                        cwe_id="CWE-538",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)

    @pytest.mark.wordpress
    def test_readme_exposed(self, wp_scanner, wordpress_url, findings_collector):
        """Test for exposed readme.html with version info."""
        readme_url = f"{wordpress_url}/readme.html"
        resp = wp_scanner.get(readme_url)

        if resp and resp.status_code == 200:
            if "wordpress" in resp.text.lower():
                finding = Finding(
                    title="WordPress readme.html Exposed",
                    severity=Severity.LOW,
                    description="readme.html reveals WordPress version information",
                    url=readme_url,
                    evidence="readme.html is publicly accessible",
                    remediation="Delete or block access to readme.html",
                    cwe_id="CWE-200",
                    owasp_category="A05:2021 - Security Misconfiguration",
                )
                findings_collector.add(finding)

    @pytest.mark.wordpress
    def test_directory_listing(self, wp_scanner, wordpress_url, findings_collector):
        """Test for directory listing in wp-content."""
        dirs_to_check = [
            "/wp-content/",
            "/wp-content/uploads/",
            "/wp-content/plugins/",
            "/wp-content/themes/",
            "/wp-includes/",
        ]

        for dir_path in dirs_to_check:
            url = f"{wordpress_url}{dir_path}"
            resp = wp_scanner.get(url)

            if resp and resp.status_code == 200:
                if "Index of" in resp.text or "<title>Index" in resp.text:
                    finding = Finding(
                        title=f"Directory Listing Enabled: {dir_path}",
                        severity=Severity.MEDIUM,
                        description="Directory listing reveals file structure",
                        url=url,
                        evidence="Directory listing page accessible",
                        remediation="Disable directory listing in server configuration",
                        cwe_id="CWE-548",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)


class TestWordPressPlugins:
    """Tests for WordPress plugin vulnerabilities."""

    @pytest.mark.wordpress
    def test_plugin_enumeration(self, wp_scanner, wordpress_url, findings_collector):
        """Enumerate installed WordPress plugins."""
        found_plugins = []

        for plugin in VULNERABLE_PLUGINS:
            paths = generate_plugin_paths(plugin)

            for path in paths:
                url = f"{wordpress_url}{path}"
                resp = wp_scanner.get(url)

                if resp and resp.status_code == 200:
                    found_plugins.append(plugin)
                    break

        if found_plugins:
            finding = Finding(
                title="WordPress Plugins Detected",
                severity=Severity.INFO,
                description=f"Found {len(found_plugins)} plugin(s) installed",
                url=wordpress_url,
                evidence=f"Plugins: {found_plugins}",
                remediation="Keep all plugins updated and remove unused plugins",
                cwe_id="CWE-1104",
                owasp_category="A06:2021 - Vulnerable and Outdated Components",
            )
            findings_collector.add(finding)

        return found_plugins

    @pytest.mark.wordpress
    def test_plugin_readme_files(self, wp_scanner, wordpress_url, findings_collector):
        """Check for plugin readme files that reveal version info."""
        for plugin in VULNERABLE_PLUGINS[:10]:  # Check top 10
            readme_url = f"{wordpress_url}/wp-content/plugins/{plugin}/readme.txt"
            resp = wp_scanner.get(readme_url)

            if resp and resp.status_code == 200:
                # Try to extract version
                version_match = re.search(r'Stable tag:\s*(\d+\.\d+(?:\.\d+)?)', resp.text, re.IGNORECASE)
                if version_match:
                    version = version_match.group(1)
                    finding = Finding(
                        title=f"Plugin Version Exposed: {plugin}",
                        severity=Severity.LOW,
                        description=f"Plugin {plugin} version {version} detected via readme.txt",
                        url=readme_url,
                        evidence=f"Version: {version}",
                        remediation="Block access to plugin readme files",
                        cwe_id="CWE-200",
                        owasp_category="A05:2021 - Security Misconfiguration",
                    )
                    findings_collector.add(finding)


class TestWordPressLogin:
    """Tests for WordPress login security."""

    @pytest.mark.wordpress
    def test_login_page_accessible(self, wp_scanner, wordpress_url, findings_collector):
        """Check if login page is publicly accessible."""
        login_url = f"{wordpress_url}/wp-login.php"
        resp = wp_scanner.get(login_url)

        if resp and resp.status_code == 200:
            if "wp-login" in resp.text or "user_login" in resp.text:
                finding = Finding(
                    title="WordPress Login Page Accessible",
                    severity=Severity.INFO,
                    description="Default WordPress login page is publicly accessible",
                    url=login_url,
                    evidence="wp-login.php accessible",
                    remediation="Consider hiding or restricting access to login page",
                    cwe_id="CWE-284",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                )
                findings_collector.add(finding)

    @pytest.mark.wordpress
    def test_wp_admin_accessible(self, wp_scanner, wordpress_url, findings_collector):
        """Check wp-admin accessibility."""
        admin_url = f"{wordpress_url}/wp-admin/"
        resp = wp_scanner.get(admin_url, allow_redirects=False)

        if resp:
            if resp.status_code == 200:
                finding = Finding(
                    title="WordPress Admin Accessible Without Auth",
                    severity=Severity.HIGH,
                    description="wp-admin is accessible without authentication",
                    url=admin_url,
                    evidence=f"Status: {resp.status_code}",
                    remediation="Ensure proper authentication is required",
                    cwe_id="CWE-284",
                    owasp_category="A01:2021 - Broken Access Control",
                )
                findings_collector.add(finding)
