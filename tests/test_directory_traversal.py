"""
Directory Traversal and File Inclusion Tests

Tests for path traversal vulnerabilities including:
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- Directory traversal
- Sensitive file access
"""

import re
from urllib.parse import quote

import pytest

from utils.scanner import SecurityScanner, Finding, Severity
from payloads.directory_traversal import (
    COMMON_LFI_PAYLOADS,
    LINUX_SENSITIVE_FILES,
    WINDOWS_SENSITIVE_FILES,
    WEB_CONFIG_FILES,
    PHP_WRAPPERS,
    FILE_READ_SIGNATURES,
    generate_traversal_payloads,
)


@pytest.fixture
def traversal_scanner(test_config):
    """Create scanner for directory traversal tests."""
    return SecurityScanner(test_config)


class TestDirectoryTraversal:
    """Tests for directory traversal vulnerabilities."""

    @pytest.mark.traversal
    def test_basic_traversal(self, traversal_scanner, target_url, findings_collector):
        """Test for basic directory traversal."""
        # Common vulnerable parameters
        test_params = ["file", "path", "page", "document", "doc", "include", "template", "load"]

        for param in test_params:
            for payload in COMMON_LFI_PAYLOADS[:10]:
                url = f"{target_url}?{param}={quote(payload)}"
                resp = traversal_scanner.get(url)

                if resp and self._check_file_read_success(resp.text):
                    finding = Finding(
                        title="Directory Traversal Vulnerability",
                        severity=Severity.CRITICAL,
                        description=f"Directory traversal via '{param}' parameter allows reading system files",
                        url=url[:200],
                        evidence=f"Payload: {payload}",
                        remediation="Validate and sanitize file paths. Use whitelists for allowed files.",
                        cwe_id="CWE-22",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)
                    return  # Found vulnerability, no need to continue

    @pytest.mark.traversal
    def test_encoded_traversal(self, traversal_scanner, target_url, findings_collector, test_config):
        """Test for directory traversal with encoding bypass."""
        if test_config.intensity == "light":
            pytest.skip("Encoded traversal tests skipped in light intensity mode")

        test_params = ["file", "path", "page", "include"]

        encoded_payloads = [
            "%2e%2e%2fetc/passwd",
            "%2e%2e/%2e%2e/etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%afetc/passwd",
            "....//....//....//etc/passwd",
            "..%00/etc/passwd",
        ]

        for param in test_params:
            for payload in encoded_payloads:
                url = f"{target_url}?{param}={payload}"
                resp = traversal_scanner.get(url)

                if resp and self._check_file_read_success(resp.text):
                    finding = Finding(
                        title="Directory Traversal (Encoding Bypass)",
                        severity=Severity.CRITICAL,
                        description=f"Encoded directory traversal bypasses filters",
                        url=url[:200],
                        evidence=f"Payload: {payload}",
                        remediation="Decode and normalize paths before validation. Use strict whitelists.",
                        cwe_id="CWE-22",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)
                    return

    @pytest.mark.traversal
    def test_null_byte_traversal(self, traversal_scanner, target_url, findings_collector):
        """Test for null byte injection in file paths."""
        test_params = ["file", "path", "page"]

        null_byte_payloads = [
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd%00.png",
            "../../../etc/passwd%00.txt",
            "....//....//etc/passwd%00",
        ]

        for param in test_params:
            for payload in null_byte_payloads:
                url = f"{target_url}?{param}={payload}"
                resp = traversal_scanner.get(url)

                if resp and self._check_file_read_success(resp.text):
                    finding = Finding(
                        title="Null Byte Injection in File Path",
                        severity=Severity.CRITICAL,
                        description="Null byte injection bypasses file extension checks",
                        url=url[:200],
                        evidence=f"Payload: {payload}",
                        remediation="Reject null bytes in input. Use path canonicalization.",
                        cwe_id="CWE-158",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)
                    return

    def _check_file_read_success(self, response_text: str) -> bool:
        """Check if file read was successful based on response content."""
        if not response_text:
            return False

        for file_type, signatures in FILE_READ_SIGNATURES.items():
            if any(sig in response_text for sig in signatures):
                return True

        return False


class TestLocalFileInclusion:
    """Tests for Local File Inclusion vulnerabilities."""

    @pytest.mark.traversal
    def test_php_wrapper_lfi(self, traversal_scanner, target_url, findings_collector, test_config):
        """Test for LFI using PHP wrappers."""
        if test_config.intensity == "light":
            pytest.skip("PHP wrapper tests skipped in light intensity mode")

        test_params = ["file", "page", "include", "path"]

        wrapper_tests = [
            ("php://filter/convert.base64-encode/resource=index.php", "base64"),
            ("php://filter/convert.base64-encode/resource=../config.php", "base64"),
            ("php://filter/convert.base64-encode/resource=../wp-config.php", "base64"),
        ]

        for param in test_params:
            for payload, check in wrapper_tests:
                url = f"{target_url}?{param}={quote(payload)}"
                resp = traversal_scanner.get(url)

                if resp and resp.status_code == 200:
                    # Check for base64 encoded content
                    if check == "base64":
                        # Look for base64-like content
                        base64_pattern = r'^[A-Za-z0-9+/]{50,}={0,2}$'
                        if re.search(base64_pattern, resp.text.strip()):
                            finding = Finding(
                                title="PHP Wrapper LFI Vulnerability",
                                severity=Severity.CRITICAL,
                                description="PHP stream wrapper allows reading source code",
                                url=url[:200],
                                evidence=f"Payload: {payload}",
                                remediation="Disable dangerous PHP wrappers. Whitelist allowed files.",
                                cwe_id="CWE-98",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            return

    @pytest.mark.traversal
    def test_log_poisoning_vectors(self, traversal_scanner, target_url, findings_collector):
        """Identify potential log poisoning entry points."""
        log_files = [
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/httpd/access_log",
            "/proc/self/environ",
        ]

        test_params = ["file", "page", "include"]

        for param in test_params:
            for log_file in log_files:
                payloads = generate_traversal_payloads(log_file.lstrip("/"))

                for payload in payloads[:3]:  # Test first 3 depths
                    url = f"{target_url}?{param}={quote(payload)}"
                    resp = traversal_scanner.get(url)

                    if resp and resp.status_code == 200:
                        # Check for log content indicators
                        log_indicators = ["GET /", "POST /", "HTTP/1", "Mozilla", "Apache", "nginx"]

                        if any(ind in resp.text for ind in log_indicators):
                            finding = Finding(
                                title="Log File Readable (Potential Log Poisoning)",
                                severity=Severity.HIGH,
                                description="Server log file is readable which may allow log poisoning",
                                url=url[:200],
                                evidence=f"Log file {log_file} is accessible",
                                remediation="Restrict file inclusion to specific directories",
                                cwe_id="CWE-117",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            return


class TestRemoteFileInclusion:
    """Tests for Remote File Inclusion vulnerabilities."""

    @pytest.mark.traversal
    def test_rfi_detection(self, traversal_scanner, target_url, findings_collector, test_config):
        """Test for Remote File Inclusion vulnerability."""
        if test_config.intensity == "light":
            pytest.skip("RFI tests skipped in light intensity mode")

        test_params = ["file", "page", "include", "url", "path"]

        # Use a safe external URL that returns identifiable content
        # Note: In real testing, you'd use a controlled server
        rfi_payloads = [
            "http://example.com/",
            "https://example.com/",
            "//example.com/",
        ]

        for param in test_params:
            for payload in rfi_payloads:
                url = f"{target_url}?{param}={quote(payload)}"
                resp = traversal_scanner.get(url)

                if resp and resp.status_code == 200:
                    # Check if external content was included
                    if "Example Domain" in resp.text or "example.com" in resp.text.lower():
                        finding = Finding(
                            title="Remote File Inclusion Vulnerability",
                            severity=Severity.CRITICAL,
                            description="Application includes content from remote URLs",
                            url=url[:200],
                            evidence=f"Payload: {payload}",
                            remediation="Disable remote file inclusion. Use allow_url_include=Off in PHP.",
                            cwe_id="CWE-98",
                            owasp_category="A01:2021 - Broken Access Control",
                        )
                        findings_collector.add(finding)
                        return


class TestSensitiveFileExposure:
    """Tests for exposed sensitive files."""

    @pytest.mark.traversal
    def test_common_sensitive_files(self, traversal_scanner, target_url, findings_collector):
        """Test for directly accessible sensitive files."""
        sensitive_paths = WEB_CONFIG_FILES + [
            "/.git/config",
            "/.git/HEAD",
            "/.svn/entries",
            "/.env",
            "/.env.local",
            "/.env.production",
            "/config/database.yml",
            "/WEB-INF/web.xml",
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/backup.sql",
            "/dump.sql",
            "/database.sql",
            "/.htpasswd",
            "/server-status",
            "/server-info",
        ]

        for path in sensitive_paths:
            url = f"{target_url}{path}"
            resp = traversal_scanner.get(url)

            if resp and resp.status_code == 200:
                # Check if it contains sensitive data
                sensitive_indicators = [
                    "password", "passwd", "secret", "api_key", "apikey",
                    "DB_", "DATABASE_", "MYSQL_", "POSTGRES_",
                    "<?php", "phpinfo()", "ref:", "[core]",  # Git
                    "INSERT INTO", "CREATE TABLE",  # SQL dumps
                    "<web-app",  # web.xml
                    "AuthType", "Require",  # .htpasswd/.htaccess
                ]

                content_lower = resp.text.lower()
                found_indicators = [ind for ind in sensitive_indicators if ind.lower() in content_lower]

                if found_indicators:
                    finding = Finding(
                        title=f"Sensitive File Exposed: {path}",
                        severity=Severity.HIGH,
                        description=f"Sensitive file {path} is publicly accessible",
                        url=url,
                        evidence=f"Contains sensitive data indicators: {found_indicators[:3]}",
                        remediation="Block access to sensitive files in web server configuration",
                        cwe_id="CWE-538",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)

    @pytest.mark.traversal
    def test_backup_files(self, traversal_scanner, target_url, findings_collector):
        """Test for exposed backup files."""
        backup_extensions = [
            ".bak", ".backup", ".old", ".orig", ".copy",
            ".tmp", ".temp", ".swp", "~", ".save",
        ]

        base_files = ["index.php", "config.php", "database.php", "settings.php", "wp-config.php"]

        for base in base_files:
            for ext in backup_extensions:
                paths = [
                    f"/{base}{ext}",
                    f"/{base}.{ext.lstrip('.')}",
                    f"/.{base}.swp",
                ]

                for path in paths:
                    url = f"{target_url}{path}"
                    resp = traversal_scanner.get(url)

                    if resp and resp.status_code == 200:
                        if "<?php" in resp.text or "define(" in resp.text:
                            finding = Finding(
                                title=f"Backup File Exposed: {path}",
                                severity=Severity.HIGH,
                                description="Backup file containing source code is accessible",
                                url=url,
                                evidence="File contains PHP code",
                                remediation="Remove backup files from web directories",
                                cwe_id="CWE-530",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)

    @pytest.mark.traversal
    def test_git_exposure(self, traversal_scanner, target_url, findings_collector):
        """Test for exposed .git directory."""
        git_paths = [
            "/.git/config",
            "/.git/HEAD",
            "/.git/index",
            "/.git/logs/HEAD",
        ]

        for path in git_paths:
            url = f"{target_url}{path}"
            resp = traversal_scanner.get(url)

            if resp and resp.status_code == 200:
                git_indicators = ["[core]", "ref:", "repositoryformatversion", "DIRC"]

                if any(ind in resp.text for ind in git_indicators):
                    finding = Finding(
                        title="Git Repository Exposed",
                        severity=Severity.HIGH,
                        description=".git directory is publicly accessible, exposing source code",
                        url=url,
                        evidence=f"Git file accessible: {path}",
                        remediation="Block access to .git directory in web server configuration",
                        cwe_id="CWE-538",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)
                    return  # Found it, no need to check more
