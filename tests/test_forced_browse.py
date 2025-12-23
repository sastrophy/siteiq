"""
Forced Browsing / Directory Brute-Force Tests

Tests for discovering hidden files and directories including:
- Common admin panels
- Backup files
- Configuration files
- Version control exposure
- Sensitive file disclosure
"""

import os
from pathlib import Path
from typing import List, Optional
from urllib.parse import urljoin

import pytest

from utils.scanner import SecurityScanner, Finding, Severity


@pytest.fixture
def browse_scanner(test_config):
    """Create scanner for forced browse tests."""
    return SecurityScanner(test_config)


def load_wordlist(wordlist_name: str) -> List[str]:
    """
    Load a wordlist file.

    Args:
        wordlist_name: Name of wordlist file or full path

    Returns:
        List of paths to test
    """
    # Check for full path
    if os.path.isfile(wordlist_name):
        wordlist_path = wordlist_name
    else:
        # Look in default wordlists directory
        base_dir = Path(__file__).parent.parent / "wordlists"
        wordlist_path = base_dir / wordlist_name

    if not os.path.isfile(wordlist_path):
        return []

    paths = []
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith('#'):
                paths.append(line)

    return paths


class TestForcedBrowsing:
    """Directory and file brute-forcing test suite."""

    # Default wordlists
    DEFAULT_DIR_WORDLIST = "common-directories.txt"
    DEFAULT_FILE_WORDLIST = "sensitive-files.txt"

    # Status codes that indicate found resources
    FOUND_STATUS_CODES = {200, 201, 202, 301, 302, 303, 307, 308, 401, 403}

    # Interesting status codes that need further investigation
    INTERESTING_STATUS_CODES = {401, 403, 500, 502, 503}

    def _check_path(
        self,
        scanner: SecurityScanner,
        base_url: str,
        path: str,
        timeout: float = 5.0,
    ) -> Optional[dict]:
        """
        Check if a path exists on the target.

        Args:
            scanner: SecurityScanner instance
            base_url: Base URL to test
            path: Path to append
            timeout: Request timeout

        Returns:
            Dict with finding info if path exists, None otherwise
        """
        # Build full URL
        if not path.startswith('/'):
            path = '/' + path
        url = urljoin(base_url.rstrip('/'), path)

        try:
            resp = scanner.request("GET", url, timeout=timeout)
            if not resp:
                return None

            if resp.status_code in self.FOUND_STATUS_CODES:
                # Determine severity based on path and status
                severity = Severity.INFO
                description = f"Found: {path}"

                # Check for sensitive paths
                sensitive_keywords = [
                    '.env', '.git', 'config', 'backup', 'admin',
                    'phpmyadmin', 'credentials', 'password', 'secret',
                    '.htaccess', 'wp-config', 'database'
                ]
                if any(kw in path.lower() for kw in sensitive_keywords):
                    severity = Severity.HIGH
                    description = f"Sensitive resource found: {path}"

                # Higher severity for accessible (200) vs blocked (401/403)
                if resp.status_code == 200:
                    if severity == Severity.INFO:
                        severity = Severity.LOW
                    description = f"Accessible resource: {path}"
                elif resp.status_code in {401, 403}:
                    description = f"Protected resource exists: {path} (HTTP {resp.status_code})"

                return {
                    "path": path,
                    "url": url,
                    "status_code": resp.status_code,
                    "content_length": len(resp.text) if resp.text else 0,
                    "severity": severity,
                    "description": description,
                    "content_snippet": resp.text[:200] if resp.text else "",
                }

        except Exception:
            pass

        return None

    @pytest.mark.security
    @pytest.mark.forced_browse
    @pytest.mark.forced_browse_dirs
    def test_common_directories(self, browse_scanner, target_url, findings_collector, request):
        """Test for common hidden directories."""
        # Get custom wordlist if provided
        wordlist = request.config.getoption("--wordlist", default=None)
        if not wordlist:
            wordlist = self.DEFAULT_DIR_WORDLIST

        paths = load_wordlist(wordlist)
        if not paths:
            pytest.skip(f"Could not load wordlist: {wordlist}")

        # Limit to avoid overwhelming target (configurable via intensity)
        intensity = request.config.getoption("--intensity", default="medium")
        if intensity == "light":
            paths = paths[:50]
        elif intensity == "medium":
            paths = paths[:150]
        # aggressive uses all paths

        vulnerabilities = []

        for path in paths:
            result = self._check_path(browse_scanner, target_url, path)
            if result:
                vulnerabilities.append(result)

        for vuln in vulnerabilities:
            finding = Finding(
                title=f"Hidden Directory Found: {vuln['path']}",
                severity=vuln["severity"],
                description=vuln["description"],
                url=vuln["url"],
                evidence=f"Status: {vuln['status_code']} | Size: {vuln['content_length']} bytes",
                remediation="Review if this resource should be publicly accessible. "
                           "Implement proper access controls or remove unnecessary files/directories. "
                           "Use robots.txt to prevent indexing (not a security control).",
                cwe_id="CWE-538",
                owasp_category="A01:2021 - Broken Access Control",
            )
            findings_collector.add(finding)
            browse_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.forced_browse
    @pytest.mark.forced_browse_files
    def test_sensitive_files(self, browse_scanner, target_url, findings_collector, request):
        """Test for sensitive file exposure."""
        paths = load_wordlist(self.DEFAULT_FILE_WORDLIST)
        if not paths:
            pytest.skip(f"Could not load wordlist: {self.DEFAULT_FILE_WORDLIST}")

        intensity = request.config.getoption("--intensity", default="medium")
        if intensity == "light":
            paths = paths[:30]
        elif intensity == "medium":
            paths = paths[:100]

        vulnerabilities = []

        for path in paths:
            result = self._check_path(browse_scanner, target_url, path)
            if result and result["status_code"] == 200:
                # Check content for additional sensitivity indicators
                content = result.get("content_snippet", "").lower()
                sensitive_content = any(kw in content for kw in [
                    "password", "secret", "api_key", "apikey", "token",
                    "mysql", "postgres", "mongodb", "private_key",
                    "[database]", "db_password", "aws_access_key"
                ])

                if sensitive_content:
                    result["severity"] = Severity.CRITICAL
                    result["description"] = f"CRITICAL: Sensitive data exposed in {path}"

                vulnerabilities.append(result)

        for vuln in vulnerabilities:
            finding = Finding(
                title=f"Sensitive File Exposed: {vuln['path']}",
                severity=vuln["severity"],
                description=vuln["description"],
                url=vuln["url"],
                evidence=f"Status: {vuln['status_code']} | Content preview: {vuln['content_snippet'][:100]}",
                remediation="Remove this file from the web root or restrict access. "
                           "Never store sensitive files in publicly accessible locations. "
                           "Review server configuration to block access to sensitive file types.",
                cwe_id="CWE-538",
                owasp_category="A01:2021 - Broken Access Control",
            )
            findings_collector.add(finding)
            browse_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.forced_browse
    @pytest.mark.forced_browse_git
    def test_git_exposure(self, browse_scanner, target_url, findings_collector):
        """Test for exposed .git directory."""
        git_paths = [
            ".git/config",
            ".git/HEAD",
            ".git/index",
            ".git/logs/HEAD",
            ".git/description",
            ".git/refs/heads/master",
            ".git/refs/heads/main",
            ".git/COMMIT_EDITMSG",
            ".gitignore",
        ]

        vulnerabilities = []

        for path in git_paths:
            result = self._check_path(browse_scanner, target_url, path)
            if result and result["status_code"] == 200:
                result["severity"] = Severity.CRITICAL
                result["description"] = f"Git repository exposed: {path}"
                vulnerabilities.append(result)

        if vulnerabilities:
            # Single critical finding for git exposure
            finding = Finding(
                title="Git Repository Exposed",
                severity=Severity.CRITICAL,
                description="The .git directory is accessible. This exposes the entire source code history, "
                           "including potentially sensitive configuration, credentials, and internal documentation.",
                url=target_url,
                evidence=f"Exposed paths: {', '.join(v['path'] for v in vulnerabilities)}",
                remediation="Block access to .git directory in web server configuration. "
                           "For Apache: 'RedirectMatch 404 /\\.git'. "
                           "For Nginx: 'location ~ /\\.git { deny all; }'. "
                           "Remove .git directory from production deployments.",
                cwe_id="CWE-538",
                owasp_category="A01:2021 - Broken Access Control",
            )
            findings_collector.add(finding)
            browse_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.forced_browse
    @pytest.mark.forced_browse_backup
    def test_backup_files(self, browse_scanner, target_url, findings_collector):
        """Test for backup file exposure."""
        # Generate backup file paths based on target URL
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        domain = parsed.netloc.replace(':', '_').replace('.', '_')

        backup_paths = [
            # Common backup archives
            "backup.zip",
            "backup.tar.gz",
            "backup.tar",
            "backup.sql",
            "backup.sql.gz",
            "db.sql",
            "database.sql",
            "dump.sql",
            "site.zip",
            "www.zip",
            "public_html.zip",
            "html.zip",
            f"{domain}.zip",
            f"{domain}.tar.gz",
            f"{domain}.sql",
            # Common CMS backups
            "wordpress.zip",
            "wp-content.zip",
            "drupal.zip",
            "joomla.zip",
            # Temp/Old files
            "index.php.bak",
            "index.php.old",
            "index.php~",
            "index.html.bak",
            "config.php.bak",
            "wp-config.php.bak",
            "web.config.bak",
            ".htaccess.bak",
        ]

        vulnerabilities = []

        for path in backup_paths:
            result = self._check_path(browse_scanner, target_url, path, timeout=10)
            if result and result["status_code"] == 200:
                result["severity"] = Severity.CRITICAL
                result["description"] = f"Backup file exposed: {path}"
                vulnerabilities.append(result)

        for vuln in vulnerabilities:
            finding = Finding(
                title=f"Backup File Exposed: {vuln['path']}",
                severity=Severity.CRITICAL,
                description="Backup files are accessible. These may contain source code, database dumps, "
                           "configuration files, and credentials.",
                url=vuln["url"],
                evidence=f"Status: {vuln['status_code']} | Size: {vuln['content_length']} bytes",
                remediation="Remove backup files from the web root. "
                           "Store backups in a secure, non-web-accessible location. "
                           "Block access to common backup file extensions in web server configuration.",
                cwe_id="CWE-530",
                owasp_category="A01:2021 - Broken Access Control",
            )
            findings_collector.add(finding)
            browse_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.forced_browse
    @pytest.mark.forced_browse_config
    def test_config_exposure(self, browse_scanner, target_url, findings_collector):
        """Test for configuration file exposure."""
        config_paths = [
            # Environment files
            ".env",
            ".env.local",
            ".env.production",
            ".env.development",
            ".env.example",
            # PHP config
            "config.php",
            "configuration.php",
            "settings.php",
            "wp-config.php",
            "LocalSettings.php",
            "config/database.php",
            "config/app.php",
            # Python config
            "settings.py",
            "local_settings.py",
            "config.py",
            "config.yaml",
            "config.yml",
            # Node.js config
            "config.json",
            ".npmrc",
            # Java config
            "application.properties",
            "application.yml",
            "application.yaml",
            # Web server config
            "nginx.conf",
            "httpd.conf",
            ".htaccess",
            "web.config",
            # Docker
            "docker-compose.yml",
            "docker-compose.yaml",
            "Dockerfile",
        ]

        vulnerabilities = []

        for path in config_paths:
            result = self._check_path(browse_scanner, target_url, path)
            if result and result["status_code"] == 200:
                # Check content for credentials
                content = result.get("content_snippet", "").lower()
                has_creds = any(kw in content for kw in [
                    "password", "secret", "key", "token", "credential",
                    "mysql", "postgres", "redis", "aws_"
                ])

                if has_creds:
                    result["severity"] = Severity.CRITICAL
                else:
                    result["severity"] = Severity.HIGH

                vulnerabilities.append(result)

        for vuln in vulnerabilities:
            finding = Finding(
                title=f"Configuration File Exposed: {vuln['path']}",
                severity=vuln["severity"],
                description="Configuration file is accessible. This may expose database credentials, "
                           "API keys, internal paths, and other sensitive configuration.",
                url=vuln["url"],
                evidence=f"Status: {vuln['status_code']} | Preview: {vuln['content_snippet'][:100]}",
                remediation="Block access to configuration files in web server configuration. "
                           "Move sensitive configuration outside the web root. "
                           "Use environment variables for credentials instead of config files.",
                cwe_id="CWE-538",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)
            browse_scanner.add_finding(finding)
