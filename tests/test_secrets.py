"""
Secrets Detection Tests

Tests for leaked credentials and exposed secrets including:
- API keys in responses
- Exposed configuration files
- Credentials in JavaScript
- Environment variable leakage
"""

import re
import pytest
from urllib.parse import urljoin

from utils.scanner import SecurityScanner, Finding, Severity
from payloads.secrets import (
    COMPILED_SECRET_PATTERNS,
    CONFIG_EXPOSURE_PATHS,
    JS_FILE_PATTERNS,
    SOURCE_MAP_PATTERNS,
)


@pytest.fixture
def secrets_scanner(test_config):
    """Create scanner for secrets tests."""
    return SecurityScanner(test_config)


class TestSecretsDetection:
    """Secrets Detection test suite."""

    def _scan_content_for_secrets(self, content: str) -> list:
        """Scan content for secret patterns."""
        found_secrets = []

        for name, info in COMPILED_SECRET_PATTERNS.items():
            matches = info["regex"].findall(content)
            if matches:
                for match in matches[:3]:  # Limit to first 3 matches per pattern
                    # Mask the secret for reporting
                    match_str = match if isinstance(match, str) else match[0] if match else ""
                    if len(match_str) > 8:
                        masked = match_str[:4] + "*" * (len(match_str) - 8) + match_str[-4:]
                    else:
                        masked = "*" * len(match_str)

                    found_secrets.append({
                        "type": name,
                        "description": info["description"],
                        "severity": info["severity"],
                        "masked_value": masked,
                    })

        return found_secrets

    @pytest.mark.security
    @pytest.mark.secrets
    @pytest.mark.config_exposure
    def test_config_file_exposure(self, secrets_scanner, target_url, findings_collector):
        """Test for exposed configuration files."""
        exposed_configs = []

        for path in CONFIG_EXPOSURE_PATHS[:50]:  # Limit to prevent excessive requests
            url = urljoin(target_url.rstrip('/') + '/', path.lstrip('/'))
            resp = secrets_scanner.request("GET", url)

            if resp and resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "").lower()

                # Skip HTML error pages
                if "html" in content_type and len(resp.text) < 500:
                    if "not found" in resp.text.lower() or "error" in resp.text.lower():
                        continue

                # Check if it looks like a config file
                config_indicators = [
                    "password", "secret", "key", "token", "database",
                    "api_key", "apikey", "auth", "credential", "private",
                    "DB_", "AWS_", "STRIPE_", "-----BEGIN",
                ]

                content_lower = resp.text.lower()
                found_indicators = [ind for ind in config_indicators if ind.lower() in content_lower]

                if found_indicators or path.endswith(('.env', '.json', '.yaml', '.yml', '.xml', '.ini')):
                    # Scan for actual secrets
                    secrets = self._scan_content_for_secrets(resp.text)

                    severity = Severity.CRITICAL if secrets else Severity.HIGH
                    exposed_configs.append({
                        "url": url,
                        "path": path,
                        "secrets_found": len(secrets),
                        "indicators": found_indicators[:3],
                    })

                    if secrets:
                        secret_types = list(set([s["description"] for s in secrets]))
                        finding = Finding(
                            title=f"Secrets Exposed in Config File ({path})",
                            severity=severity,
                            description=f"Configuration file {path} is publicly accessible and contains {len(secrets)} potential secrets.",
                            url=url,
                            evidence=f"Secret types found: {', '.join(secret_types[:5])}",
                            remediation="Remove config files from web root. Use environment variables. Add to .gitignore. Configure web server to block access to sensitive files.",
                            cwe_id="CWE-200",
                            owasp_category="A01:2021 - Broken Access Control",
                        )
                        findings_collector.add(finding)
                        secrets_scanner.add_finding(finding)

        # Report exposed configs even without confirmed secrets
        if exposed_configs and not any(c["secrets_found"] for c in exposed_configs):
            finding = Finding(
                title="Configuration Files Exposed",
                severity=Severity.MEDIUM,
                description=f"Found {len(exposed_configs)} accessible configuration file(s).",
                url=exposed_configs[0]["url"],
                evidence=f"Exposed paths: {[c['path'] for c in exposed_configs[:5]]}",
                remediation="Block access to configuration files via web server config. Move sensitive files outside web root.",
                cwe_id="CWE-200",
                owasp_category="A01:2021 - Broken Access Control",
            )
            findings_collector.add(finding)
            secrets_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.secrets
    @pytest.mark.js_secrets
    def test_secrets_in_javascript(self, secrets_scanner, target_url, findings_collector):
        """Test for secrets exposed in JavaScript files."""
        js_secrets = []

        # First, get the main page and extract JS URLs
        main_resp = secrets_scanner.request("GET", target_url)
        if main_resp and main_resp.status_code == 200:
            # Find script tags
            script_pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
            scripts = re.findall(script_pattern, main_resp.text, re.IGNORECASE)

            # Add common JS paths
            scripts.extend(JS_FILE_PATTERNS[:10])

            for script_path in scripts[:20]:  # Limit
                if script_path.startswith(('http://', 'https://')):
                    url = script_path
                else:
                    url = urljoin(target_url.rstrip('/') + '/', script_path.lstrip('/'))

                resp = secrets_scanner.request("GET", url)
                if resp and resp.status_code == 200 and len(resp.text) > 100:
                    secrets = self._scan_content_for_secrets(resp.text)

                    if secrets:
                        js_secrets.extend([{**s, "url": url} for s in secrets])

        if js_secrets:
            # Deduplicate by type
            unique_types = list(set([s["description"] for s in js_secrets]))
            critical_count = sum(1 for s in js_secrets if s["severity"] == "critical")

            severity = Severity.CRITICAL if critical_count > 0 else Severity.HIGH
            finding = Finding(
                title="Secrets Exposed in JavaScript",
                severity=severity,
                description=f"Found {len(js_secrets)} potential secrets in JavaScript files. Types: {', '.join(unique_types[:5])}",
                url=js_secrets[0]["url"],
                evidence=f"Secret types: {unique_types[:5]}, Critical: {critical_count}",
                remediation="Never embed secrets in client-side JavaScript. Use backend APIs to handle sensitive operations. Rotate any exposed credentials immediately.",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
            )
            findings_collector.add(finding)
            secrets_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.secrets
    @pytest.mark.sourcemaps
    def test_source_maps_exposure(self, secrets_scanner, target_url, findings_collector):
        """Test for exposed source maps that may contain secrets."""
        exposed_maps = []

        for path in SOURCE_MAP_PATTERNS:
            url = urljoin(target_url.rstrip('/') + '/', path.lstrip('/'))
            resp = secrets_scanner.request("GET", url)

            if resp and resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "").lower()

                # Check if it's a valid source map
                if "json" in content_type or resp.text.strip().startswith('{'):
                    try:
                        data = resp.json()
                        if "mappings" in data or "sources" in data:
                            exposed_maps.append({
                                "url": url,
                                "sources": len(data.get("sources", [])),
                            })

                            # Check sourcesContent for secrets
                            sources_content = data.get("sourcesContent", [])
                            for content in sources_content:
                                if content:
                                    secrets = self._scan_content_for_secrets(str(content))
                                    if secrets:
                                        finding = Finding(
                                            title="Secrets in Source Map",
                                            severity=Severity.HIGH,
                                            description=f"Source map at {url} contains original source code with secrets.",
                                            url=url,
                                            evidence=f"Found {len(secrets)} potential secrets in source map content",
                                            remediation="Disable source maps in production builds. If needed, restrict access via authentication.",
                                            cwe_id="CWE-540",
                                            owasp_category="A05:2021 - Security Misconfiguration",
                                        )
                                        findings_collector.add(finding)
                                        secrets_scanner.add_finding(finding)
                                        return
                    except Exception:
                        pass

        if exposed_maps:
            finding = Finding(
                title="Source Maps Publicly Accessible",
                severity=Severity.LOW,
                description=f"Found {len(exposed_maps)} exposed source map(s). These reveal original source code structure.",
                url=exposed_maps[0]["url"],
                evidence=f"Source maps: {[m['url'] for m in exposed_maps[:3]]}",
                remediation="Remove source maps from production or restrict access. Configure build tools to exclude source maps from deployment.",
                cwe_id="CWE-540",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)
            secrets_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.secrets
    @pytest.mark.response_secrets
    def test_secrets_in_responses(self, secrets_scanner, target_url, findings_collector):
        """Test for secrets leaked in HTTP responses."""
        # Check main page and common API endpoints
        endpoints = [
            target_url,
            urljoin(target_url, "/api"),
            urljoin(target_url, "/api/config"),
            urljoin(target_url, "/api/settings"),
            urljoin(target_url, "/api/user"),
            urljoin(target_url, "/api/me"),
            urljoin(target_url, "/debug"),
            urljoin(target_url, "/info"),
        ]

        all_secrets = []
        for url in endpoints:
            resp = secrets_scanner.request("GET", url)
            if resp and resp.status_code == 200:
                secrets = self._scan_content_for_secrets(resp.text)
                if secrets:
                    all_secrets.extend([{**s, "url": url} for s in secrets])

                # Also check response headers
                headers_str = str(resp.headers)
                header_secrets = self._scan_content_for_secrets(headers_str)
                if header_secrets:
                    all_secrets.extend([{**s, "url": url, "location": "headers"} for s in header_secrets])

        if all_secrets:
            unique_types = list(set([s["description"] for s in all_secrets]))
            finding = Finding(
                title="Secrets Leaked in HTTP Responses",
                severity=Severity.HIGH,
                description=f"Found {len(all_secrets)} potential secrets in HTTP responses.",
                url=all_secrets[0]["url"],
                evidence=f"Secret types: {', '.join(unique_types[:5])}",
                remediation="Audit API responses for sensitive data leakage. Implement proper data filtering. Never expose internal secrets to clients.",
                cwe_id="CWE-200",
                owasp_category="A01:2021 - Broken Access Control",
            )
            findings_collector.add(finding)
            secrets_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.secrets
    @pytest.mark.git_exposure
    def test_git_exposure(self, secrets_scanner, target_url, findings_collector):
        """Test for exposed .git directory."""
        git_paths = [
            "/.git/config",
            "/.git/HEAD",
            "/.git/index",
            "/.git/logs/HEAD",
            "/.git/refs/heads/main",
            "/.git/refs/heads/master",
        ]

        for path in git_paths:
            url = urljoin(target_url.rstrip('/') + '/', path.lstrip('/'))
            resp = secrets_scanner.request("GET", url)

            if resp and resp.status_code == 200:
                content = resp.text

                # Verify it's actually git content
                git_indicators = ["[core]", "ref:", "repositoryformatversion", "blob", "tree"]
                if any(ind in content for ind in git_indicators):
                    finding = Finding(
                        title="Git Repository Exposed",
                        severity=Severity.CRITICAL,
                        description=f"The .git directory is publicly accessible. Attackers can download the entire repository including history and potentially secrets.",
                        url=url,
                        evidence=f"Accessible path: {path}",
                        remediation="Block access to .git directory in web server config. Add to .htaccess: `RedirectMatch 404 /\\.git`",
                        cwe_id="CWE-527",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)
                    secrets_scanner.add_finding(finding)
                    return
