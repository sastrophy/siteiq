"""
SQL Injection Security Tests

Tests for SQL injection vulnerabilities including:
- Classic SQL injection
- Union-based SQL injection
- Error-based SQL injection
- Blind SQL injection (boolean and time-based)
- NoSQL injection
"""

import re
import time

import pytest

from utils.scanner import SecurityScanner, Finding, Severity, extract_forms
from payloads.sql_injection import (
    CLASSIC_SQLI,
    UNION_SQLI,
    ERROR_SQLI,
    TIME_SQLI,
    BOOLEAN_SQLI,
    NOSQL_INJECTION,
    SQL_ERROR_SIGNATURES,
)


@pytest.fixture
def sqli_scanner(test_config):
    """Create scanner for SQL injection tests."""
    return SecurityScanner(test_config)


class TestSQLInjection:
    """SQL Injection test suite."""

    @pytest.mark.sql_injection
    def test_error_based_sqli_detection(self, sqli_scanner, target_url, findings_collector):
        """Test for error-based SQL injection by looking for database error messages."""
        payloads = CLASSIC_SQLI[:10]  # Use subset for initial testing

        # Test the main page and common endpoints
        test_urls = [
            target_url,
            f"{target_url}/search",
            f"{target_url}/login",
            f"{target_url}/products",
            f"{target_url}/api/search",
        ]

        for base_url in test_urls:
            response = sqli_scanner.get(base_url)
            if not response:
                continue

            # Look for forms and input fields
            forms = extract_forms(response.text, base_url)

            for payload in payloads:
                # Test URL parameters
                injected_urls = sqli_scanner.inject_payload(base_url, payload)

                for url in injected_urls:
                    resp = sqli_scanner.get(url)
                    if resp and self._check_sql_error(resp.text):
                        finding = Finding(
                            title="Potential SQL Injection (Error-Based)",
                            severity=Severity.CRITICAL,
                            description=f"Database error message detected when injecting SQL payload",
                            url=url,
                            evidence=f"Payload: {payload}",
                            remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                        )
                        findings_collector.add(finding)
                        sqli_scanner.add_finding(finding)

                # Test forms
                for form in forms:
                    form_data = {inp["name"]: payload for inp in form["inputs"]}
                    if form["method"] == "POST":
                        resp = sqli_scanner.post(form["action"], data=form_data)
                    else:
                        resp = sqli_scanner.get(form["action"], params=form_data)

                    if resp and self._check_sql_error(resp.text):
                        finding = Finding(
                            title="Potential SQL Injection in Form (Error-Based)",
                            severity=Severity.CRITICAL,
                            description=f"Database error message detected when injecting SQL payload into form",
                            url=form["action"],
                            evidence=f"Payload: {payload}, Form fields: {[i['name'] for i in form['inputs']]}",
                            remediation="Use parameterized queries or prepared statements.",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                        )
                        findings_collector.add(finding)
                        sqli_scanner.add_finding(finding)

    @pytest.mark.sql_injection
    @pytest.mark.slow
    def test_time_based_blind_sqli(self, sqli_scanner, target_url, findings_collector, test_config):
        """Test for time-based blind SQL injection."""
        if test_config.intensity == "light":
            pytest.skip("Time-based tests skipped in light intensity mode")

        payloads = TIME_SQLI[:5]
        delay_threshold = 4  # seconds

        test_urls = [
            f"{target_url}/search?q=test",
            f"{target_url}/login",
            f"{target_url}/api/users?id=1",
        ]

        for base_url in test_urls:
            for payload in payloads:
                injected_urls = sqli_scanner.inject_payload(base_url, payload)

                for url in injected_urls:
                    start_time = time.time()
                    resp = sqli_scanner.get(url, timeout=15)
                    elapsed = time.time() - start_time

                    if elapsed >= delay_threshold:
                        finding = Finding(
                            title="Potential SQL Injection (Time-Based Blind)",
                            severity=Severity.CRITICAL,
                            description=f"Response delayed by {elapsed:.2f}s suggesting time-based SQL injection",
                            url=url,
                            evidence=f"Payload: {payload}, Delay: {elapsed:.2f}s",
                            remediation="Use parameterized queries or prepared statements.",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                        )
                        findings_collector.add(finding)
                        sqli_scanner.add_finding(finding)

    @pytest.mark.sql_injection
    def test_union_based_sqli(self, sqli_scanner, target_url, findings_collector):
        """Test for union-based SQL injection."""
        payloads = UNION_SQLI[:8]

        # Common patterns that indicate successful UNION injection
        union_success_patterns = [
            r"null.*null",
            r"1.*2.*3",
            r"admin|root|user",  # Leaked usernames
            r"@version|@@version",
            r"mysql|postgresql|mssql|oracle|sqlite",
        ]

        test_urls = [
            f"{target_url}/products?id=1",
            f"{target_url}/user?id=1",
            f"{target_url}/article?id=1",
            f"{target_url}/item?id=1",
        ]

        for base_url in test_urls:
            for payload in payloads:
                injected_urls = sqli_scanner.inject_payload(base_url, payload)

                for url in injected_urls:
                    resp = sqli_scanner.get(url)
                    if not resp:
                        continue

                    # Check for UNION injection indicators
                    for pattern in union_success_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            finding = Finding(
                                title="Potential SQL Injection (Union-Based)",
                                severity=Severity.CRITICAL,
                                description=f"Response suggests successful UNION injection",
                                url=url,
                                evidence=f"Payload: {payload}, Pattern matched: {pattern}",
                                remediation="Use parameterized queries or prepared statements.",
                                cwe_id="CWE-89",
                                owasp_category="A03:2021 - Injection",
                            )
                            findings_collector.add(finding)
                            sqli_scanner.add_finding(finding)
                            break

    @pytest.mark.sql_injection
    def test_boolean_based_blind_sqli(self, sqli_scanner, target_url, findings_collector, test_config):
        """Test for boolean-based blind SQL injection."""
        if test_config.intensity == "light":
            pytest.skip("Boolean-based tests skipped in light intensity mode")

        test_urls = [
            f"{target_url}/products?id=1",
            f"{target_url}/user?id=1",
            f"{target_url}/search?q=test",
        ]

        for base_url in test_urls:
            # First, get baseline response
            baseline_resp = sqli_scanner.get(base_url)
            if not baseline_resp:
                continue

            baseline_length = len(baseline_resp.text)

            # Test with true and false conditions
            true_payloads = ["' AND '1'='1", "' AND 1=1 --", "1' AND 1=1#"]
            false_payloads = ["' AND '1'='2", "' AND 1=2 --", "1' AND 1=2#"]

            for true_payload, false_payload in zip(true_payloads, false_payloads):
                true_urls = sqli_scanner.inject_payload(base_url, true_payload)
                false_urls = sqli_scanner.inject_payload(base_url, false_payload)

                for true_url, false_url in zip(true_urls, false_urls):
                    true_resp = sqli_scanner.get(true_url)
                    false_resp = sqli_scanner.get(false_url)

                    if not true_resp or not false_resp:
                        continue

                    true_length = len(true_resp.text)
                    false_length = len(false_resp.text)

                    # If true condition matches baseline but false differs significantly
                    if (abs(true_length - baseline_length) < 100 and
                            abs(false_length - baseline_length) > 100):
                        finding = Finding(
                            title="Potential SQL Injection (Boolean-Based Blind)",
                            severity=Severity.HIGH,
                            description="Different responses for true/false SQL conditions suggest blind SQL injection",
                            url=base_url,
                            evidence=f"True payload: {true_payload}, False payload: {false_payload}",
                            remediation="Use parameterized queries or prepared statements.",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                        )
                        findings_collector.add(finding)
                        sqli_scanner.add_finding(finding)
                        break

    @pytest.mark.sql_injection
    def test_nosql_injection(self, sqli_scanner, target_url, findings_collector):
        """Test for NoSQL injection vulnerabilities."""
        payloads = NOSQL_INJECTION

        test_endpoints = [
            f"{target_url}/api/users",
            f"{target_url}/api/login",
            f"{target_url}/api/search",
            f"{target_url}/api/products",
        ]

        for endpoint in test_endpoints:
            for payload in payloads:
                # Test as query parameter
                resp = sqli_scanner.get(f"{endpoint}?query={payload}")

                # Test as JSON body
                json_resp = sqli_scanner.post(
                    endpoint,
                    json={"username": payload, "password": payload},
                    headers={"Content-Type": "application/json"}
                )

                for response in [resp, json_resp]:
                    if response and response.status_code == 200:
                        # Check for signs of NoSQL injection
                        if self._check_nosql_success(response):
                            finding = Finding(
                                title="Potential NoSQL Injection",
                                severity=Severity.HIGH,
                                description="Response suggests NoSQL injection vulnerability",
                                url=endpoint,
                                evidence=f"Payload: {payload}",
                                remediation="Validate and sanitize all user input. Use proper query builders.",
                                cwe_id="CWE-943",
                                owasp_category="A03:2021 - Injection",
                            )
                            findings_collector.add(finding)
                            sqli_scanner.add_finding(finding)

    def _check_sql_error(self, response_text: str) -> bool:
        """Check if response contains SQL error messages."""
        if not response_text:
            return False

        response_lower = response_text.lower()
        return any(sig in response_lower for sig in SQL_ERROR_SIGNATURES)

    def _check_nosql_success(self, response) -> bool:
        """Check for signs of successful NoSQL injection."""
        try:
            data = response.json()
            # Check if we got unexpected data back
            if isinstance(data, list) and len(data) > 0:
                return True
            if isinstance(data, dict) and ("users" in data or "results" in data):
                return True
        except Exception:
            pass
        return False


@pytest.mark.sql_injection
def test_second_order_sqli_locations(sqli_scanner, target_url, findings_collector):
    """Identify potential second-order SQL injection locations."""
    # These are locations where data is stored and later used in queries
    storage_endpoints = [
        "/register",
        "/signup",
        "/profile/update",
        "/settings",
        "/comment",
        "/review",
    ]

    for endpoint in storage_endpoints:
        url = f"{target_url}{endpoint}"
        resp = sqli_scanner.get(url)

        if resp and resp.status_code in [200, 302]:
            finding = Finding(
                title="Potential Second-Order SQL Injection Location",
                severity=Severity.INFO,
                description=f"Endpoint stores user data that may be used in later queries",
                url=url,
                evidence="Manual testing recommended for second-order SQL injection",
                remediation="Ensure all data is properly sanitized when stored AND when retrieved for use in queries.",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
            )
            findings_collector.add(finding)
