"""
HTTP Parameter Pollution (HPP) Tests

Tests for HTTP Parameter Pollution attacks including:
- Parameter duplication
- Array notation
- WAF bypass via HPP
- Backend framework bypass
"""

import pytest

from utils.scanner import SecurityScanner, Finding, Severity, extract_forms

# HPP payloads - using tuples for duplicate keys
HPP_ID_PAYLOADS = [
    [("id", "123"), ("id", "456")],
    [("id", "1"), ("id", "999")],
    [("id", "valid"), ("id", "' OR '1'='1")],
]

HPP_USER_PAYLOADS = [
    [("user", "admin"), ("user", "guest")],
    [("username", "admin"), ("username", "victim")],
    [("user_id", "1"), ("user_id", "2")],
]

HPP_ROLE_PAYLOADS = [
    [("role", "admin"), ("role", "user")],
    [("is_admin", "true"), ("is_admin", "false")],
    [("user_type", "administrator"), ("user_type", "normal")],
    [("privilege", "1"), ("privilege", "0")],
]

HPP_WAF_BYPASS_PAYLOADS = [
    [("id", "1"), ("id", "1' OR '1'='1")],
    [("search", "test"), ("search", "<script>alert(1)</script>")],
    [("query", "normal"), ("query", "1' UNION SELECT * FROM users--")],
    [("cmd", "safe"), ("cmd", "; cat /etc/passwd")],
]

HPP_ARRAY_PAYLOADS = [
    {"id[]": ["123", "456"]},
    {"user[]": ["admin", "victim"]},
    {"items[]": ["1", "2", "3"]},
]


@pytest.fixture
def hpp_scanner(test_config):
    """Create scanner for HPP tests."""
    return SecurityScanner(test_config)


class TestHPP:
    """HTTP Parameter Pollution test suite."""

    def _send_hpp_request(self, scanner, url, params_list, method="POST"):
        """Send request with duplicate parameters using list of tuples."""
        if method == "POST":
            # For POST, we need to construct body manually
            from urllib.parse import urlencode
            body = urlencode(params_list)
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            return scanner.post(url, data=body, headers=headers)
        else:
            # For GET, append to URL
            from urllib.parse import urlencode
            query_string = urlencode(params_list)
            full_url = f"{url}?{query_string}" if "?" not in url else f"{url}&{query_string}"
            return scanner.get(full_url)

    def _check_hpp_duplicate_accepted(self, form_action, param_name, param_values, resp_text):
        """Check if duplicate parameter was accepted."""
        param_str = str(param_values)

        if "duplicate" in resp_text.lower() or "accepted" in resp_text.lower():
            finding = Finding(
                title="HTTP Parameter Pollution - Duplicate Parameter",
                severity=Severity.MEDIUM,
                description=f"Duplicate parameter {param_name} accepted by server - {param_str}",
                url=form_action,
                evidence="Parameter duplication accepted",
                remediation="Validate parameter uniqueness server-side. Reject duplicate parameters. Use first or last value only.",
                cwe_id="CWE-440",
                owasp_category="A01:2021 - Broken Access Control",
            )
            return finding
        return None

    @pytest.mark.security
    @pytest.mark.hpp
    def test_duplicate_id_parameter(self, hpp_scanner, target_url, findings_collector):
        """Test for duplicate ID parameter HPP."""
        resp = hpp_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)

        for form in forms[:3]:
            for inp in form["inputs"]:
                if "id" in inp["name"].lower():
                    for hpp_params in HPP_ID_PAYLOADS:
                        resp = self._send_hpp_request(hpp_scanner, form["action"], hpp_params)

                        if resp and resp.status_code == 200:
                            text = resp.text.lower()
                            # Check if second value was used (indicates HPP vulnerability)
                            second_value = hpp_params[1][1].lower() if len(hpp_params) > 1 else ""

                            if second_value in text or "456" in text or "999" in text:
                                finding = Finding(
                                    title="HTTP Parameter Pollution - ID Parameter",
                                    severity=Severity.MEDIUM,
                                    description=f"Duplicate ID parameter accepted - second value used: {hpp_params}",
                                    url=form["action"],
                                    evidence=f"HPP payload: {hpp_params}",
                                    remediation="Validate parameter uniqueness. Use only first occurrence of parameter.",
                                    cwe_id="CWE-440",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                hpp_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.hpp
    def test_duplicate_user_parameter(self, hpp_scanner, target_url, findings_collector):
        """Test for duplicate user parameter HPP."""
        resp = hpp_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)

        for form in forms[:3]:
            for inp in form["inputs"]:
                if "user" in inp["name"].lower() or "username" in inp["name"].lower():
                    for hpp_params in HPP_USER_PAYLOADS:
                        resp = self._send_hpp_request(hpp_scanner, form["action"], hpp_params)

                        if resp and resp.status_code == 200:
                            text = resp.text.lower()

                            # Check if admin access was granted via HPP
                            if "admin" in text and "welcome" in text:
                                finding = Finding(
                                    title="HPP - User Parameter Pollution",
                                    severity=Severity.HIGH,
                                    description=f"User parameter manipulation via HPP - {hpp_params}",
                                    url=form["action"],
                                    evidence="Admin access via duplicate user parameter",
                                    remediation="Validate user parameter uniqueness. Reject duplicate usernames.",
                                    cwe_id="CWE-440",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                hpp_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.hpp
    def test_array_notation_hpp(self, hpp_scanner, target_url, findings_collector):
        """Test for array notation HPP."""
        resp = hpp_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)

        for form in forms[:2]:
            for inp in form["inputs"]:
                if "id" in inp["name"].lower() or "user" in inp["name"].lower():
                    for array_payload in HPP_ARRAY_PAYLOADS:
                        resp = hpp_scanner.post(form["action"], data=array_payload)

                        if resp and resp.status_code == 200:
                            text = resp.text.lower()

                            if "456" in text or "victim" in text or "accepted" in text:
                                finding = Finding(
                                    title="HPP - Array Notation Accepted",
                                    severity=Severity.MEDIUM,
                                    description=f"Array notation parameter accepted - {array_payload}",
                                    url=form["action"],
                                    evidence=f"Array notation: {array_payload}",
                                    remediation="Validate array parameters. Flatten arrays or use first/last values only.",
                                    cwe_id="CWE-440",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                hpp_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.hpp
    def test_role_parameter_bypass(self, hpp_scanner, target_url, findings_collector):
        """Test for role parameter privilege escalation via HPP."""
        resp = hpp_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)

        for form in forms[:3]:
            for inp in form["inputs"]:
                if "role" in inp["name"].lower() or "is_admin" in inp["name"].lower() or "user_type" in inp["name"].lower():
                    for hpp_params in HPP_ROLE_PAYLOADS:
                        resp = self._send_hpp_request(hpp_scanner, form["action"], hpp_params)

                        if resp and resp.status_code == 200:
                            text = resp.text.lower()

                            if "admin" in text or "administrator" in text or "elevated" in text:
                                finding = Finding(
                                    title="Privilege Escalation via HPP",
                                    severity=Severity.HIGH,
                                    description=f"Role parameter manipulated via HPP - {hpp_params}",
                                    url=form["action"],
                                    evidence="Privilege escalation via duplicate parameters",
                                    remediation="Never trust client-side role parameters. Validate roles server-side. Use fixed roles.",
                                    cwe_id="CWE-269",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                hpp_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.hpp
    def test_waf_bypass_via_hpp(self, hpp_scanner, target_url, findings_collector):
        """Test for WAF bypass via HPP."""
        resp = hpp_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)

        for form in forms[:2]:
            for inp in form["inputs"]:
                if "id" in inp["name"].lower() or "search" in inp["name"].lower() or "query" in inp["name"].lower():
                    for hpp_params in HPP_WAF_BYPASS_PAYLOADS:
                        resp = self._send_hpp_request(hpp_scanner, form["action"], hpp_params)

                        if resp and resp.status_code == 200:
                            text = resp.text.lower()

                            # Check if malicious payload was processed
                            if "alert" in text or "union" in text.lower() or "passwd" in text:
                                finding = Finding(
                                    title="WAF Bypass via HPP",
                                    severity=Severity.HIGH,
                                    description=f"WAF bypass via HPP - malicious second param executed: {hpp_params}",
                                    url=form["action"],
                                    evidence="Second parameter bypassed WAF filtering",
                                    remediation="Implement proper input validation. Use parameter whitelist. Normalize request parameters.",
                                    cwe_id="CWE-444",
                                    owasp_category="A05:2021 - Security Misconfiguration",
                                )
                                findings_collector.add(finding)
                                hpp_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.hpp
    def test_idor_via_hpp(self, hpp_scanner, target_url, findings_collector):
        """Test for IDOR via HTTP parameter pollution."""
        test_paths = ["/user", "/profile", "/api/users", "/account"]

        for path in test_paths[:3]:
            # Test with duplicate ID parameters in URL
            hpp_params = [("id", "1"), ("id", "2")]
            url = f"{target_url}{path}"

            resp = self._send_hpp_request(hpp_scanner, url, hpp_params, method="GET")

            if resp and resp.status_code == 200:
                text = resp.text.lower()

                # Check if we can access different user's data
                if "user 2" in text or "userid: 2" in text or "different user" in text:
                    finding = Finding(
                        title="IDOR via HPP",
                        severity=Severity.HIGH,
                        description="Different user data accessible via HPP",
                        url=url,
                        evidence=f"HPP params: {hpp_params} returned different user data",
                        remediation="Validate user authorization per request. Don't trust user IDs from parameters.",
                        cwe_id="CWE-639",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)
                    hpp_scanner.add_finding(finding)
                    return

    @pytest.mark.security
    @pytest.mark.hpp
    def test_negative_values_via_hpp(self, hpp_scanner, target_url, findings_collector):
        """Test for negative value acceptance via HPP."""
        resp = hpp_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)

        for form in forms[:2]:
            for inp in form["inputs"]:
                if "amount" in inp["name"].lower() or "quantity" in inp["name"].lower() or "price" in inp["name"].lower():
                    # Use duplicate params - first positive, second negative
                    hpp_params = [
                        [(inp["name"], "100"), (inp["name"], "-100")],
                        [(inp["name"], "1"), (inp["name"], "-999")],
                    ]

                    for params in hpp_params:
                        resp = self._send_hpp_request(hpp_scanner, form["action"], params)

                        if resp and resp.status_code == 200:
                            text = resp.text.lower()

                            if "success" in text or "order" in text or "processed" in text:
                                finding = Finding(
                                    title="Negative Value Accepted via HPP",
                                    severity=Severity.HIGH,
                                    description=f"Negative values accepted via HPP - {params}",
                                    url=form["action"],
                                    evidence="Negative value in duplicate parameter accepted",
                                    remediation="Validate all numeric inputs server-side. Reject negative values.",
                                    cwe_id="CWE-400",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                hpp_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.hpp
    def test_json_parameter_pollution(self, hpp_scanner, target_url, findings_collector):
        """Test for JSON parameter pollution."""
        api_paths = ["/api/user", "/api/login", "/api/update"]

        for path in api_paths[:2]:
            url = f"{target_url}{path}"

            # JSON with duplicate keys (some parsers use last value)
            json_payloads = [
                '{"role": "user", "role": "admin"}',
                '{"id": 1, "id": 999}',
                '{"admin": false, "admin": true}',
            ]

            for payload in json_payloads:
                headers = {"Content-Type": "application/json"}

                try:
                    resp = hpp_scanner.post(url, data=payload, headers=headers)

                    if resp and resp.status_code == 200:
                        text = resp.text.lower()

                        if "admin" in text or "999" in text or "elevated" in text:
                            finding = Finding(
                                title="JSON Parameter Pollution",
                                severity=Severity.MEDIUM,
                                description=f"JSON with duplicate keys processed - {payload}",
                                url=url,
                                evidence="JSON duplicate key accepted",
                                remediation="Use strict JSON parsers. Reject duplicate keys in JSON.",
                                cwe_id="CWE-440",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            hpp_scanner.add_finding(finding)
                            return
                except Exception:
                    pass
