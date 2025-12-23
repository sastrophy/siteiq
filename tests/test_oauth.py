"""
OAuth 2.0 / OpenID Connect Tests

Tests for OAuth and OpenID Connect attacks including:
- Redirect URI manipulation
- State parameter bypass
- Token leakage
- PKCE bypass
- Client impersonation
"""

import pytest

from utils.scanner import SecurityScanner, Finding, Severity, extract_forms

# OAuth attack payloads
REDIRECT_URI_PAYLOADS = [
    {"redirect_uri": "http://evil.com/callback", "desc": "External domain redirect"},
    {"redirect_uri": "http://target.com/auth?redirect=http://evil.com", "desc": "Open redirect chain"},
    {"redirect_uri": "", "desc": "Empty redirect URI"},
    {"redirect_uri": "file:///etc/passwd", "desc": "File protocol"},
    {"redirect_uri": "http://127.0.0.1:8080/callback", "desc": "Localhost redirect"},
    {"redirect_uri": "javascript:alert(1)", "desc": "JavaScript protocol"},
    {"redirect_uri": "//evil.com/callback", "desc": "Protocol-relative URL"},
    {"redirect_uri": "https://target.com@evil.com/callback", "desc": "URL confusion"},
]

STATE_BYPASS_PAYLOADS = [
    {"state": "", "desc": "Empty state"},
    {"state": "bypass", "desc": "Predictable state"},
    {"state": "attacker_state_value", "desc": "Attacker controlled"},
    {"state": "../../../etc/passwd", "desc": "Path traversal in state"},
    {"state": "<script>alert(1)</script>", "desc": "XSS in state"},
]

PKCE_BYPASS_PAYLOADS = [
    {"code_challenge": "", "code_challenge_method": "S256", "desc": "Empty challenge"},
    {"code_challenge_method": "plain", "desc": "Weak method"},
    {"code_verifier": "", "desc": "Empty verifier"},
    {"code_verifier": "a" * 43, "desc": "Minimum length verifier"},
    {"code_challenge": "test", "code_challenge_method": "plain", "desc": "Plain method with weak value"},
]

SCOPE_PAYLOADS = [
    {"scope": "openid profile email admin", "desc": "Admin scope injection"},
    {"scope": "openid profile email offline_access", "desc": "Offline access"},
    {"scope": "read write delete", "desc": "Excessive permissions"},
    {"scope": "*", "desc": "Wildcard scope"},
]


@pytest.fixture
def oauth_scanner(test_config):
    """Create scanner for OAuth tests."""
    return SecurityScanner(test_config)


class TestOAuth:
    """OAuth security test suite."""

    @pytest.mark.security
    @pytest.mark.oauth
    def test_redirect_uri_manipulation(self, oauth_scanner, target_url, findings_collector):
        """Test for redirect URI manipulation."""
        auth_paths = ["/oauth/authorize", "/auth/authorize", "/api/oauth2/authorize"]

        for path in auth_paths[:2]:
            url = f"{target_url}{path}"
            resp = oauth_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms[:2]:
                redirect_uris = [
                    {"redirect_uri": "http://evil.com/callback"},
                    {"redirect_uri": "http://target.com/auth?redirect=http://evil.com"},
                    {"redirect_uri": ""},  # Open redirect
                    {"redirect_uri": "file:///etc/passwd"},
                    {"redirect_uri": "http://127.0.0.1:8080/callback"},
                ]

                for payload in redirect_uris:
                    resp = oauth_scanner.post(form["action"], data=payload)

                    if resp and resp.status_code == 200:
                        text = resp.text.lower()

                        if "evil.com" in text or "callback" in text:
                            finding = Finding(
                                title="OAuth Redirect URI Manipulation",
                                severity=Severity.HIGH,
                                description="Redirect URI can be manipulated to external domain",
                                url=form["action"],
                                evidence=f"Redirect URI: {payload.get('redirect_uri', 'N/A')}",
                                remediation="Validate redirect_uri against whitelist. Reject open redirects. Use nonce/state tokens.",
                                cwe_id="CWE-601",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            oauth_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.oauth
    def test_state_parameter_bypass(self, oauth_scanner, target_url, findings_collector):
        """Test for state parameter bypass."""
        auth_paths = ["/oauth/authorize", "/auth/authorize"]

        for path in auth_paths[:2]:
            url = f"{target_url}{path}"
            resp = oauth_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms[:2]:
                state_payloads = [
                    {"state": "bypass"},
                    {"state": ""},
                    {"state": "attacker_state_value"},
                    {"state": "csrf_token"},
                ]

                for payload in state_payloads:
                    resp = oauth_scanner.post(form["action"], data=payload)

                    if resp and resp.status_code == 200:
                        text = resp.text.lower()

                        if "bypass" in text or "accepted" in text:
                            finding = Finding(
                                title="OAuth State Parameter Bypass",
                                severity=Severity.HIGH,
                                description="State parameter validation can be bypassed",
                                url=form["action"],
                                evidence="State bypass accepted",
                                remediation="Generate cryptographically strong state values. Validate state parameter properly.",
                                cwe_id="CWE-613",
                                owasp_category="A07:2021 - Identification and Authentication Failures",
                            )
                            findings_collector.add(finding)
                            oauth_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.oauth
    def test_token_leakage_via_fragment(self, oauth_scanner, target_url, findings_collector):
        """Test for OAuth token leakage via URL fragment."""
        auth_paths = ["/oauth/authorize", "/auth/authorize", "/api/oauth2/token"]

        for path in auth_paths[:2]:
            url = f"{target_url}{path}"
            resp = oauth_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms[:2]:
                fragment_payloads = [
                    {"redirect_uri": "http://target.com#access_token=leaked_token"},
                    {"redirect_uri": "http://target.com#refresh_token=stolen_token"},
                ]

                for payload in fragment_payloads:
                    resp = oauth_scanner.post(form["action"], data=payload)

                    if resp and resp.status_code == 200:
                        text = resp.text.lower()

                        if "access_token" in text or "refresh_token" in text:
                            finding = Finding(
                                title="OAuth Token Leakage via Fragment",
                                severity=Severity.HIGH,
                                description="OAuth tokens leaked via URL fragment",
                                url=form["action"],
                                evidence="Token in fragment: access_token or refresh_token",
                                remediation="Use POST method instead of GET for token endpoint. Don't include tokens in fragment.",
                                cwe_id="CWE-598",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            oauth_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.oauth
    def test_pkce_bypass(self, oauth_scanner, target_url, findings_collector):
        """Test for PKCE (Proof Key for Code Exchange) bypass."""
        auth_paths = ["/oauth/authorize", "/auth/authorize", "/api/oauth2/authorize"]

        for path in auth_paths[:2]:
            url = f"{target_url}{path}"
            resp = oauth_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms[:2]:
                pkce_bypass_payloads = [
                    {"code_challenge": ""},
                    {"code_challenge_method": "plain"},
                    {"code_verifier": ""},
                    {"code_verifier": "weak_verifier"},
                ]

                for payload in pkce_bypass_payloads:
                    resp = oauth_scanner.post(form["action"], data=payload)

                    if resp and resp.status_code == 200:
                        text = resp.text.lower()

                        if "authorized" in text or "code" in text:
                            finding = Finding(
                                title="OAuth PKCE Bypass",
                                severity=Severity.MEDIUM,
                                description="PKCE validation can be bypassed or is weak",
                                url=form["action"],
                                evidence="PKCE bypass attempted",
                                remediation="Enforce code_challenge and code_verifier. Use strong code_verifiers. Reject empty values.",
                                cwe_id="CWE-287",
                                owasp_category="A02:2021 - Cryptographic Failures",
                            )
                            findings_collector.add(finding)
                            oauth_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.oauth
    def test_openid_response_mode(self, oauth_scanner, target_url, findings_collector):
        """Test for OpenID response mode manipulation."""
        auth_paths = ["/openid/auth", "/api/openid"]

        for path in auth_paths[:2]:
            url = f"{target_url}{path}"
            resp = oauth_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms[:2]:
                response_mode_payloads = [
                    {"response_mode": "fragment"},
                    {"response_mode": "query"},
                    {"response_mode": "post"},
                ]

                for payload in response_mode_payloads:
                    resp = oauth_scanner.post(form["action"], data=payload)

                    if resp and resp.status_code == 200:
                        text = resp.text.lower()

                        if "token" in text:
                            finding = Finding(
                                title="OpenID Response Mode - Fragment (Token Leakage)",
                                severity=Severity.HIGH,
                                description="OpenID response mode allows token leakage via fragment",
                                url=form["action"],
                                evidence="Response mode: fragment",
                                remediation="Use post mode instead of query/fragment for token delivery.",
                                cwe_id="CWE-598",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            oauth_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.oauth
    def test_openid_nonce_bypass(self, oauth_scanner, target_url, findings_collector):
        """Test for OpenID nonce parameter bypass."""
        auth_paths = ["/openid/auth", "/api/openid"]

        for path in auth_paths[:2]:
            url = f"{target_url}{path}"
            resp = oauth_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms[:1]:
                nonce_payloads = [
                    {"nonce": ""},
                    {"nonce": "bypass"},
                    {"nonce": "123456"},
                ]

                for payload in nonce_payloads:
                    resp = oauth_scanner.post(form["action"], data=payload)

                    if resp and resp.status_code == 200:
                        text = resp.text.lower()

                        if "authenticated" in text or "verified" in text:
                            finding = Finding(
                                title="OpenID Nonce Bypass",
                                severity=Severity.MEDIUM,
                                description="OpenID nonce parameter can be bypassed or is weak",
                                url=form["action"],
                                evidence="Nonce bypass attempted",
                                remediation="Generate cryptographically random nonce values. Validate nonce properly.",
                                cwe_id="CWE-287",
                                owasp_category="A02:2021 - Cryptographic Failures",
                            )
                            findings_collector.add(finding)
                            oauth_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.oauth
    def test_scope_broadening(self, oauth_scanner, target_url, findings_collector):
        """Test for OAuth scope broadening attack."""
        auth_paths = ["/oauth/authorize", "/api/oauth2/authorize"]

        for path in auth_paths[:2]:
            url = f"{target_url}{path}"
            resp = oauth_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms[:2]:
                scope_payloads = [
                    {"scope": "openid profile email address"},  # Broad scope
                    {"scope": "admin"},
                    {"scope": "read write offline_access"},
                ]

                for payload in scope_payloads:
                    resp = oauth_scanner.post(form["action"], data=payload)

                    if resp and resp.status_code == 200:
                        text = resp.text.lower()

                        if "accepted" in text or "granted" in text or "authorized" in text:
                            finding = Finding(
                                title="OAuth Scope Broadening",
                                severity=Severity.MEDIUM,
                                description="Excessive OAuth scope requested - may lead to overprivileged access",
                                url=form["action"],
                                evidence=f"Scope: {payload.get('scope', 'N/A')}",
                                remediation="Use minimum required scopes. Validate scope requests. Implement scope consent prompts.",
                                cwe_id="CWE-840",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            oauth_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.oauth
    def test_response_type_token_leak(self, oauth_scanner, target_url, findings_collector):
        """Test for token leakage via response_type (implicit flow)."""
        auth_paths = ["/oauth/authorize", "/api/oauth2/authorize"]

        for path in auth_paths[:2]:
            url = f"{target_url}{path}"
            resp = oauth_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms[:2]:
                implicit_payloads = [
                    {"response_type": "token"},  # Implicit flow returns token in fragment
                    {"response_type": "token id_token"},  # Hybrid flow
                    {"client_id": "attacker_client_id"},
                ]

                for payload in implicit_payloads:
                    resp = oauth_scanner.post(form["action"], data=payload)

                    if resp and resp.status_code == 200:
                        text = resp.text.lower()

                        if "token" in text or "access_token" in text:
                            finding = Finding(
                                title="OAuth Implicit Flow - Token in Fragment",
                                severity=Severity.HIGH,
                                description="OAuth implicit flow returns token in URL fragment which can leak to attacker",
                                url=form["action"],
                                evidence="Implicit flow with token in fragment",
                                remediation="Use authorization code flow instead of implicit flow. Don't include tokens in fragment.",
                                cwe_id="CWE-598",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            oauth_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.oauth
    def test_client_credential_theft(self, oauth_scanner, target_url, findings_collector):
        """Test for client credential exposure."""
        token_paths = ["/oauth/token", "/api/oauth2/token", "/token"]

        for path in token_paths[:2]:
            url = f"{target_url}{path}"

            # Test various client auth methods
            auth_payloads = [
                {"client_id": "test", "client_secret": "", "grant_type": "client_credentials"},
                {"client_id": "test", "grant_type": "client_credentials"},  # No secret
                {"client_id": "admin", "client_secret": "admin", "grant_type": "password"},
            ]

            for payload in auth_payloads:
                resp = oauth_scanner.post(url, data=payload)

                if resp and resp.status_code == 200:
                    text = resp.text.lower()

                    if "access_token" in text or "token_type" in text:
                        finding = Finding(
                            title="OAuth Client Credential Weakness",
                            severity=Severity.HIGH,
                            description=f"Token endpoint accepts weak credentials - {payload}",
                            url=url,
                            evidence="Access token issued without proper client authentication",
                            remediation="Require strong client authentication. Use client_secret_jwt or private_key_jwt.",
                            cwe_id="CWE-287",
                            owasp_category="A07:2021 - Identification and Authentication Failures",
                        )
                        findings_collector.add(finding)
                        oauth_scanner.add_finding(finding)
                        return
