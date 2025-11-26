"""
Authentication Security Tests

Tests for authentication vulnerabilities including:
- Brute force protection
- Password policy
- Session management
- Account enumeration
- Credential exposure
"""

import re
import time

import pytest

from utils.scanner import SecurityScanner, Finding, Severity, extract_forms


@pytest.fixture
def auth_scanner(test_config):
    """Create scanner for authentication tests."""
    return SecurityScanner(test_config)


class TestLoginSecurity:
    """Tests for login functionality security."""

    @pytest.mark.auth
    def test_login_page_exists(self, auth_scanner, target_url, findings_collector):
        """Find and test login pages."""
        login_paths = [
            "/login",
            "/signin",
            "/auth/login",
            "/user/login",
            "/account/login",
            "/admin/login",
            "/wp-login.php",
            "/administrator",
        ]

        found_login_pages = []

        for path in login_paths:
            url = f"{target_url}{path}"
            resp = auth_scanner.get(url)

            if resp and resp.status_code == 200:
                forms = extract_forms(resp.text, url)
                # Check if it looks like a login form
                for form in forms:
                    input_names = [i["name"].lower() for i in form["inputs"]]
                    if any(n in input_names for n in ["password", "passwd", "pass", "pwd"]):
                        found_login_pages.append(url)
                        break

        return found_login_pages

    @pytest.mark.auth
    def test_brute_force_protection(self, auth_scanner, target_url, findings_collector):
        """Test for brute force protection on login."""
        login_paths = ["/login", "/signin", "/wp-login.php", "/admin/login"]

        for path in login_paths:
            url = f"{target_url}{path}"
            resp = auth_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)
            login_form = None

            for form in forms:
                input_names = [i["name"].lower() for i in form["inputs"]]
                if any(n in input_names for n in ["password", "passwd", "pass"]):
                    login_form = form
                    break

            if not login_form:
                continue

            # Try multiple failed login attempts
            failed_attempts = 0
            blocked = False

            for i in range(10):
                form_data = {}
                for inp in login_form["inputs"]:
                    name = inp["name"].lower()
                    if "user" in name or "email" in name or "login" in name:
                        form_data[inp["name"]] = f"testuser{i}@test.com"
                    elif "pass" in name or "pwd" in name:
                        form_data[inp["name"]] = f"wrongpassword{i}"
                    else:
                        form_data[inp["name"]] = "test"

                if login_form["method"] == "POST":
                    login_resp = auth_scanner.post(login_form["action"], data=form_data)
                else:
                    login_resp = auth_scanner.get(login_form["action"], params=form_data)

                if login_resp:
                    if login_resp.status_code == 429:  # Too Many Requests
                        blocked = True
                        break
                    if "blocked" in login_resp.text.lower() or "locked" in login_resp.text.lower():
                        blocked = True
                        break
                    if "captcha" in login_resp.text.lower():
                        blocked = True
                        break

                failed_attempts += 1
                time.sleep(0.5)

            if not blocked and failed_attempts >= 10:
                finding = Finding(
                    title="No Brute Force Protection Detected",
                    severity=Severity.HIGH,
                    description=f"Login form at {url} allows unlimited login attempts",
                    url=url,
                    evidence=f"Made {failed_attempts} failed login attempts without being blocked",
                    remediation="Implement rate limiting, account lockout, or CAPTCHA after failed attempts",
                    cwe_id="CWE-307",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                )
                findings_collector.add(finding)

            break  # Only test first found login form

    @pytest.mark.auth
    def test_username_enumeration(self, auth_scanner, target_url, findings_collector):
        """Test for username enumeration via error messages."""
        login_paths = ["/login", "/signin", "/wp-login.php"]

        for path in login_paths:
            url = f"{target_url}{path}"
            resp = auth_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms:
                input_names = [i["name"].lower() for i in form["inputs"]]
                if not any(n in input_names for n in ["password", "passwd", "pass"]):
                    continue

                # Test with likely invalid username
                invalid_user_data = {}
                for inp in form["inputs"]:
                    name = inp["name"].lower()
                    if "user" in name or "email" in name or "login" in name:
                        invalid_user_data[inp["name"]] = "definitelynotarealuser123456"
                    elif "pass" in name:
                        invalid_user_data[inp["name"]] = "testpassword"
                    else:
                        invalid_user_data[inp["name"]] = "test"

                # Test with likely valid username format
                valid_user_data = {}
                for inp in form["inputs"]:
                    name = inp["name"].lower()
                    if "user" in name or "email" in name or "login" in name:
                        valid_user_data[inp["name"]] = "admin"
                    elif "pass" in name:
                        valid_user_data[inp["name"]] = "testpassword"
                    else:
                        valid_user_data[inp["name"]] = "test"

                if form["method"] == "POST":
                    invalid_resp = auth_scanner.post(form["action"], data=invalid_user_data)
                    valid_resp = auth_scanner.post(form["action"], data=valid_user_data)
                else:
                    invalid_resp = auth_scanner.get(form["action"], params=invalid_user_data)
                    valid_resp = auth_scanner.get(form["action"], params=valid_user_data)

                if invalid_resp and valid_resp:
                    # Check for different error messages
                    enumeration_patterns = [
                        r"user.*(not found|doesn't exist|invalid)",
                        r"no.*account",
                        r"unknown.*user",
                        r"incorrect.*password",  # Different from "invalid credentials"
                    ]

                    invalid_text = invalid_resp.text.lower()
                    valid_text = valid_resp.text.lower()

                    for pattern in enumeration_patterns:
                        invalid_match = re.search(pattern, invalid_text)
                        valid_match = re.search(pattern, valid_text)

                        if invalid_match and not valid_match:
                            finding = Finding(
                                title="Username Enumeration Possible",
                                severity=Severity.MEDIUM,
                                description="Different error messages for valid/invalid usernames allow enumeration",
                                url=url,
                                evidence=f"Different responses for valid vs invalid usernames",
                                remediation="Use generic error messages like 'Invalid credentials'",
                                cwe_id="CWE-204",
                                owasp_category="A07:2021 - Identification and Authentication Failures",
                            )
                            findings_collector.add(finding)
                            break

                break

    @pytest.mark.auth
    def test_password_transmitted_securely(self, auth_scanner, target_url, findings_collector):
        """Test that login forms use HTTPS."""
        login_paths = ["/login", "/signin", "/wp-login.php"]

        for path in login_paths:
            url = f"{target_url}{path}"
            resp = auth_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms:
                input_names = [i["name"].lower() for i in form["inputs"]]
                if any(n in input_names for n in ["password", "passwd", "pass"]):
                    if form["action"].startswith("http://"):
                        finding = Finding(
                            title="Login Form Submits Over HTTP",
                            severity=Severity.CRITICAL,
                            description="Login form sends credentials over unencrypted HTTP",
                            url=url,
                            evidence=f"Form action: {form['action']}",
                            remediation="Always use HTTPS for login forms",
                            cwe_id="CWE-319",
                            owasp_category="A02:2021 - Cryptographic Failures",
                        )
                        findings_collector.add(finding)


class TestSessionSecurity:
    """Tests for session management security."""

    @pytest.mark.auth
    def test_session_cookie_flags(self, auth_scanner, target_url, findings_collector):
        """Test session cookie security flags."""
        resp = auth_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        cookies = resp.cookies

        session_cookie_names = ["sessionid", "session", "phpsessid", "jsessionid", "aspsessionid", "sid"]

        for cookie in resp.headers.get("Set-Cookie", "").split(","):
            cookie_lower = cookie.lower()

            # Check if it's a session-like cookie
            is_session_cookie = any(name in cookie_lower for name in session_cookie_names)

            if not is_session_cookie:
                continue

            # Extract cookie name
            cookie_name = cookie.split("=")[0].strip()

            # Check for Secure flag
            if target_url.startswith("https://") and "secure" not in cookie_lower:
                finding = Finding(
                    title=f"Session Cookie Missing Secure Flag: {cookie_name}",
                    severity=Severity.MEDIUM,
                    description="Session cookie can be transmitted over unencrypted connection",
                    url=target_url,
                    evidence=f"Cookie: {cookie[:100]}",
                    remediation="Add Secure flag to session cookies",
                    cwe_id="CWE-614",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                )
                findings_collector.add(finding)

            # Check for HttpOnly flag
            if "httponly" not in cookie_lower:
                finding = Finding(
                    title=f"Session Cookie Missing HttpOnly Flag: {cookie_name}",
                    severity=Severity.MEDIUM,
                    description="Session cookie accessible via JavaScript (XSS risk)",
                    url=target_url,
                    evidence=f"Cookie: {cookie[:100]}",
                    remediation="Add HttpOnly flag to session cookies",
                    cwe_id="CWE-1004",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                )
                findings_collector.add(finding)

            # Check for SameSite attribute
            if "samesite" not in cookie_lower:
                finding = Finding(
                    title=f"Session Cookie Missing SameSite Attribute: {cookie_name}",
                    severity=Severity.LOW,
                    description="Session cookie missing SameSite attribute (CSRF risk)",
                    url=target_url,
                    evidence=f"Cookie: {cookie[:100]}",
                    remediation="Add SameSite=Strict or SameSite=Lax to cookies",
                    cwe_id="CWE-1275",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                )
                findings_collector.add(finding)

    @pytest.mark.auth
    def test_session_id_in_url(self, auth_scanner, target_url, findings_collector):
        """Test for session IDs exposed in URLs."""
        resp = auth_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        # Check response URL for session parameters
        session_params = ["sessionid", "session", "sid", "phpsessid", "jsessionid", "token"]

        final_url = str(resp.url)

        for param in session_params:
            if f"{param}=" in final_url.lower():
                finding = Finding(
                    title="Session ID Exposed in URL",
                    severity=Severity.HIGH,
                    description="Session identifier is passed via URL parameter",
                    url=final_url,
                    evidence=f"Session parameter in URL: {param}",
                    remediation="Use cookies for session management instead of URL parameters",
                    cwe_id="CWE-598",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                )
                findings_collector.add(finding)
                break

        # Check page content for session in links
        session_in_links = re.findall(
            r'href=["\'][^"\']*[?&](session|sid|token)=[^"\']*["\']',
            resp.text,
            re.IGNORECASE
        )

        if session_in_links:
            finding = Finding(
                title="Session ID Exposed in Links",
                severity=Severity.MEDIUM,
                description="Page contains links with session identifiers",
                url=target_url,
                evidence=f"Found {len(session_in_links)} links with session parameters",
                remediation="Remove session IDs from URLs and use cookies",
                cwe_id="CWE-598",
                owasp_category="A07:2021 - Identification and Authentication Failures",
            )
            findings_collector.add(finding)


class TestPasswordReset:
    """Tests for password reset functionality."""

    @pytest.mark.auth
    def test_password_reset_enumeration(self, auth_scanner, target_url, findings_collector):
        """Test for user enumeration via password reset."""
        reset_paths = [
            "/forgot-password",
            "/password/reset",
            "/reset-password",
            "/account/forgot",
            "/wp-login.php?action=lostpassword",
        ]

        for path in reset_paths:
            url = f"{target_url}{path}"
            resp = auth_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms:
                input_names = [i["name"].lower() for i in form["inputs"]]
                if any(n in input_names for n in ["email", "user", "username"]):
                    # Test with invalid email
                    invalid_data = {}
                    valid_data = {}

                    for inp in form["inputs"]:
                        name = inp["name"].lower()
                        if "email" in name or "user" in name:
                            invalid_data[inp["name"]] = "notarealemail12345@nowhere.invalid"
                            valid_data[inp["name"]] = "admin@example.com"
                        else:
                            invalid_data[inp["name"]] = "test"
                            valid_data[inp["name"]] = "test"

                    if form["method"] == "POST":
                        invalid_resp = auth_scanner.post(form["action"], data=invalid_data)
                        valid_resp = auth_scanner.post(form["action"], data=valid_data)
                    else:
                        invalid_resp = auth_scanner.get(form["action"], params=invalid_data)
                        valid_resp = auth_scanner.get(form["action"], params=valid_data)

                    if invalid_resp and valid_resp:
                        # Check for different messages
                        if len(invalid_resp.text) != len(valid_resp.text):
                            finding = Finding(
                                title="User Enumeration via Password Reset",
                                severity=Severity.MEDIUM,
                                description="Password reset reveals whether email exists",
                                url=url,
                                evidence="Different response lengths for valid/invalid emails",
                                remediation="Return same message regardless of email existence",
                                cwe_id="CWE-204",
                                owasp_category="A07:2021 - Identification and Authentication Failures",
                            )
                            findings_collector.add(finding)

                    break
            break


class TestDefaultCredentials:
    """Tests for default credentials."""

    @pytest.mark.auth
    def test_common_admin_paths(self, auth_scanner, target_url, findings_collector):
        """Test for accessible admin panels."""
        admin_paths = [
            "/admin",
            "/administrator",
            "/admin.php",
            "/wp-admin",
            "/backend",
            "/manage",
            "/control",
            "/cpanel",
            "/dashboard",
            "/phpmyadmin",
            "/adminer",
        ]

        for path in admin_paths:
            url = f"{target_url}{path}"
            resp = auth_scanner.get(url, allow_redirects=False)

            if resp:
                if resp.status_code == 200:
                    finding = Finding(
                        title=f"Admin Panel Accessible: {path}",
                        severity=Severity.INFO,
                        description=f"Admin panel found at {path}",
                        url=url,
                        evidence=f"Status: {resp.status_code}",
                        remediation="Restrict admin panel access by IP or additional authentication",
                        cwe_id="CWE-284",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)
                elif resp.status_code in [401, 403]:
                    finding = Finding(
                        title=f"Admin Panel Found (Protected): {path}",
                        severity=Severity.INFO,
                        description=f"Admin panel exists but requires authentication",
                        url=url,
                        evidence=f"Status: {resp.status_code}",
                        remediation="Ensure strong authentication is in place",
                        cwe_id="CWE-284",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)
