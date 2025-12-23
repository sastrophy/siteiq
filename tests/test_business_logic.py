"""
Business Logic Flaws Tests

Tests for business logic vulnerability testing including:
- Price manipulation
- Coupon abuse
- Parameter tampering
- Workflow bypass
- Privilege escalation
"""

import re

import pytest

from utils.scanner import SecurityScanner, Finding, Severity, extract_forms


@pytest.fixture
def business_logic_scanner(test_config):
    """Create scanner for business logic tests."""
    return SecurityScanner(test_config)


class TestBusinessLogicFlaws:
    """Business logic flaw test suite."""

    def _check_negative_value_accepted(self, form_action, field_name, field_value, result_text):
        """Check if negative value was accepted."""
        if "success" in result_text.lower() or "accepted" in result_text.lower():
            finding = Finding(
                title=f"Negative {field_name} Accepted",
                severity=Severity.HIGH,
                description=f"Negative value {field_value} for {field_name} was accepted",
                url=form_action,
                evidence=f"{field_name}: {field_value}",
                remediation=f"Validate all numeric inputs server-side. Reject negative values for {field_name}.",
                cwe_id="CWE-400",
                owasp_category="A01:2021 - Broken Access Control",
            )
            return finding
        return None

    @pytest.mark.security
    @pytest.mark.business_logic
    def test_negative_price(self, business_logic_scanner, target_url, findings_collector):
        """Test for negative price manipulation."""
        resp = business_logic_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)

        for form in forms[:3]:
            for inp in form["inputs"]:
                if "price" in inp["name"].lower():
                    negative_prices = [-100, -1, -999999]

                    for price in negative_prices:
                        form_data = {inp["name"]: price, "quantity": 1}

                        resp = business_logic_scanner.post(form["action"], data=form_data)

                        if resp and resp.status_code == 200:
                            text = resp.text.lower()

                            finding = self._check_negative_value_accepted(form["action"], "price", price, text)
                            if finding:
                                findings_collector.add(finding)
                                business_logic_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.business_logic
    def test_price_overflow(self, business_logic_scanner, target_url, findings_collector):
        """Test for price overflow attacks."""
        resp = business_logic_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)

        for form in forms[:2]:
            for inp in form["inputs"]:
                if "price" in inp["name"].lower():
                    overflow_payloads = [1.7976931348623157e308, 999999999999, float('inf')]

                    for price in overflow_payloads:
                        form_data = {inp["name"]: price, "quantity": 1}

                        resp = business_logic_scanner.post(form["action"], data=form_data)

                        if resp and resp.status_code == 200:
                            text = resp.text.lower()

                            if "success" in text or "order" in text:
                                finding = Finding(
                                    title="Price Overflow Attack",
                                    severity=Severity.HIGH,
                                    description=f"Overflow price {price} was accepted",
                                    url=form["action"],
                                    evidence=f"Price: {price}",
                                    remediation="Validate numeric ranges. Use 64-bit integers. Reject float values for prices.",
                                    cwe_id="CWE-190",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                business_logic_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.business_logic
    def test_quantity_manipulation(self, business_logic_scanner, target_url, findings_collector):
        """Test for quantity manipulation attacks."""
        resp = business_logic_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)

        for form in forms[:3]:
            for inp in form["inputs"]:
                if "quantity" in inp["name"].lower():
                    manip_payloads = [-1, 0, 999999, 1.5]

                    for quantity in manip_payloads:
                        form_data = {inp["name"]: quantity, "price": 100}

                        resp = business_logic_scanner.post(form["action"], data=form_data)

                        if resp and resp.status_code == 200:
                            text = resp.text.lower()

                            if quantity < 1 and ("success" in text or "order" in text):
                                finding = Finding(
                                    title="Negative or Zero Quantity",
                                    severity=Severity.MEDIUM,
                                    description=f"Quantity {quantity} was accepted - potential free item",
                                    url=form["action"],
                                    evidence=f"Quantity: {quantity}",
                                    remediation="Validate quantity is positive integer. Reject zero or negative values.",
                                    cwe_id="CWE-400",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                business_logic_scanner.add_finding(finding)
                                return

                            if quantity > 99999 and ("success" in text or "order" in text):
                                finding = Finding(
                                    title="Excessive Quantity Accepted",
                                    severity=Severity.MEDIUM,
                                    description=f"Excessive quantity {quantity} was not validated",
                                    url=form["action"],
                                    evidence=f"Quantity: {quantity}",
                                    remediation="Implement quantity limits per order. Validate maximum quantity.",
                                    cwe_id="CWE-400",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                business_logic_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.business_logic
    def test_privilege_escalation(self, business_logic_scanner, target_url, findings_collector):
        """Test for privilege escalation via parameters."""
        resp = business_logic_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        test_paths = ["/account", "/profile", "/admin", "/user"]

        for path in test_paths[:3]:
            url = f"{target_url}{path}"
            resp = business_logic_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms[:2]:
                privilege_params = [
                    ("role", "admin"),
                    ("is_admin", "true"),
                    ("admin", "true"),
                    ("privilege", "admin"),
                    ("user_type", "administrator"),
                ]

                for param_name, param_value in privilege_params:
                    for inp in form["inputs"]:
                        if param_name in inp["name"].lower():
                            form_data = {inp["name"]: param_value}

                            resp = business_logic_scanner.post(form["action"], data=form_data)

                            if resp and resp.status_code == 200:
                                text = resp.text.lower()

                                if param_value.lower() in text or "admin" in text or "dashboard" in text:
                                    finding = Finding(
                                        title="Privilege Escalation via Parameter",
                                        severity=Severity.CRITICAL,
                                        description=f"Privilege escalation via {param_name} parameter to admin",
                                        url=form["action"],
                                        evidence=f"Parameter: {param_name}={param_value}",
                                        remediation="Never accept role or admin status from user input. Use proper authorization checks.",
                                        cwe_id="CWE-269",
                                        owasp_category="A01:2021 - Broken Access Control",
                                    )
                                    findings_collector.add(finding)
                                    business_logic_scanner.add_finding(finding)
                                    return

    @pytest.mark.security
    @pytest.mark.business_logic
    def test_coupon_abuse(self, business_logic_scanner, target_url, findings_collector):
        """Test for coupon abuse and stacking."""
        resp = business_logic_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        cart_forms = []
        for f in forms[:5]:
            for inp in f.get("inputs", []):
                if "coupon" in inp.get("name", "").lower() or "promo" in inp.get("name", "").lower() or "discount" in inp.get("name", "").lower():
                    cart_forms.append(f)
                    break

        for form in cart_forms[:2]:
            coupon_field = None

            for inp in form["inputs"]:
                if "coupon" in inp["name"].lower():
                    coupon_field = inp["name"]
                    break

            if coupon_field:
                stacking_payload = {"coupon": ["SAVE10", "SAVE20"], "quantity": 1}

                resp = business_logic_scanner.post(form["action"], data=stacking_payload)

                if resp and resp.status_code == 200:
                    text = resp.text.lower()

                    success_indicators = ["discount applied", "coupons applied", "success"]
                    for indicator in success_indicators:
                        if indicator in text:
                            finding = Finding(
                                title="Coupon Stacking Vulnerability",
                                severity=Severity.MEDIUM,
                                description="Multiple coupons can be applied to get excessive discount",
                                url=form["action"],
                                evidence="Coupon stacking accepted",
                                remediation="Limit coupons per transaction. Validate coupon combinations server-side.",
                                cwe_id="CWE-400",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            business_logic_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.business_logic
    def test_workflow_bypass(self, business_logic_scanner, target_url, findings_collector):
        """Test for workflow bypass via parameter manipulation."""
        resp = business_logic_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        test_paths = ["/checkout", "/payment", "/confirm", "/complete"]

        for path in test_paths[:3]:
            url = f"{target_url}{path}"
            resp = business_logic_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms[:2]:
                bypass_payloads = [
                    {"step": "4", "current_step": "1"},
                    {"approved": True, "skip_verification": True},
                    {"direct_access": True, "redirect": "payment_complete"},
                ]

                for payload in bypass_payloads:
                    resp = business_logic_scanner.post(form["action"], data=payload)

                    if resp and resp.status_code == 200:
                        text = resp.text.lower()

                        if "success" in text or "completed" in text or "approved" in text:
                            finding = Finding(
                                title="Workflow Bypass - Parameter Manipulation",
                                severity=Severity.HIGH,
                                description="Workflow steps can be skipped via parameters",
                                url=form["action"],
                                evidence=f"Payload: {payload}",
                                remediation="Validate all workflow steps server-side. Use state machines. Don't trust client-side parameters.",
                                cwe_id="CWE-840",
                                owasp_category="A01:2021 - Broken Access Control",
                            )
                            findings_collector.add(finding)
                            business_logic_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.business_logic
    def test_payment_bypass(self, business_logic_scanner, target_url, findings_collector):
        """Test for payment bypass via amount manipulation."""
        resp = business_logic_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        test_paths = ["/pay", "/purchase", "/checkout", "/api/payment"]

        for path in test_paths[:2]:
            url = f"{target_url}{path}"
            resp = business_logic_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms[:2]:
                amount_field = None
                for inp in form["inputs"]:
                    if "amount" in inp["name"].lower():
                        amount_field = inp["name"]
                        break

                if amount_field:
                    bypass_payloads = [
                        {"amount": 0},
                        {"amount": 0.01},
                        {"amount": -100},
                        {"payment": "free"},
                    ]

                    for payload in bypass_payloads:
                        resp = business_logic_scanner.post(form["action"], data=payload)

                        if resp and resp.status_code == 200:
                            text = resp.text.lower()

                            if "success" in text or "completed" in text or "approved" in text:
                                finding = Finding(
                                    title="Payment Bypass - Zero/Negative Amount",
                                    severity=Severity.HIGH,
                                    description="Zero or negative payment amount was accepted",
                                    url=form["action"],
                                    evidence=f"Payment amount: {payload.get('amount', 'N/A')}",
                                    remediation="Validate payment amounts server-side. Reject zero or negative values.",
                                    cwe_id="CWE-400",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                business_logic_scanner.add_finding(finding)
                                return
