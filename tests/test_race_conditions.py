"""
Race Condition Tests

Tests for time-of-check-time-of-use (TOCTOU) and race condition attacks including:
- Concurrent request attacks
- Resource competition
- State manipulation
"""

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from utils.scanner import SecurityScanner, Finding, Severity, extract_forms


@pytest.fixture
def race_scanner(test_config):
    """Create scanner for race condition tests."""
    return SecurityScanner(test_config)


class TestRaceConditions:
    """Race condition test suite."""

    def _send_concurrent_requests(self, scanner, url, form_data, num_threads=5):
        """Send multiple concurrent requests and collect results."""
        results = []
        errors = []

        def make_request():
            try:
                resp = scanner.post(url, data=form_data)
                if resp:
                    return {"status": resp.status_code, "text": resp.text.lower()[:500]}
            except Exception as e:
                return {"error": str(e)}
            return None

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(make_request) for _ in range(num_threads)]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    if "error" in result:
                        errors.append(result)
                    else:
                        results.append(result)

        return results, errors

    def _check_race_success(self, results, success_indicator):
        """Check if race condition was successful (multiple successes)."""
        success_count = 0
        for result in results:
            text = result.get("text", "")
            if success_indicator in text:
                success_count += 1
        return success_count

    @pytest.mark.security
    @pytest.mark.race_conditions
    def test_coupon_reuse_race(self, race_scanner, target_url, findings_collector):
        """Test for coupon reuse race condition."""
        resp = race_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)

        for form in forms[:2]:
            for inp in form["inputs"]:
                if "coupon" in inp["name"].lower():
                    form_data = {inp["name"]: "SAVE20", "quantity": 1}

                    # Send concurrent requests
                    results, _ = self._send_concurrent_requests(
                        race_scanner, form["action"], form_data, num_threads=5
                    )

                    # Check if coupon was applied multiple times
                    success_count = self._check_race_success(results, "applied")
                    if success_count > 1:
                        finding = Finding(
                            title="Coupon Reuse Race Condition",
                            severity=Severity.MEDIUM,
                            description=f"Coupon applied {success_count} times in concurrent requests",
                            url=form["action"],
                            evidence=f"Coupon 'SAVE20' accepted {success_count} times concurrently",
                            remediation="Implement one-time use coupon tracking with database transactions and row locking.",
                            cwe_id="CWE-362",
                            owasp_category="A01:2021 - Broken Access Control",
                        )
                        findings_collector.add(finding)
                        race_scanner.add_finding(finding)
                        return

    @pytest.mark.security
    @pytest.mark.race_conditions
    def test_coupon_stacking(self, race_scanner, target_url, findings_collector):
        """Test for coupon stacking attack."""
        resp = race_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)

        for form in forms[:2]:
            for inp in form["inputs"]:
                if "coupon" in inp["name"].lower():
                    form_data = {"coupons": ["SAVE10", "SAVE20", "SAVE30"], "quantity": 1}

                    resp = race_scanner.post(form["action"], data=form_data)

                    if resp and resp.status_code == 200:
                        text = resp.text.lower()
                        success_indicators = ["total discount", "applied", "success"]

                        for indicator in success_indicators:
                            if indicator in text:
                                finding = Finding(
                                    title="Coupon Stacking Vulnerability",
                                    severity=Severity.MEDIUM,
                                    description="Multiple coupons can be applied in a single transaction",
                                    url=form["action"],
                                    evidence=f"Coupon stacking response: {text[:200]}",
                                    remediation="Limit number of coupons per transaction. Validate coupon combinations server-side.",
                                    cwe_id="CWE-400",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                race_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.race_conditions
    def test_double_withdrawal_race(self, race_scanner, target_url, findings_collector):
        """Test for double withdrawal race condition."""
        test_paths = ["/withdraw", "/transfer", "/payment"]

        for path in test_paths:
            url = f"{target_url}{path}"
            resp = race_scanner.get(url)

            if resp and resp.status_code == 200:
                forms = extract_forms(resp.text, url)

                for form in forms[:2]:
                    for inp in form["inputs"]:
                        if "amount" in inp["name"].lower() or "withdraw" in inp["name"].lower():
                            form_data = {inp["name"]: 100}

                            # Send concurrent withdrawal requests
                            results, _ = self._send_concurrent_requests(
                                race_scanner, form["action"], form_data, num_threads=5
                            )

                            success_count = self._check_race_success(results, "success")
                            if success_count > 1:
                                finding = Finding(
                                    title="Double Withdrawal Race Condition",
                                    severity=Severity.HIGH,
                                    description=f"Withdrawal processed {success_count} times concurrently",
                                    url=form["action"],
                                    evidence=f"Multiple 100 withdrawal requests succeeded: {success_count}",
                                    remediation="Use database transactions and row locking. Implement idempotency keys.",
                                    cwe_id="CWE-362",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                race_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.race_conditions
    def test_negative_balance_race(self, race_scanner, target_url, findings_collector):
        """Test for negative balance manipulation."""
        test_paths = ["/account", "/profile", "/wallet"]

        for path in test_paths:
            url = f"{target_url}{path}"
            resp = race_scanner.get(url)

            if resp and resp.status_code == 200:
                forms = extract_forms(resp.text, url)

                for form in forms[:2]:
                    for inp in form["inputs"]:
                        if "balance" in inp["name"].lower() or "amount" in inp["name"].lower():
                            form_data = {inp["name"]: -100}

                            resp = race_scanner.post(form["action"], data=form_data)

                            if resp and resp.status_code == 200:
                                text = resp.text.lower()

                                if "success" in text or "updated" in text:
                                    finding = Finding(
                                        title="Negative Balance Manipulation",
                                        severity=Severity.HIGH,
                                        description="Negative balance/amount accepted by server",
                                        url=form["action"],
                                        evidence="Negative value -100 accepted",
                                        remediation="Validate all numeric inputs server-side. Use absolute values and reject negative numbers.",
                                        cwe_id="CWE-400",
                                        owasp_category="A01:2021 - Broken Access Control",
                                    )
                                    findings_collector.add(finding)
                                    race_scanner.add_finding(finding)
                                    return

    @pytest.mark.security
    @pytest.mark.race_conditions
    def test_password_reset_token_reuse(self, race_scanner, target_url, findings_collector):
        """Test for password reset token reuse via race condition."""
        reset_paths = ["/forgot-password", "/password/reset", "/reset-password"]

        for path in reset_paths:
            url = f"{target_url}{path}"
            resp = race_scanner.get(url)

            if not resp or resp.status_code != 200:
                continue

            forms = extract_forms(resp.text, url)

            for form in forms[:2]:
                for inp in form["inputs"]:
                    if "email" in inp["name"].lower():
                        form_data = {inp["name"]: "test@example.com"}

                        # Send concurrent reset requests
                        results, _ = self._send_concurrent_requests(
                            race_scanner, form["action"], form_data, num_threads=3
                        )

                        # Check if multiple tokens were generated
                        sent_count = self._check_race_success(results, "sent")
                        if sent_count > 1:
                            finding = Finding(
                                title="Password Reset Token Race",
                                severity=Severity.MEDIUM,
                                description=f"Multiple reset tokens generated: {sent_count}",
                                url=form["action"],
                                evidence="Concurrent password reset requests accepted",
                                remediation="Invalidate previous tokens when generating new ones. Use rate limiting.",
                                cwe_id="CWE-287",
                                owasp_category="A07:2021 - Identification and Authentication Failures",
                            )
                            findings_collector.add(finding)
                            race_scanner.add_finding(finding)
                            return

    @pytest.mark.security
    @pytest.mark.race_conditions
    def test_price_race_condition(self, race_scanner, target_url, findings_collector):
        """Test for price manipulation via race."""
        test_paths = ["/cart", "/checkout", "/purchase", "/buy"]

        for path in test_paths:
            url = f"{target_url}{path}"
            resp = race_scanner.get(url)

            if resp and resp.status_code == 200:
                forms = extract_forms(resp.text, url)

                for form in forms[:2]:
                    for inp in form["inputs"]:
                        if "price" in inp["name"].lower():
                            price_payloads = [0, -100, 1e10, 999999999]

                            for price in price_payloads:
                                form_data = {inp["name"]: price, "quantity": 1}

                                resp = race_scanner.post(form["action"], data=form_data)

                                if resp and resp.status_code in [200, 201]:
                                    text = resp.text.lower()

                                    if "success" in text or "order" in text or "added" in text:
                                        finding = Finding(
                                            title="Price Manipulation Vulnerability",
                                            severity=Severity.HIGH,
                                            description=f"Invalid price {price} accepted by server",
                                            url=form["action"],
                                            evidence=f"Price {price} resulted in successful response",
                                            remediation="Validate all prices server-side. Use server-side price lookups.",
                                            cwe_id="CWE-400",
                                            owasp_category="A01:2021 - Broken Access Control",
                                        )
                                        findings_collector.add(finding)
                                        race_scanner.add_finding(finding)
                                        return

    @pytest.mark.security
    @pytest.mark.race_conditions
    def test_concurrent_booking(self, race_scanner, target_url, findings_collector):
        """Test for resource booking race condition."""
        test_paths = ["/book", "/reserve", "/schedule", "/appointment"]

        for path in test_paths:
            url = f"{target_url}{path}"
            resp = race_scanner.get(url)

            if resp and resp.status_code == 200:
                forms = extract_forms(resp.text, url)

                for form in forms[:2]:
                    for inp in form["inputs"]:
                        if "quantity" in inp["name"].lower() or "book" in inp["name"].lower() or "seats" in inp["name"].lower():
                            form_data = {inp["name"]: 1, "resource_id": "limited_item"}

                            # Send concurrent booking requests
                            results, _ = self._send_concurrent_requests(
                                race_scanner, form["action"], form_data, num_threads=5
                            )

                            success_count = self._check_race_success(results, "booked")
                            alt_count = self._check_race_success(results, "reserved")
                            total_success = success_count + alt_count

                            if total_success > 1:
                                finding = Finding(
                                    title="Resource Booking Race Condition",
                                    severity=Severity.MEDIUM,
                                    description=f"Limited resource booked {total_success} times concurrently",
                                    url=form["action"],
                                    evidence=f"Concurrent booking succeeded {total_success} times",
                                    remediation="Implement inventory checks with database transactions. Use optimistic locking.",
                                    cwe_id="CWE-362",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                race_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.race_conditions
    def test_vote_stacking(self, race_scanner, target_url, findings_collector):
        """Test for vote stacking race condition."""
        test_paths = ["/vote", "/poll", "/like", "/rating"]

        for path in test_paths:
            url = f"{target_url}{path}"
            resp = race_scanner.get(url)

            if resp and resp.status_code == 200:
                forms = extract_forms(resp.text, url)

                for form in forms[:2]:
                    for inp in form["inputs"]:
                        if "vote" in inp["name"].lower() or "like" in inp["name"].lower():
                            form_data = {inp["name"]: "1", "item_id": "test_item"}

                            # Send concurrent vote requests
                            results, _ = self._send_concurrent_requests(
                                race_scanner, form["action"], form_data, num_threads=5
                            )

                            success_count = self._check_race_success(results, "voted")
                            alt_count = self._check_race_success(results, "recorded")
                            total_success = success_count + alt_count

                            if total_success > 1:
                                finding = Finding(
                                    title="Vote Stacking Race Condition",
                                    severity=Severity.MEDIUM,
                                    description=f"Vote recorded {total_success} times concurrently",
                                    url=form["action"],
                                    evidence=f"Vote parameter accepted {total_success} times",
                                    remediation="Implement vote deduplication with unique constraints. Use rate limiting.",
                                    cwe_id="CWE-362",
                                    owasp_category="A05:2021 - Security Misconfiguration",
                                )
                                findings_collector.add(finding)
                                race_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.race_conditions
    def test_id_creation_race(self, race_scanner, target_url, findings_collector):
        """Test for ID predictability race condition."""
        test_paths = ["/register", "/signup", "/create-account", "/create-order"]

        for path in test_paths[:2]:
            url = f"{target_url}{path}"
            resp = race_scanner.get(url)

            if resp and resp.status_code == 200:
                forms = extract_forms(resp.text, url)

                for form in forms[:1]:
                    # Build form data from available inputs
                    form_data = {}
                    for inp in form.get("inputs", []):
                        if inp.get("name"):
                            form_data[inp["name"]] = f"test_{int(time.time())}"

                    if not form_data:
                        continue

                    ids = []
                    for i in range(5):
                        create_resp = race_scanner.post(form["action"], data=form_data)

                        if create_resp and create_resp.status_code == 200:
                            text = create_resp.text
                            id_pattern = r'ID[:\s]*(\d+)'
                            matches = re.search(id_pattern, text, re.IGNORECASE)

                            if matches:
                                ids.append(matches.group(1))

                    if len(ids) >= 3:
                        try:
                            id_nums = [int(id_val) for id_val in ids]
                            if max(id_nums) - min(id_nums) <= 10:
                                finding = Finding(
                                    title="Predictable ID Generation",
                                    severity=Severity.MEDIUM,
                                    description="Sequential or predictable IDs can be guessed",
                                    url=form["action"],
                                    evidence=f"IDs: {ids[:5]}",
                                    remediation="Use UUID or random IDs with sufficient entropy. Don't use sequential patterns.",
                                    cwe_id="CWE-338",
                                    owasp_category="A02:2021 - Cryptographic Failures",
                                )
                                findings_collector.add(finding)
                                race_scanner.add_finding(finding)
                                return
                        except ValueError:
                            pass

    @pytest.mark.security
    @pytest.mark.race_conditions
    def test_otp_race_condition(self, race_scanner, target_url, findings_collector):
        """Test for OTP/2FA race condition."""
        otp_paths = ["/verify-otp", "/2fa/verify", "/mfa/check"]

        for path in otp_paths:
            url = f"{target_url}{path}"
            resp = race_scanner.get(url)

            if resp and resp.status_code == 200:
                forms = extract_forms(resp.text, url)

                for form in forms[:1]:
                    for inp in form["inputs"]:
                        if "otp" in inp["name"].lower() or "code" in inp["name"].lower():
                            # Try multiple OTP guesses concurrently
                            otp_guesses = ["000000", "123456", "111111", "999999", "000001"]

                            results = []
                            for otp in otp_guesses:
                                form_data = {inp["name"]: otp}
                                resp = race_scanner.post(form["action"], data=form_data)
                                if resp:
                                    results.append(resp.text.lower())

                            # Check if any succeeded or if rate limiting is missing
                            success_found = any("success" in r or "verified" in r for r in results)
                            rate_limit_found = any("too many" in r or "rate limit" in r or "blocked" in r for r in results)

                            if not rate_limit_found and len(results) >= 3:
                                finding = Finding(
                                    title="OTP Rate Limiting Missing",
                                    severity=Severity.MEDIUM,
                                    description="Multiple OTP attempts allowed without rate limiting",
                                    url=form["action"],
                                    evidence=f"Submitted {len(results)} OTP attempts without blocking",
                                    remediation="Implement rate limiting on OTP verification. Lock account after N failed attempts.",
                                    cwe_id="CWE-307",
                                    owasp_category="A07:2021 - Identification and Authentication Failures",
                                )
                                findings_collector.add(finding)
                                race_scanner.add_finding(finding)
                                return
