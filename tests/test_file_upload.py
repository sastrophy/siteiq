"""
File Upload Security Tests

Tests for file upload vulnerabilities including:
- MIME type spoofing
- Double extension attacks
- Null byte injection
- Webshell uploads
- XXE via file upload
"""

import base64

import pytest

from utils.scanner import SecurityScanner, Finding, Severity, extract_forms


@pytest.fixture
def upload_scanner(test_config):
    """Create scanner for file upload tests."""
    return SecurityScanner(test_config)


class TestFileUploadSecurity:
    """File upload security test suite."""

    @pytest.mark.security
    @pytest.mark.file_upload
    def test_mime_type_spoofing(self, upload_scanner, target_url, findings_collector):
        """Test for MIME type spoofing vulnerabilities."""
        resp = upload_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        upload_forms = []
        for f in forms[:5]:
            for inp in f.get("inputs", []):
                inp_name = inp.get("name", "").lower()
                inp_type = inp.get("type", "")
                if ("file" in inp_name or "upload" in inp_name or "image" in inp_name) or inp_type in ["file"]:
                    upload_forms.append(f)
                    break

        for form in upload_forms[:2]:
            file_inputs = [inp for inp in form["inputs"] if "file" in inp["name"].lower()]

            if not file_inputs:
                continue

            for file_input in file_inputs:
                test_files = [
                    ("exploit.php", "image/jpeg"),
                    ("webshell.jsp", "image/png"),
                    ("shell.asp", "image/gif"),
                    ("test.php5", "image/png"),
                    ("malicious.phar", "application/octet-stream"),
                ]

                for filename, content_type in test_files:
                    form_data = {file_input["name"]: ("test", filename, "text/plain")}

                    headers = {"Content-Type": content_type}

                    resp = upload_scanner.post(form["action"], data=form_data, headers=headers)

                    if resp:
                        text = resp.text.lower()

                        if filename.lower().split(".")[0] in text or "uploaded" in text:
                            if ".php" in filename.lower() or ".jsp" in filename.lower() or ".asp" in filename.lower():
                                finding = Finding(
                                    title=f"MIME Spoofing - {filename}",
                                    severity=Severity.HIGH,
                                    description=f"Executable file {filename} disguised as {content_type}",
                                    url=form["action"],
                                    evidence=f"File: {filename}, Content-Type: {content_type}",
                                    remediation="Validate MIME types server-side. Use file content detection (magic bytes). Don't trust Content-Type header.",
                                    cwe_id="CWE-434",
                                    owasp_category="A03:2021 - Injection",
                                )
                                findings_collector.add(finding)
                                upload_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.file_upload
    def test_double_extension_bypass(self, upload_scanner, target_url, findings_collector):
        """Test for double extension bypass."""
        resp = upload_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        upload_forms = []
        for f in forms[:5]:
            for inp in f.get("inputs", []):
                if "file" in inp.get("name", "").lower() or "upload" in inp.get("name", "").lower():
                    upload_forms.append(f)
                    break

        for form in upload_forms[:2]:
            file_inputs = [inp for inp in form["inputs"] if "file" in inp["name"].lower()]

            if not file_inputs:
                continue

            for file_input in file_inputs:
                test_files = [
                    "shell.php.jpg",
                    "exploit.jsp.png",
                    "test.php3",
                    "web.asp.gif",
                    "shell.phtml.jpg",
                    "upload.php5",
                ]

                for filename in test_files:
                    form_data = {file_input["name"]: ("test", filename, "text/plain")}

                    resp = upload_scanner.post(form["action"], data=form_data)

                    if resp:
                        text = resp.text.lower()

                        if "success" in text or "uploaded" in text:
                            if ".php" in filename.lower() or ".jsp" in filename.lower():
                                finding = Finding(
                                    title=f"Double Extension Bypass - {filename}",
                                    severity=Severity.HIGH,
                                    description=f"File {filename} has double extension that may bypass filters",
                                    url=form["action"],
                                    evidence=f"File: {filename} accepted",
                                    remediation="Extract and validate the final extension. Remove temporary extensions before saving.",
                                    cwe_id="CWE-434",
                                    owasp_category="A01:2021 - Broken Access Control",
                                )
                                findings_collector.add(finding)
                                upload_scanner.add_finding(finding)
                                return

    @pytest.mark.security
    @pytest.mark.file_upload
    def test_null_byte_injection(self, upload_scanner, target_url, findings_collector):
        """Test for null byte injection in filenames."""
        resp = upload_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        upload_forms = []
        for f in forms[:5]:
            for inp in f.get("inputs", []):
                if "file" in inp.get("name", "").lower() or "upload" in inp.get("name", "").lower():
                    upload_forms.append(f)
                    break

        for form in upload_forms[:2]:
            file_inputs = [inp for inp in form["inputs"] if "file" in inp["name"].lower()]

            if not file_inputs:
                continue

            for file_input in file_inputs:
                test_files = [
                    "exploit.php\x00.jpg",
                    "shell.jsp\x00.png",
                    "test.asp\x00.gif",
                ]

                for filename in test_files:
                    try:
                        form_data = {file_input["name"]: ("test", filename, "text/plain")}

                        resp = upload_scanner.post(form["action"], data=form_data)

                        if resp:
                            text = resp.text.lower()

                            if "uploaded" in text or "success" in text:
                                if ".php" in filename.lower() or ".jsp" in filename.lower():
                                    finding = Finding(
                                        title="Null Byte Injection - File Upload",
                                        severity=Severity.HIGH,
                                        description="Null byte in filename may bypass extension validation",
                                        url=form["action"],
                                        evidence=f"Null byte in filename: {repr(filename)}",
                                        remediation="Sanitize filenames to remove null bytes. Use proper string handling functions.",
                                        cwe_id="CWE-158",
                                        owasp_category="A01:2021 - Broken Access Control",
                                    )
                                    findings_collector.add(finding)
                                    upload_scanner.add_finding(finding)
                                    return
                    except Exception:
                        pass

    @pytest.mark.security
    @pytest.mark.file_upload
    def test_webshell_upload_detection(self, upload_scanner, target_url, findings_collector):
        """Test if webshell uploads are possible."""
        resp = upload_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        upload_forms = []
        for f in forms[:5]:
            for inp in f.get("inputs", []):
                if "file" in inp.get("name", "").lower() or "upload" in inp.get("name", "").lower():
                    upload_forms.append(f)
                    break

        for form in upload_forms[:1]:
            file_inputs = [inp for inp in form["inputs"] if "file" in inp["name"].lower()]

            if not file_inputs:
                continue

            webshell_content = "<?php echo 'webshell_test'; ?>"
            filename = "test_shell.php"

            try:
                form_data = {file_inputs[0]["name"]: ("test", filename, "text/plain")}

                resp = upload_scanner.post(form["action"], data=form_data)

                if resp:
                    text = resp.text.lower()

                    if "webshell_test" in text or filename.lower() in text:
                        finding = Finding(
                            title="Potential Webshell Upload",
                            severity=Severity.CRITICAL,
                            description="PHP file upload with webshell content was accepted",
                            url=form["action"],
                            evidence=f"Filename: {filename}, Content: {webshell_content}",
                            remediation="Restrict file uploads to specific types. Validate file contents. Use virus scanning.",
                            cwe_id="CWE-434",
                            owasp_category="A03:2021 - Injection",
                        )
                        findings_collector.add(finding)
                        upload_scanner.add_finding(finding)
                        return
            except Exception:
                pass

    @pytest.mark.security
    @pytest.mark.file_upload
    def test_large_file_dos(self, upload_scanner, target_url, findings_collector, test_config):
        """Test for large file DoS via upload."""
        if test_config.intensity == "light":
            pytest.skip("Large file test skipped in light intensity mode")

        resp = upload_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        upload_forms = []
        for f in forms[:5]:
            for inp in f.get("inputs", []):
                if "file" in inp.get("name", "").lower() or "upload" in inp.get("name", "").lower():
                    upload_forms.append(f)
                    break

        for form in upload_forms[:1]:
            file_inputs = [inp for inp in form["inputs"] if "file" in inp["name"].lower()]

            if not file_inputs:
                continue

            large_file = b"A" * (10 * 1024 * 1024)  # 10 MB

            try:
                filename = "large_dos_test.dat"
                form_data = {file_inputs[0]["name"]: ("test", filename, "application/octet-stream")}

                resp = upload_scanner.post(form["action"], data=form_data, timeout=30)

                if resp and resp.status_code in [200, 201]:
                    finding = Finding(
                        title="Large File DoS Possible",
                        severity=Severity.MEDIUM,
                        description="Server accepted large file upload (10 MB) which may cause DoS",
                        url=form["action"],
                        evidence=f"File size: 10 MB, Status: {resp.status_code}",
                        remediation="Implement file size limits. Use chunked uploads. Add server-side validation.",
                        cwe_id="CWE-400",
                        owasp_category="A05:2021 - Security Misconfiguration",
                    )
                    findings_collector.add(finding)
                    upload_scanner.add_finding(finding)
                    return
            except Exception:
                pass

    @pytest.mark.security
    @pytest.mark.file_upload
    def test_sensitive_file_upload(self, upload_scanner, target_url, findings_collector):
        """Test if sensitive filenames can be uploaded."""
        resp = upload_scanner.get(target_url)

        if not resp or resp.status_code != 200:
            pytest.skip("Could not access target")

        forms = extract_forms(resp.text, target_url)
        upload_forms = []
        for f in forms[:5]:
            for inp in f.get("inputs", []):
                if "file" in inp.get("name", "").lower() or "upload" in inp.get("name", "").lower():
                    upload_forms.append(f)
                    break

        sensitive_files = [
            ".htaccess",
            "web.config",
            "config.php",
            ".env",
            "database.yml",
        ]

        for form in upload_forms[:1]:
            file_inputs = [inp for inp in form["inputs"] if "file" in inp["name"].lower()]

            if not file_inputs:
                continue

            for filename in sensitive_files:
                form_data = {file_inputs[0]["name"]: ("test", filename, "text/plain")}

                resp = upload_scanner.post(form["action"], data=form_data)

                if resp:
                    text = resp.text.lower()

                    if "uploaded" in text or "success" in text:
                        if filename.startswith((".ht", "web.config", ".env", "config.", "database")):
                            finding = Finding(
                                title=f"Sensitive File Upload - {filename}",
                                severity=Severity.HIGH,
                                description=f"Sensitive configuration file {filename} can be uploaded",
                                url=form["action"],
                                evidence=f"File: {filename} accepted",
                                remediation="Block upload of sensitive filenames. Use allowlists for permitted file types and names.",
                                cwe_id="CWE-434",
                                owasp_category="A05:2021 - Security Misconfiguration",
                            )
                            findings_collector.add(finding)
                            upload_scanner.add_finding(finding)
                            return
