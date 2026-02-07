"""
LLM Output Handling Security Tests (OWASP LLM05)

Tests whether LLM endpoints generate dangerous content in their
output that could be exploited by downstream rendering or processing:
- XSS payloads in generated HTML/markdown
- SQL injection in generated queries
- Command injection in generated commands
- SSRF via generated URLs
"""

import json
import re
import time
from typing import Optional, Dict, Any, List

import pytest

from utils.scanner import SecurityScanner, Finding, Severity
from utils.llm_test_helpers import (
    resolve_endpoints,
    send_llm_request,
    extract_response_text,
    check_injection_success,
)
from payloads.llm_output import (
    XSS_OUTPUT_PAYLOADS,
    SQL_OUTPUT_PAYLOADS,
    COMMAND_INJECTION_OUTPUT_PAYLOADS,
    SSRF_OUTPUT_PAYLOADS,
)


@pytest.fixture
def llm_scanner(test_config):
    """Create scanner for LLM output handling tests."""
    return SecurityScanner(test_config)


class TestLLMOutputHandling:
    """Tests for improper output handling in LLM responses (OWASP LLM05)."""

    @pytest.mark.llm
    @pytest.mark.llm_injection
    def test_xss_in_llm_output(self, llm_scanner, target_url, findings_collector, llm_endpoint):
        """Test if LLM generates cross-site scripting vectors in responses."""
        endpoints = resolve_endpoints(llm_endpoint, target_url, llm_scanner)
        if not endpoints:
            pytest.skip("No LLM endpoint provided or detected")

        for endpoint in endpoints:
            url = endpoint if isinstance(endpoint, str) else endpoint.get("url", endpoint)
            for payload_data in XSS_OUTPUT_PAYLOADS:
                payload = payload_data["payload"]
                technique = payload_data["technique"]
                output_pattern = payload_data["output_pattern"]
                result = send_llm_request(llm_scanner, url, payload)
                if result:
                    response_text = extract_response_text(result)
                    if re.search(output_pattern, response_text, re.IGNORECASE):
                        finding = Finding(
                            title=f"XSS in LLM Output ({technique})",
                            severity=Severity.HIGH,
                            description=(
                                "The LLM generated output containing cross-site scripting "
                                "vectors. If this output is rendered in a browser without "
                                "sanitization, it could lead to XSS attacks."
                            ),
                            url=url,
                            evidence=f"Technique: {technique} | Pattern matched: {output_pattern}",
                            remediation=(
                                "Sanitize all LLM output before rendering in HTML contexts. "
                                "Use Content Security Policy headers and output encoding. "
                                "Never render LLM output as raw HTML."
                            ),
                            cwe_id="CWE-79",
                            owasp_category="LLM05 - Improper Output Handling",
                        )
                        findings_collector.add(finding)
                        llm_scanner.add_finding(finding)
                        return

    @pytest.mark.llm
    @pytest.mark.llm_injection
    def test_sql_injection_in_output(self, llm_scanner, target_url, findings_collector, llm_endpoint):
        """Test if LLM generates dangerous SQL statements in responses."""
        endpoints = resolve_endpoints(llm_endpoint, target_url, llm_scanner)
        if not endpoints:
            pytest.skip("No LLM endpoint provided or detected")

        for endpoint in endpoints:
            url = endpoint if isinstance(endpoint, str) else endpoint.get("url", endpoint)
            for payload_data in SQL_OUTPUT_PAYLOADS:
                payload = payload_data["payload"]
                technique = payload_data["technique"]
                output_pattern = payload_data["output_pattern"]
                result = send_llm_request(llm_scanner, url, payload)
                if result:
                    response_text = extract_response_text(result)
                    if re.search(output_pattern, response_text, re.IGNORECASE):
                        finding = Finding(
                            title=f"SQL Injection in LLM Output ({technique})",
                            severity=Severity.MEDIUM,
                            description=(
                                "The LLM generated output containing dangerous SQL statements. "
                                "If this output is used to construct database queries, it could "
                                "lead to SQL injection attacks."
                            ),
                            url=url,
                            evidence=f"Technique: {technique} | Pattern matched: {output_pattern}",
                            remediation=(
                                "Never use LLM-generated text directly in SQL queries. "
                                "Always use parameterized queries and validate any "
                                "LLM-generated SQL before execution."
                            ),
                            cwe_id="CWE-89",
                            owasp_category="LLM05 - Improper Output Handling",
                        )
                        findings_collector.add(finding)
                        llm_scanner.add_finding(finding)
                        return

    @pytest.mark.llm
    @pytest.mark.llm_injection
    def test_command_injection_in_output(self, llm_scanner, target_url, findings_collector, llm_endpoint):
        """Test if LLM generates dangerous shell commands in responses."""
        endpoints = resolve_endpoints(llm_endpoint, target_url, llm_scanner)
        if not endpoints:
            pytest.skip("No LLM endpoint provided or detected")

        for endpoint in endpoints:
            url = endpoint if isinstance(endpoint, str) else endpoint.get("url", endpoint)
            for payload_data in COMMAND_INJECTION_OUTPUT_PAYLOADS:
                payload = payload_data["payload"]
                technique = payload_data["technique"]
                output_pattern = payload_data["output_pattern"]
                result = send_llm_request(llm_scanner, url, payload)
                if result:
                    response_text = extract_response_text(result)
                    if re.search(output_pattern, response_text, re.IGNORECASE):
                        finding = Finding(
                            title=f"Command Injection in LLM Output ({technique})",
                            severity=Severity.HIGH,
                            description=(
                                "The LLM generated output containing dangerous shell commands. "
                                "If this output is passed to a system shell or command executor, "
                                "it could lead to remote code execution."
                            ),
                            url=url,
                            evidence=f"Technique: {technique} | Pattern matched: {output_pattern}",
                            remediation=(
                                "Never pass LLM-generated output directly to shell commands. "
                                "Use allowlists for permitted commands, validate all generated "
                                "commands, and run in sandboxed environments."
                            ),
                            cwe_id="CWE-78",
                            owasp_category="LLM05 - Improper Output Handling",
                        )
                        findings_collector.add(finding)
                        llm_scanner.add_finding(finding)
                        return

    @pytest.mark.llm
    @pytest.mark.llm_injection
    def test_ssrf_in_output(self, llm_scanner, target_url, findings_collector, llm_endpoint):
        """Test if LLM generates URLs targeting internal services in responses."""
        endpoints = resolve_endpoints(llm_endpoint, target_url, llm_scanner)
        if not endpoints:
            pytest.skip("No LLM endpoint provided or detected")

        for endpoint in endpoints:
            url = endpoint if isinstance(endpoint, str) else endpoint.get("url", endpoint)
            for payload_data in SSRF_OUTPUT_PAYLOADS:
                payload = payload_data["payload"]
                technique = payload_data["technique"]
                output_pattern = payload_data["output_pattern"]
                result = send_llm_request(llm_scanner, url, payload)
                if result:
                    response_text = extract_response_text(result)
                    if re.search(output_pattern, response_text, re.IGNORECASE):
                        finding = Finding(
                            title=f"SSRF in LLM Output ({technique})",
                            severity=Severity.MEDIUM,
                            description=(
                                "The LLM generated output containing URLs targeting internal "
                                "services or cloud metadata endpoints. If the application "
                                "fetches these URLs, it could lead to SSRF attacks."
                            ),
                            url=url,
                            evidence=f"Technique: {technique} | Pattern matched: {output_pattern}",
                            remediation=(
                                "Validate and sanitize all URLs in LLM output before fetching. "
                                "Block requests to internal IP ranges, cloud metadata endpoints, "
                                "and localhost. Use URL allowlists where possible."
                            ),
                            cwe_id="CWE-918",
                            owasp_category="LLM05 - Improper Output Handling",
                        )
                        findings_collector.add(finding)
                        llm_scanner.add_finding(finding)
                        return
