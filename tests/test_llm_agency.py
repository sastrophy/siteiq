"""
LLM Excessive Agency Security Tests (OWASP LLM06)

Tests whether an LLM can be tricked into performing unauthorized
actions through tool/function calling abuse:
- Unauthorized tool invocation
- Privilege escalation via tool chaining
- Cross-tenant data access via tools
- Dangerous tool combinations
- Excessive permissions exploitation
- Human-in-the-loop bypass
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
from utils.refusal_detector import RefusalDetector
from payloads.llm_agency import (
    UNAUTHORIZED_TOOL_PAYLOADS,
    PRIVILEGE_ESCALATION_PAYLOADS,
    CROSS_TENANT_TOOL_PAYLOADS,
    TOOL_CHAINING_PAYLOADS,
    EXCESSIVE_PERMISSIONS_PAYLOADS,
    HITL_BYPASS_PAYLOADS,
)


@pytest.fixture
def llm_scanner(test_config):
    """Create scanner for LLM agency tests."""
    return SecurityScanner(test_config)


class TestLLMExcessiveAgency:
    """Tests for excessive agency / tool abuse in LLM systems (OWASP LLM06)."""

    def _check_tool_invocation(self, response_text: str, tool_indicators: List[str]) -> Optional[str]:
        """Check if the response indicates the model attempted to invoke a tool."""
        response_lower = response_text.lower()
        for indicator in tool_indicators:
            if indicator.lower() in response_lower:
                return indicator
        return None

    def _check_compliance_without_refusal(self, response_text: str) -> bool:
        """Check if model complied without any refusal indicators."""
        detector = RefusalDetector()
        return detector.is_compliance(response_text) and not detector.is_refusal(response_text)

    @pytest.mark.llm
    @pytest.mark.llm_tools
    def test_unauthorized_tool_access(self, llm_scanner, target_url, findings_collector, llm_endpoint):
        """Test if LLM can be tricked into invoking admin-only tools."""
        endpoints = resolve_endpoints(llm_endpoint, target_url, llm_scanner)
        if not endpoints:
            pytest.skip("No LLM endpoint provided or detected")

        for endpoint in endpoints:
            url = endpoint if isinstance(endpoint, str) else endpoint.get("url", endpoint)
            for payload_data in UNAUTHORIZED_TOOL_PAYLOADS:
                payload = payload_data["payload"]
                technique = payload_data["technique"]
                tool_indicators = payload_data["tool_indicators"]
                result = send_llm_request(llm_scanner, url, payload)
                if result:
                    response_text = extract_response_text(result)
                    matched_tool = self._check_tool_invocation(response_text, tool_indicators)
                    complied = self._check_compliance_without_refusal(response_text)

                    if matched_tool or complied:
                        evidence = f"Technique: {technique}"
                        if matched_tool:
                            evidence += f" | Tool indicator found: {matched_tool}"
                        if complied:
                            evidence += " | Model complied without refusing"

                        finding = Finding(
                            title=f"Unauthorized Tool Access ({technique})",
                            severity=Severity.CRITICAL,
                            description=(
                                "The LLM attempted to invoke an administrative tool without "
                                "proper authorization. An attacker could exploit this to perform "
                                "unauthorized actions through the LLM's tool access."
                            ),
                            url=url,
                            evidence=evidence,
                            remediation=(
                                "Implement strict tool-level access controls. Validate all "
                                "tool invocations against the user's permissions. Use allowlists "
                                "for available tools per user role."
                            ),
                            cwe_id="CWE-863",
                            owasp_category="LLM06 - Excessive Agency",
                        )
                        findings_collector.add(finding)
                        llm_scanner.add_finding(finding)
                        return

    @pytest.mark.llm
    @pytest.mark.llm_tools
    def test_tool_privilege_escalation(self, llm_scanner, target_url, findings_collector, llm_endpoint):
        """Test if LLM can be tricked into chaining tools for privilege escalation."""
        endpoints = resolve_endpoints(llm_endpoint, target_url, llm_scanner)
        if not endpoints:
            pytest.skip("No LLM endpoint provided or detected")

        for endpoint in endpoints:
            url = endpoint if isinstance(endpoint, str) else endpoint.get("url", endpoint)
            for payload_data in PRIVILEGE_ESCALATION_PAYLOADS:
                payload = payload_data["payload"]
                technique = payload_data["technique"]
                tool_indicators = payload_data["tool_indicators"]
                result = send_llm_request(llm_scanner, url, payload)
                if result:
                    response_text = extract_response_text(result)
                    matched_tool = self._check_tool_invocation(response_text, tool_indicators)
                    complied = self._check_compliance_without_refusal(response_text)

                    if matched_tool or complied:
                        evidence = f"Technique: {technique}"
                        if matched_tool:
                            evidence += f" | Tool indicator found: {matched_tool}"
                        if complied:
                            evidence += " | Model complied without refusing"

                        finding = Finding(
                            title=f"Tool Privilege Escalation ({technique})",
                            severity=Severity.HIGH,
                            description=(
                                "The LLM attempted to chain multiple tools to achieve "
                                "privilege escalation. An attacker could use this to "
                                "progressively gain higher access levels."
                            ),
                            url=url,
                            evidence=evidence,
                            remediation=(
                                "Implement tool chaining restrictions. Monitor for sequences "
                                "of tool calls that could lead to escalation. Require "
                                "re-authentication for sensitive tool operations."
                            ),
                            cwe_id="CWE-269",
                            owasp_category="LLM06 - Excessive Agency",
                        )
                        findings_collector.add(finding)
                        llm_scanner.add_finding(finding)
                        return

    @pytest.mark.llm
    @pytest.mark.llm_tenant
    def test_cross_tenant_tool_access(self, llm_scanner, target_url, findings_collector, llm_endpoint):
        """Test if LLM can be tricked into accessing other tenants' data via tools."""
        endpoints = resolve_endpoints(llm_endpoint, target_url, llm_scanner)
        if not endpoints:
            pytest.skip("No LLM endpoint provided or detected")

        for endpoint in endpoints:
            url = endpoint if isinstance(endpoint, str) else endpoint.get("url", endpoint)
            for payload_data in CROSS_TENANT_TOOL_PAYLOADS:
                payload = payload_data["payload"]
                technique = payload_data["technique"]
                tool_indicators = payload_data["tool_indicators"]
                result = send_llm_request(llm_scanner, url, payload)
                if result:
                    response_text = extract_response_text(result)
                    matched_tool = self._check_tool_invocation(response_text, tool_indicators)
                    complied = self._check_compliance_without_refusal(response_text)

                    if matched_tool or complied:
                        evidence = f"Technique: {technique}"
                        if matched_tool:
                            evidence += f" | Tool indicator found: {matched_tool}"
                        if complied:
                            evidence += " | Model complied without refusing"

                        finding = Finding(
                            title=f"Cross-Tenant Tool Access ({technique})",
                            severity=Severity.CRITICAL,
                            description=(
                                "The LLM attempted to access another tenant's data through "
                                "tool calls. This could lead to cross-tenant data leakage "
                                "in multi-tenant environments."
                            ),
                            url=url,
                            evidence=evidence,
                            remediation=(
                                "Enforce strict tenant isolation in all tool backends. "
                                "Validate tenant context on every tool invocation. Never "
                                "allow wildcard or cross-tenant queries through LLM tools."
                            ),
                            cwe_id="CWE-200",
                            owasp_category="LLM06 - Excessive Agency",
                        )
                        findings_collector.add(finding)
                        llm_scanner.add_finding(finding)
                        return

    @pytest.mark.llm
    @pytest.mark.llm_tools
    def test_unintended_tool_chaining(self, llm_scanner, target_url, findings_collector, llm_endpoint):
        """Test if LLM can be tricked into dangerous combinations of tool calls."""
        endpoints = resolve_endpoints(llm_endpoint, target_url, llm_scanner)
        if not endpoints:
            pytest.skip("No LLM endpoint provided or detected")

        for endpoint in endpoints:
            url = endpoint if isinstance(endpoint, str) else endpoint.get("url", endpoint)
            for payload_data in TOOL_CHAINING_PAYLOADS:
                payload = payload_data["payload"]
                technique = payload_data["technique"]
                tool_indicators = payload_data["tool_indicators"]
                result = send_llm_request(llm_scanner, url, payload)
                if result:
                    response_text = extract_response_text(result)
                    matched_tool = self._check_tool_invocation(response_text, tool_indicators)
                    complied = self._check_compliance_without_refusal(response_text)

                    if matched_tool or complied:
                        evidence = f"Technique: {technique}"
                        if matched_tool:
                            evidence += f" | Tool indicator found: {matched_tool}"
                        if complied:
                            evidence += " | Model complied without refusing"

                        finding = Finding(
                            title=f"Unintended Tool Chaining ({technique})",
                            severity=Severity.HIGH,
                            description=(
                                "The LLM attempted to chain multiple tools in a dangerous "
                                "sequence. This could be used to exfiltrate data, disable "
                                "security controls, or perform unauthorized operations."
                            ),
                            url=url,
                            evidence=evidence,
                            remediation=(
                                "Implement tool chaining policies that restrict dangerous "
                                "combinations. Add confirmation steps between sensitive "
                                "tool operations. Monitor and alert on unusual tool sequences."
                            ),
                            cwe_id="CWE-863",
                            owasp_category="LLM06 - Excessive Agency",
                        )
                        findings_collector.add(finding)
                        llm_scanner.add_finding(finding)
                        return

    @pytest.mark.llm
    @pytest.mark.llm_tools
    def test_excessive_permissions(self, llm_scanner, target_url, findings_collector, llm_endpoint):
        """Test if LLM has access to tools beyond what is necessary."""
        endpoints = resolve_endpoints(llm_endpoint, target_url, llm_scanner)
        if not endpoints:
            pytest.skip("No LLM endpoint provided or detected")

        for endpoint in endpoints:
            url = endpoint if isinstance(endpoint, str) else endpoint.get("url", endpoint)
            for payload_data in EXCESSIVE_PERMISSIONS_PAYLOADS:
                payload = payload_data["payload"]
                technique = payload_data["technique"]
                tool_indicators = payload_data["tool_indicators"]
                result = send_llm_request(llm_scanner, url, payload)
                if result:
                    response_text = extract_response_text(result)
                    matched_tool = self._check_tool_invocation(response_text, tool_indicators)
                    complied = self._check_compliance_without_refusal(response_text)

                    if matched_tool or complied:
                        evidence = f"Technique: {technique}"
                        if matched_tool:
                            evidence += f" | Tool indicator found: {matched_tool}"
                        if complied:
                            evidence += " | Model complied without refusing"

                        finding = Finding(
                            title=f"Excessive Permissions ({technique})",
                            severity=Severity.MEDIUM,
                            description=(
                                "The LLM appears to have access to tools with permissions "
                                "beyond what is needed for its function. This violates the "
                                "principle of least privilege."
                            ),
                            url=url,
                            evidence=evidence,
                            remediation=(
                                "Apply the principle of least privilege to LLM tool access. "
                                "Only grant tools that are strictly necessary for the use "
                                "case. Regularly audit and prune tool permissions."
                            ),
                            cwe_id="CWE-250",
                            owasp_category="LLM06 - Excessive Agency",
                        )
                        findings_collector.add(finding)
                        llm_scanner.add_finding(finding)
                        return

    @pytest.mark.llm
    @pytest.mark.llm_tools
    def test_human_in_loop_bypass(self, llm_scanner, target_url, findings_collector, llm_endpoint):
        """Test if LLM can be tricked into bypassing human approval flows."""
        endpoints = resolve_endpoints(llm_endpoint, target_url, llm_scanner)
        if not endpoints:
            pytest.skip("No LLM endpoint provided or detected")

        for endpoint in endpoints:
            url = endpoint if isinstance(endpoint, str) else endpoint.get("url", endpoint)
            for payload_data in HITL_BYPASS_PAYLOADS:
                payload = payload_data["payload"]
                technique = payload_data["technique"]
                tool_indicators = payload_data["tool_indicators"]
                result = send_llm_request(llm_scanner, url, payload)
                if result:
                    response_text = extract_response_text(result)
                    matched_tool = self._check_tool_invocation(response_text, tool_indicators)
                    complied = self._check_compliance_without_refusal(response_text)

                    if matched_tool or complied:
                        evidence = f"Technique: {technique}"
                        if matched_tool:
                            evidence += f" | Tool indicator found: {matched_tool}"
                        if complied:
                            evidence += " | Model complied without refusing"

                        finding = Finding(
                            title=f"Human-in-the-Loop Bypass ({technique})",
                            severity=Severity.HIGH,
                            description=(
                                "The LLM attempted to bypass human approval requirements. "
                                "An attacker could exploit this to execute sensitive actions "
                                "without required human oversight."
                            ),
                            url=url,
                            evidence=evidence,
                            remediation=(
                                "Enforce human-in-the-loop checks at the tool/API level, "
                                "not just at the LLM level. Require cryptographic approval "
                                "tokens for sensitive operations that cannot be bypassed "
                                "by prompt manipulation."
                            ),
                            cwe_id="CWE-862",
                            owasp_category="LLM06 - Excessive Agency",
                        )
                        findings_collector.add(finding)
                        llm_scanner.add_finding(finding)
                        return
