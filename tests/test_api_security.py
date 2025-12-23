"""
API Security Tests

Tests for modern API vulnerabilities including:
- GraphQL introspection
- Swagger/OpenAPI exposure
- Mass assignment attacks
- API information disclosure
"""

import json
import pytest
from urllib.parse import urljoin

from utils.scanner import SecurityScanner, Finding, Severity
from payloads.api_security import (
    GRAPHQL_PATHS,
    GRAPHQL_INTROSPECTION_QUERY,
    GRAPHQL_INTROSPECTION_SIMPLE,
    SWAGGER_PATHS,
    SWAGGER_INDICATORS,
    MASS_ASSIGNMENT_PAYLOADS,
    MASS_ASSIGNMENT_ENDPOINTS,
    MASS_ASSIGNMENT_METHODS,
    API_INFO_DISCLOSURE_PATHS,
    CORS_TEST_ORIGINS,
)


@pytest.fixture
def api_scanner(test_config):
    """Create scanner for API tests."""
    return SecurityScanner(test_config)


class TestAPISecurityVulnerabilities:
    """API Security test suite."""

    @pytest.mark.security
    @pytest.mark.api_security
    @pytest.mark.graphql
    def test_graphql_introspection(self, api_scanner, target_url, findings_collector):
        """Test for GraphQL introspection enabled (schema disclosure)."""
        for path in GRAPHQL_PATHS:
            url = urljoin(target_url.rstrip('/') + '/', path.lstrip('/'))

            # Try POST with introspection query
            headers = {"Content-Type": "application/json"}
            payload = {"query": GRAPHQL_INTROSPECTION_SIMPLE}

            resp = api_scanner.request("POST", url, json=payload, headers=headers)

            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data and "__schema" in data.get("data", {}):
                        types = data["data"]["__schema"].get("types", [])
                        type_names = [t.get("name", "") for t in types if t.get("name")]

                        finding = Finding(
                            title="GraphQL Introspection Enabled",
                            severity=Severity.MEDIUM,
                            description=f"GraphQL introspection is enabled at {url}. This exposes the entire API schema to attackers, revealing types, queries, mutations, and potentially sensitive fields.",
                            url=url,
                            evidence=f"Found {len(type_names)} types including: {', '.join(type_names[:10])}...",
                            remediation="Disable introspection in production: set `introspection: false` in your GraphQL server config. For Apollo Server: `new ApolloServer({ introspection: false })`",
                            cwe_id="CWE-200",
                            owasp_category="A01:2021 - Broken Access Control",
                        )
                        findings_collector.add(finding)
                        api_scanner.add_finding(finding)
                        return  # Found vulnerability, stop testing
                except (json.JSONDecodeError, KeyError):
                    pass

            # Also try GET with query parameter
            resp = api_scanner.request("GET", url, params={"query": GRAPHQL_INTROSPECTION_SIMPLE})
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data and "__schema" in data.get("data", {}):
                        finding = Finding(
                            title="GraphQL Introspection Enabled (GET)",
                            severity=Severity.MEDIUM,
                            description=f"GraphQL introspection is enabled via GET at {url}.",
                            url=url,
                            evidence="Schema introspection query returned valid response",
                            remediation="Disable introspection in production environments.",
                            cwe_id="CWE-200",
                            owasp_category="A01:2021 - Broken Access Control",
                        )
                        findings_collector.add(finding)
                        api_scanner.add_finding(finding)
                        return
                except (json.JSONDecodeError, KeyError):
                    pass

    @pytest.mark.security
    @pytest.mark.api_security
    @pytest.mark.swagger
    def test_swagger_openapi_exposure(self, api_scanner, target_url, findings_collector):
        """Test for publicly accessible Swagger/OpenAPI documentation."""
        found_docs = []

        for path in SWAGGER_PATHS:
            url = urljoin(target_url.rstrip('/') + '/', path.lstrip('/'))
            resp = api_scanner.request("GET", url)

            if resp and resp.status_code == 200:
                content = resp.text.lower()
                content_type = resp.headers.get("Content-Type", "").lower()

                # Check for JSON/YAML API docs
                if "json" in content_type or "yaml" in content_type:
                    indicator_count = sum(1 for ind in SWAGGER_INDICATORS if ind in content)
                    if indicator_count >= 2:
                        found_docs.append({"url": url, "type": "json/yaml"})

                # Check for Swagger UI HTML
                elif "html" in content_type:
                    if "swagger" in content or "openapi" in content or "api-docs" in content:
                        found_docs.append({"url": url, "type": "ui"})

        if found_docs:
            urls = [d["url"] for d in found_docs]
            finding = Finding(
                title="Swagger/OpenAPI Documentation Exposed",
                severity=Severity.LOW,
                description=f"API documentation is publicly accessible. Found {len(found_docs)} documentation endpoints.",
                url=urls[0],
                evidence=f"Documentation URLs: {', '.join(urls[:5])}",
                remediation="Restrict API documentation access to authenticated users or internal networks. Use authentication middleware or IP allowlisting.",
                cwe_id="CWE-200",
                owasp_category="A01:2021 - Broken Access Control",
            )
            findings_collector.add(finding)
            api_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.api_security
    @pytest.mark.mass_assignment
    def test_mass_assignment(self, api_scanner, target_url, findings_collector):
        """Test for mass assignment vulnerabilities."""
        for endpoint in MASS_ASSIGNMENT_ENDPOINTS:
            url = urljoin(target_url.rstrip('/') + '/', endpoint.lstrip('/'))

            for method in MASS_ASSIGNMENT_METHODS:
                # First, check if endpoint exists
                test_resp = api_scanner.request("OPTIONS", url)
                if not test_resp or test_resp.status_code == 404:
                    continue

                # Try each mass assignment payload
                for payload in MASS_ASSIGNMENT_PAYLOADS[:10]:  # Limit to first 10 to avoid excessive requests
                    headers = {"Content-Type": "application/json"}

                    resp = api_scanner.request(method, url, json=payload, headers=headers)

                    if resp and resp.status_code in [200, 201, 204]:
                        try:
                            data = resp.json() if resp.text else {}

                            # Check if any injected field was accepted
                            for key in payload.keys():
                                if key in str(data):
                                    finding = Finding(
                                        title=f"Potential Mass Assignment ({key})",
                                        severity=Severity.HIGH,
                                        description=f"The API endpoint {url} may be vulnerable to mass assignment. The parameter '{key}' was accepted in the request.",
                                        url=url,
                                        evidence=f"Method: {method}, Payload: {json.dumps(payload)}, Response contained key: {key}",
                                        remediation="Implement allowlist of permitted fields for each endpoint. Use DTOs or serializers to control which fields can be modified. Example: `allowed_fields = ['name', 'email']`",
                                        cwe_id="CWE-915",
                                        owasp_category="A01:2021 - Broken Access Control",
                                    )
                                    findings_collector.add(finding)
                                    api_scanner.add_finding(finding)
                                    return  # Found vulnerability
                        except json.JSONDecodeError:
                            pass

    @pytest.mark.security
    @pytest.mark.api_security
    @pytest.mark.api_info
    def test_api_information_disclosure(self, api_scanner, target_url, findings_collector):
        """Test for API information disclosure via debug/health endpoints."""
        sensitive_findings = []

        for path in API_INFO_DISCLOSURE_PATHS:
            url = urljoin(target_url.rstrip('/') + '/', path.lstrip('/'))
            resp = api_scanner.request("GET", url)

            if resp and resp.status_code == 200:
                content = resp.text.lower()

                # Check for sensitive information
                sensitive_patterns = [
                    ("database", "Database connection info"),
                    ("password", "Password/credential exposure"),
                    ("secret", "Secret key exposure"),
                    ("api_key", "API key exposure"),
                    ("token", "Token exposure"),
                    ("private", "Private data exposure"),
                    ("internal", "Internal configuration"),
                    ("debug", "Debug information"),
                    ("stack", "Stack trace"),
                    ("version", "Version information"),
                ]

                found_patterns = []
                for pattern, desc in sensitive_patterns:
                    if pattern in content:
                        found_patterns.append(desc)

                if found_patterns:
                    sensitive_findings.append({
                        "url": url,
                        "patterns": found_patterns[:3],
                    })

        if sensitive_findings:
            finding = Finding(
                title="API Information Disclosure",
                severity=Severity.MEDIUM,
                description=f"Found {len(sensitive_findings)} endpoints exposing potentially sensitive information.",
                url=sensitive_findings[0]["url"],
                evidence=f"Endpoints: {[f['url'] for f in sensitive_findings[:3]]}, Patterns: {sensitive_findings[0]['patterns']}",
                remediation="Disable debug endpoints in production. Restrict access to health/status endpoints. Remove sensitive data from API responses.",
                cwe_id="CWE-200",
                owasp_category="A01:2021 - Broken Access Control",
            )
            findings_collector.add(finding)
            api_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.api_security
    @pytest.mark.cors
    def test_cors_misconfiguration(self, api_scanner, target_url, findings_collector):
        """Test for CORS misconfiguration."""
        for origin in CORS_TEST_ORIGINS:
            headers = {"Origin": origin}
            resp = api_scanner.request("GET", target_url, headers=headers)

            if resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                # Check for wildcard with credentials
                if acao == "*" and acac.lower() == "true":
                    finding = Finding(
                        title="CORS Wildcard with Credentials",
                        severity=Severity.HIGH,
                        description="The server allows any origin with credentials, which is a severe security misconfiguration.",
                        url=target_url,
                        evidence=f"Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                        remediation="Never use wildcard (*) with credentials. Implement a strict allowlist of trusted origins.",
                        cwe_id="CWE-942",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)
                    api_scanner.add_finding(finding)
                    return

                # Check for reflected origin
                if acao == origin and origin in ["https://evil.com", "https://attacker.com", "null"]:
                    severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                    finding = Finding(
                        title="CORS Origin Reflection",
                        severity=severity,
                        description=f"The server reflects arbitrary origins in Access-Control-Allow-Origin header.",
                        url=target_url,
                        evidence=f"Reflected origin: {origin}, Credentials: {acac}",
                        remediation="Validate origins against a strict allowlist. Do not reflect arbitrary origins.",
                        cwe_id="CWE-942",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    findings_collector.add(finding)
                    api_scanner.add_finding(finding)
                    return
