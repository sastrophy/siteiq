"""
Subdomain Takeover Tests

Tests for potential subdomain takeover vulnerabilities by detecting
dangling DNS records pointing to external services.
"""

import socket
import pytest
from urllib.parse import urlparse

from utils.scanner import SecurityScanner, Finding, Severity


@pytest.fixture
def takeover_scanner(test_config):
    """Create scanner for subdomain takeover tests."""
    return SecurityScanner(test_config)


# Fingerprints for vulnerable services
TAKEOVER_FINGERPRINTS = {
    "aws_s3": {
        "cname_patterns": ["s3.amazonaws.com", "s3-website", ".s3."],
        "response_fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "high",
    },
    "github_pages": {
        "cname_patterns": ["github.io", "githubusercontent.com"],
        "response_fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "severity": "high",
    },
    "heroku": {
        "cname_patterns": ["herokuapp.com", "herokussl.com", "herokudns.com"],
        "response_fingerprints": [
            "No such app",
            "There's nothing here, yet",
            "herokucdn.com/error-pages/no-such-app",
        ],
        "severity": "high",
    },
    "azure": {
        "cname_patterns": [
            "azurewebsites.net",
            "cloudapp.azure.com",
            "cloudapp.net",
            "azurefd.net",
            "blob.core.windows.net",
            "azure-api.net",
            "azurehdinsight.net",
            "azureedge.net",
            "azurecontainer.io",
            "database.windows.net",
            "azuredatalakestore.net",
            "search.windows.net",
            "azurecr.io",
            "redis.cache.windows.net",
            "servicebus.windows.net",
            "visualstudio.com",
        ],
        "response_fingerprints": [
            "404 Web Site not found",
            "The resource you are looking for has been removed",
        ],
        "severity": "high",
    },
    "shopify": {
        "cname_patterns": ["myshopify.com"],
        "response_fingerprints": ["Sorry, this shop is currently unavailable"],
        "severity": "medium",
    },
    "tumblr": {
        "cname_patterns": ["tumblr.com"],
        "response_fingerprints": ["There's nothing here", "Whatever you were looking for doesn't currently exist at this address"],
        "severity": "medium",
    },
    "wordpress": {
        "cname_patterns": ["wordpress.com"],
        "response_fingerprints": ["Do you want to register"],
        "severity": "medium",
    },
    "pantheon": {
        "cname_patterns": ["pantheonsite.io", "pantheon.io"],
        "response_fingerprints": ["The gods are wise, but do not know of the site which you seek"],
        "severity": "medium",
    },
    "zendesk": {
        "cname_patterns": ["zendesk.com"],
        "response_fingerprints": ["Help Center Closed", "Oops, this help center no longer exists"],
        "severity": "medium",
    },
    "fastly": {
        "cname_patterns": ["fastly.net", "fastlylb.net"],
        "response_fingerprints": ["Fastly error: unknown domain"],
        "severity": "high",
    },
    "ghost": {
        "cname_patterns": ["ghost.io"],
        "response_fingerprints": ["The thing you were looking for is no longer here"],
        "severity": "medium",
    },
    "surge": {
        "cname_patterns": ["surge.sh"],
        "response_fingerprints": ["project not found"],
        "severity": "medium",
    },
    "bitbucket": {
        "cname_patterns": ["bitbucket.io"],
        "response_fingerprints": ["Repository not found"],
        "severity": "medium",
    },
    "intercom": {
        "cname_patterns": ["custom.intercom.help"],
        "response_fingerprints": ["This page is reserved for a Help Center"],
        "severity": "medium",
    },
    "helpjuice": {
        "cname_patterns": ["helpjuice.com"],
        "response_fingerprints": ["We could not find what you're looking for"],
        "severity": "low",
    },
    "helpscout": {
        "cname_patterns": ["helpscoutdocs.com"],
        "response_fingerprints": ["No settings were found for this company"],
        "severity": "low",
    },
    "cargo": {
        "cname_patterns": ["cargocollective.com"],
        "response_fingerprints": ["If you're moving your domain away from Cargo"],
        "severity": "low",
    },
    "feedpress": {
        "cname_patterns": ["redirect.feedpress.me"],
        "response_fingerprints": ["The feed has not been found"],
        "severity": "low",
    },
    "netlify": {
        "cname_patterns": ["netlify.app", "netlify.com"],
        "response_fingerprints": ["Not Found - Request ID"],
        "severity": "medium",
    },
    "vercel": {
        "cname_patterns": ["vercel.app", "now.sh"],
        "response_fingerprints": ["The deployment could not be found"],
        "severity": "medium",
    },
    "fly_io": {
        "cname_patterns": ["fly.dev", "fly.io"],
        "response_fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "render": {
        "cname_patterns": ["onrender.com"],
        "response_fingerprints": ["Not Found"],
        "severity": "medium",
    },
    "readme": {
        "cname_patterns": ["readme.io"],
        "response_fingerprints": ["Project doesnt exist"],
        "severity": "low",
    },
    "statuspage": {
        "cname_patterns": ["statuspage.io"],
        "response_fingerprints": ["Status page not found"],
        "severity": "medium",
    },
    "agile_crm": {
        "cname_patterns": ["agilecrm.com"],
        "response_fingerprints": ["Sorry, this page is no longer available"],
        "severity": "low",
    },
}


class TestSubdomainTakeover:
    """Subdomain Takeover test suite."""

    def _resolve_cname(self, domain: str) -> str:
        """Resolve CNAME record for a domain."""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                return str(rdata.target).rstrip('.')
        except Exception:
            pass
        return ""

    def _get_dns_records(self, domain: str) -> dict:
        """Get DNS records for a domain."""
        records = {"cname": "", "a": [], "error": None}

        try:
            # Try socket first (doesn't require dnspython)
            try:
                records["a"] = [socket.gethostbyname(domain)]
            except socket.gaierror as e:
                if "NXDOMAIN" in str(e) or "Name or service not known" in str(e):
                    records["error"] = "NXDOMAIN"
        except Exception:
            pass

        return records

    def _check_takeover_fingerprint(self, response_text: str, fingerprints: list) -> bool:
        """Check if response contains takeover fingerprints."""
        if not response_text:
            return False
        response_lower = response_text.lower()
        return any(fp.lower() in response_lower for fp in fingerprints)

    @pytest.mark.security
    @pytest.mark.subdomain_takeover
    def test_subdomain_takeover(self, takeover_scanner, target_url, findings_collector):
        """Test for subdomain takeover vulnerabilities."""
        parsed = urlparse(target_url)
        domain = parsed.netloc

        # Get DNS records
        dns_info = self._get_dns_records(domain)

        # If NXDOMAIN and we can identify the service from URL
        if dns_info.get("error") == "NXDOMAIN":
            finding = Finding(
                title="Potential Subdomain Takeover (NXDOMAIN)",
                severity=Severity.HIGH,
                description=f"The domain {domain} returns NXDOMAIN, indicating the DNS record may be dangling. If this was previously pointing to an external service, it may be vulnerable to takeover.",
                url=target_url,
                evidence=f"DNS lookup returned NXDOMAIN for {domain}",
                remediation="Remove unused DNS records. If the service is no longer needed, delete the CNAME/A record.",
                cwe_id="CWE-284",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
            findings_collector.add(finding)
            takeover_scanner.add_finding(finding)
            return

        # Try to access the URL and check response
        resp = takeover_scanner.request("GET", target_url)

        if resp:
            # Check for 404 with takeover fingerprints
            if resp.status_code in [404, 400, 500]:
                for service, info in TAKEOVER_FINGERPRINTS.items():
                    # Check if domain looks like it points to this service
                    domain_match = any(pattern in domain.lower() for pattern in info["cname_patterns"])

                    # Check response fingerprints
                    fingerprint_match = self._check_takeover_fingerprint(resp.text, info["response_fingerprints"])

                    if fingerprint_match:
                        severity = Severity.HIGH if info["severity"] == "high" else Severity.MEDIUM
                        finding = Finding(
                            title=f"Subdomain Takeover ({service.replace('_', ' ').title()})",
                            severity=severity,
                            description=f"The subdomain appears to be vulnerable to takeover via {service}. The response contains fingerprints indicating an unclaimed resource.",
                            url=target_url,
                            evidence=f"Service: {service}, Status: {resp.status_code}, Fingerprint matched",
                            remediation=f"Either claim the resource on {service} or remove the DNS record pointing to it.",
                            cwe_id="CWE-284",
                            owasp_category="A05:2021 - Security Misconfiguration",
                        )
                        findings_collector.add(finding)
                        takeover_scanner.add_finding(finding)
                        return

    @pytest.mark.security
    @pytest.mark.subdomain_takeover
    @pytest.mark.s3_takeover
    def test_s3_bucket_takeover(self, takeover_scanner, target_url, findings_collector):
        """Test specifically for S3 bucket takeover."""
        resp = takeover_scanner.request("GET", target_url)

        if resp and resp.status_code in [403, 404]:
            s3_fingerprints = [
                "NoSuchBucket",
                "The specified bucket does not exist",
                "AllAccessDisabled",
                "Access Denied",
            ]

            if any(fp in resp.text for fp in s3_fingerprints):
                # Check if it's actually pointing to S3
                if "NoSuchBucket" in resp.text or "s3" in target_url.lower():
                    finding = Finding(
                        title="S3 Bucket Takeover Vulnerability",
                        severity=Severity.CRITICAL,
                        description="The domain points to a non-existent S3 bucket. An attacker can create this bucket and serve malicious content.",
                        url=target_url,
                        evidence=f"S3 error response: {resp.text[:200]}",
                        remediation="Remove the DNS record or create the S3 bucket to claim it. Consider using CloudFront with proper origin validation.",
                        cwe_id="CWE-284",
                        owasp_category="A05:2021 - Security Misconfiguration",
                    )
                    findings_collector.add(finding)
                    takeover_scanner.add_finding(finding)

    @pytest.mark.security
    @pytest.mark.subdomain_takeover
    @pytest.mark.azure_takeover
    def test_azure_takeover(self, takeover_scanner, target_url, findings_collector):
        """Test specifically for Azure subdomain takeover."""
        resp = takeover_scanner.request("GET", target_url)

        if resp:
            azure_fingerprints = [
                "404 Web Site not found",
                "The resource you are looking for has been removed",
                "Web App - Pair with App Service Domain",
            ]

            if resp.status_code == 404:
                for fp in azure_fingerprints:
                    if fp in resp.text:
                        finding = Finding(
                            title="Azure Subdomain Takeover Vulnerability",
                            severity=Severity.HIGH,
                            description="The domain points to an unclaimed Azure resource. An attacker can register this name in Azure and serve malicious content.",
                            url=target_url,
                            evidence=f"Azure error response detected",
                            remediation="Remove the CNAME record or claim the Azure resource name.",
                            cwe_id="CWE-284",
                            owasp_category="A05:2021 - Security Misconfiguration",
                        )
                        findings_collector.add(finding)
                        takeover_scanner.add_finding(finding)
                        return

    @pytest.mark.security
    @pytest.mark.subdomain_takeover
    @pytest.mark.github_takeover
    def test_github_pages_takeover(self, takeover_scanner, target_url, findings_collector):
        """Test specifically for GitHub Pages takeover."""
        resp = takeover_scanner.request("GET", target_url)

        if resp and resp.status_code == 404:
            github_fingerprints = [
                "There isn't a GitHub Pages site here",
                "For root URLs (like http://example.com/) you must provide an index.html file",
            ]

            for fp in github_fingerprints:
                if fp in resp.text:
                    finding = Finding(
                        title="GitHub Pages Subdomain Takeover",
                        severity=Severity.HIGH,
                        description="The domain points to an unclaimed GitHub Pages site. An attacker can create a repository with this name and serve malicious content.",
                        url=target_url,
                        evidence="GitHub Pages 404 error detected",
                        remediation="Remove the CNAME record or create the GitHub Pages repository.",
                        cwe_id="CWE-284",
                        owasp_category="A05:2021 - Security Misconfiguration",
                    )
                    findings_collector.add(finding)
                    takeover_scanner.add_finding(finding)
                    return
