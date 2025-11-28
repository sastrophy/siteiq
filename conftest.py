"""
Pytest Configuration and Fixtures

Provides shared fixtures and configuration for all security tests.
"""

import json
import os
from datetime import datetime
from pathlib import Path

import pytest

from config import SecurityTestConfig, config, set_target_url
from utils.scanner import SecurityScanner, Finding


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--target-url",
        action="store",
        default=os.getenv("SECURITY_TEST_URL", ""),
        help="Target URL to test (required)",
    )
    parser.addoption(
        "--wordpress-path",
        action="store",
        default="/blog",
        help="Path to WordPress installation (default: /blog)",
    )
    parser.addoption(
        "--intensity",
        action="store",
        default="medium",
        choices=["light", "medium", "aggressive"],
        help="Test intensity level (default: medium)",
    )
    parser.addoption(
        "--auth-username",
        action="store",
        default=None,
        help="Username for authenticated testing",
    )
    parser.addoption(
        "--auth-password",
        action="store",
        default=None,
        help="Password for authenticated testing",
    )
    parser.addoption(
        "--skip-ssl",
        action="store_true",
        default=False,
        help="Skip SSL/TLS tests",
    )
    parser.addoption(
        "--skip-wordpress",
        action="store_true",
        default=False,
        help="Skip WordPress-specific tests",
    )
    parser.addoption(
        "--report-id",
        action="store",
        default=None,
        help="Custom report ID for filename (used by webapp)",
    )
    parser.addoption(
        "--llm-endpoint",
        action="store",
        default=None,
        help="LLM API endpoint to test (e.g., /api/chat)",
    )


def pytest_configure(config):
    """Configure pytest with custom markers."""
    # Security test markers
    config.addinivalue_line("markers", "sql_injection: SQL injection tests")
    config.addinivalue_line("markers", "xss: Cross-site scripting tests")
    config.addinivalue_line("markers", "csrf: CSRF tests")
    config.addinivalue_line("markers", "headers: Security headers tests")
    config.addinivalue_line("markers", "ssl: SSL/TLS tests")
    config.addinivalue_line("markers", "wordpress: WordPress-specific tests")
    config.addinivalue_line("markers", "auth: Authentication tests")
    config.addinivalue_line("markers", "traversal: Directory traversal tests")
    config.addinivalue_line("markers", "slow: Slow tests")

    # SEO test markers
    config.addinivalue_line("markers", "seo: SEO analysis tests")
    config.addinivalue_line("markers", "meta_tags: Meta tags analysis")
    config.addinivalue_line("markers", "headings: Heading structure tests")
    config.addinivalue_line("markers", "images: Image optimization tests")
    config.addinivalue_line("markers", "robots: Robots.txt tests")
    config.addinivalue_line("markers", "sitemap: Sitemap.xml tests")
    config.addinivalue_line("markers", "canonical: Canonical tag tests")
    config.addinivalue_line("markers", "links: Link analysis tests")
    config.addinivalue_line("markers", "urls: URL structure tests")
    config.addinivalue_line("markers", "mobile: Mobile friendliness tests")
    config.addinivalue_line("markers", "schema: Schema markup tests")
    config.addinivalue_line("markers", "opengraph: Open Graph tests")
    config.addinivalue_line("markers", "twitter: Twitter Card tests")
    config.addinivalue_line("markers", "performance: Performance SEO tests")
    config.addinivalue_line("markers", "pagespeed: PageSpeed API tests")
    config.addinivalue_line("markers", "hreflang: Hreflang tests")

    # GEO test markers
    config.addinivalue_line("markers", "geo: GEO testing")
    config.addinivalue_line("markers", "accessibility: Geo accessibility tests")
    config.addinivalue_line("markers", "latency: Response time tests")
    config.addinivalue_line("markers", "content: Geo content variation tests")
    config.addinivalue_line("markers", "compliance: Regional compliance tests")
    config.addinivalue_line("markers", "redirects: Geo redirect tests")
    config.addinivalue_line("markers", "cdn: CDN and edge tests")
    config.addinivalue_line("markers", "international_seo: International SEO tests")

    # LLM test markers
    config.addinivalue_line("markers", "llm: LLM security tests")
    config.addinivalue_line("markers", "llm_injection: Prompt injection tests")
    config.addinivalue_line("markers", "llm_jailbreak: Jailbreaking tests")
    config.addinivalue_line("markers", "llm_leakage: System prompt leakage tests")
    config.addinivalue_line("markers", "llm_dos: Denial of Wallet tests")
    config.addinivalue_line("markers", "llm_data: Data exfiltration tests")
    config.addinivalue_line("markers", "llm_rate: Rate limiting tests")
    config.addinivalue_line("markers", "llm_auth: Authentication tests")


@pytest.fixture(scope="session")
def test_config(request) -> SecurityTestConfig:
    """Create and validate test configuration."""
    target_url = request.config.getoption("--target-url")

    if not target_url:
        pytest.skip("No target URL provided. Use --target-url or set SECURITY_TEST_URL")

    set_target_url(target_url)

    # Update config from command line options
    from config import config as global_config
    global_config.wordpress_path = request.config.getoption("--wordpress-path")
    global_config.intensity = request.config.getoption("--intensity")
    global_config.auth_username = request.config.getoption("--auth-username")
    global_config.auth_password = request.config.getoption("--auth-password")
    global_config.test_ssl = not request.config.getoption("--skip-ssl")
    global_config.test_wordpress = not request.config.getoption("--skip-wordpress")

    # Validate configuration
    global_config.validate()

    return global_config


@pytest.fixture(scope="session")
def scanner(test_config) -> SecurityScanner:
    """Create a shared scanner instance."""
    return SecurityScanner(test_config)


@pytest.fixture(scope="session")
def target_url(test_config) -> str:
    """Get the target URL."""
    return test_config.base_url


@pytest.fixture(scope="session")
def wordpress_url(test_config) -> str:
    """Get the WordPress URL."""
    return test_config.wordpress_url


@pytest.fixture(scope="session")
def llm_endpoint(request, target_url) -> str:
    """Get the LLM API endpoint."""
    endpoint = request.config.getoption("--llm-endpoint")
    if endpoint:
        # If it's a relative path, prepend target_url
        if endpoint.startswith("/"):
            return f"{target_url.rstrip('/')}{endpoint}"
        return endpoint
    return None


@pytest.fixture(scope="session")
def findings_collector():
    """Collect all findings across tests."""
    findings = []

    class Collector:
        def add(self, finding: Finding):
            findings.append(finding)

        def get_all(self) -> list[Finding]:
            return findings

        def get_by_severity(self, severity) -> list[Finding]:
            return [f for f in findings if f.severity == severity]

    return Collector()


@pytest.fixture(scope="session", autouse=True)
def generate_report(request, findings_collector, test_config):
    """Generate a report after all tests complete."""
    yield

    # Generate report
    findings = findings_collector.get_all()

    if not findings:
        return

    report = {
        "target": test_config.base_url,
        "timestamp": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings_by_severity": {
            "critical": len([f for f in findings if f.severity.value == "critical"]),
            "high": len([f for f in findings if f.severity.value == "high"]),
            "medium": len([f for f in findings if f.severity.value == "medium"]),
            "low": len([f for f in findings if f.severity.value == "low"]),
            "info": len([f for f in findings if f.severity.value == "info"]),
        },
        "findings": [f.to_dict() for f in findings],
    }

    # Ensure reports directory exists
    report_dir = Path(test_config.report_dir)
    report_dir.mkdir(exist_ok=True)

    # Write JSON report - use report-id if provided (from webapp), otherwise timestamp
    report_id = request.config.getoption("--report-id")
    if report_id:
        report_file = report_dir / f"report_{report_id}.json"
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = report_dir / f"security_report_{timestamp}.json"

    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n\nSecurity Report saved to: {report_file}")
    print(f"Total findings: {len(findings)}")
    print(f"  Critical: {report['findings_by_severity']['critical']}")
    print(f"  High: {report['findings_by_severity']['high']}")
    print(f"  Medium: {report['findings_by_severity']['medium']}")
    print(f"  Low: {report['findings_by_severity']['low']}")
    print(f"  Info: {report['findings_by_severity']['info']}")
