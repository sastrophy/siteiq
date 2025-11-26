"""
Core Scanner Utilities

Provides common functionality for security testing including
HTTP requests, response analysis, and vulnerability detection.
"""

import re
import time
import urllib3
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings for testing (we test SSL separately)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a security finding."""
    title: str
    severity: Severity
    description: str
    url: str
    evidence: str = ""
    remediation: str = ""
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "url": self.url,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
        }


class SecurityScanner:
    """Base security scanner with common HTTP functionality."""

    def __init__(self, config):
        self.config = config
        self.session = self._create_session()
        self.findings: list[Finding] = []

    def _create_session(self) -> requests.Session:
        """Create a configured requests session."""
        session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set default headers
        session.headers.update({
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })

        # Set authentication if provided
        if self.config.auth_username and self.config.auth_password:
            session.auth = (self.config.auth_username, self.config.auth_password)

        return session

    def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[requests.Response]:
        """Make an HTTP request with error handling and rate limiting."""
        try:
            # Apply rate limiting
            time.sleep(self.config.request_delay)

            # Set defaults
            kwargs.setdefault("timeout", self.config.timeout)
            kwargs.setdefault("verify", False)  # We test SSL separately
            kwargs.setdefault("allow_redirects", True)

            response = self.session.request(method, url, **kwargs)
            return response

        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.RequestException:
            return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a GET request."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a POST request."""
        return self.request("POST", url, **kwargs)

    def add_finding(self, finding: Finding):
        """Add a security finding."""
        self.findings.append(finding)

    def get_findings(self) -> list[Finding]:
        """Get all findings."""
        return self.findings

    def build_url(self, path: str) -> str:
        """Build a full URL from a path."""
        return urljoin(self.config.base_url, path)

    def inject_payload(self, url: str, payload: str) -> list[str]:
        """
        Generate URLs with payload injected into query parameters.
        Returns list of URLs with payload in each parameter.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            # If no params, try adding a common one
            return [f"{url}?id={payload}", f"{url}?q={payload}", f"{url}?search={payload}"]

        injected_urls = []
        for param in params:
            # Create a copy with payload injected
            modified_params = params.copy()
            modified_params[param] = [payload]
            new_query = urlencode(modified_params, doseq=True)
            new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            injected_urls.append(new_url)

        return injected_urls


def detect_waf(response: requests.Response) -> Optional[str]:
    """Detect if a Web Application Firewall is present."""
    waf_signatures = {
        "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
        "AWS WAF": ["x-amzn-requestid", "awswaf"],
        "Akamai": ["akamai", "x-akamai"],
        "Imperva": ["incap_ses", "visid_incap", "x-iinfo"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Sucuri": ["sucuri", "x-sucuri"],
        "Wordfence": ["wordfence"],
    }

    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
    body_lower = response.text.lower() if response.text else ""

    for waf_name, signatures in waf_signatures.items():
        for sig in signatures:
            if any(sig in h or sig in v for h, v in headers_lower.items()):
                return waf_name
            if sig in body_lower:
                return waf_name

    return None


def extract_forms(html: str, base_url: str) -> list[dict]:
    """Extract forms from HTML for testing."""
    forms = []
    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
    action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
    method_pattern = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
    input_pattern = re.compile(
        r'<input[^>]*name=["\']([^"\']*)["\'][^>]*(?:type=["\']([^"\']*)["\'])?[^>]*>',
        re.IGNORECASE
    )
    textarea_pattern = re.compile(r'<textarea[^>]*name=["\']([^"\']*)["\']', re.IGNORECASE)

    for form_match in form_pattern.finditer(html):
        form_html = form_match.group(0)
        form_content = form_match.group(1)

        # Extract action
        action_match = action_pattern.search(form_html)
        action = action_match.group(1) if action_match else ""
        if action and not action.startswith(("http://", "https://")):
            action = urljoin(base_url, action)
        elif not action:
            action = base_url

        # Extract method
        method_match = method_pattern.search(form_html)
        method = (method_match.group(1) if method_match else "GET").upper()

        # Extract inputs
        inputs = []
        for input_match in input_pattern.finditer(form_html):
            name = input_match.group(1)
            input_type = input_match.group(2) or "text"
            if input_type.lower() not in ("submit", "button", "image", "reset"):
                inputs.append({"name": name, "type": input_type})

        # Extract textareas
        for textarea_match in textarea_pattern.finditer(form_content):
            inputs.append({"name": textarea_match.group(1), "type": "textarea"})

        if inputs:
            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
            })

    return forms


def extract_links(html: str, base_url: str) -> set[str]:
    """Extract links from HTML."""
    links = set()
    link_pattern = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)

    base_parsed = urlparse(base_url)

    for match in link_pattern.finditer(html):
        link = match.group(1)

        # Skip javascript, mailto, tel links
        if link.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue

        # Convert relative URLs to absolute
        if not link.startswith(("http://", "https://")):
            link = urljoin(base_url, link)

        # Only include same-domain links
        link_parsed = urlparse(link)
        if link_parsed.netloc == base_parsed.netloc:
            links.add(link)

    return links


def is_error_page(response: requests.Response) -> bool:
    """Check if response is an error page."""
    error_indicators = [
        "error", "exception", "stacktrace", "traceback",
        "fatal", "warning:", "notice:", "parse error",
        "syntax error", "undefined", "null reference",
    ]

    if response.status_code >= 400:
        return True

    content_lower = response.text.lower() if response.text else ""
    return any(indicator in content_lower for indicator in error_indicators)


def check_reflection(response: requests.Response, payload: str) -> bool:
    """Check if a payload is reflected in the response."""
    if not response or not response.text:
        return False
    return payload in response.text
