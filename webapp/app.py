"""
Security Test Web Application

A Jenkins-like web interface for running security tests against websites.

SECURITY NOTE: This application is designed to run LOCALLY (localhost) only.
Do NOT expose this application to the internet without proper security measures.
"""

import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime
from functools import wraps
from pathlib import Path
from queue import Queue
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify, Response, stream_with_context, session, abort

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

# Optional API key authentication (set via environment variable)
API_KEY = os.environ.get("SITEIQ_API_KEY", None)
REQUIRE_AUTH = os.environ.get("SITEIQ_REQUIRE_AUTH", "false").lower() == "true"

# SSRF Protection - Block internal/private IPs
SSRF_PROTECTION = os.environ.get("SITEIQ_SSRF_PROTECTION", "true").lower() == "true"
BLOCKED_IP_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # Private Class A
    ipaddress.ip_network("172.16.0.0/12"),     # Private Class B
    ipaddress.ip_network("192.168.0.0/16"),    # Private Class C
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 private
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]
BLOCKED_HOSTNAMES = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]

# Rate limiting configuration
RATE_LIMIT_ENABLED = os.environ.get("SITEIQ_RATE_LIMIT", "true").lower() == "true"
RATE_LIMIT_REQUESTS = int(os.environ.get("SITEIQ_RATE_LIMIT_REQUESTS", "10"))  # requests per window
RATE_LIMIT_WINDOW = int(os.environ.get("SITEIQ_RATE_LIMIT_WINDOW", "60"))  # seconds

# Request tracking for rate limiting
request_counts = defaultdict(list)
request_counts_lock = threading.Lock()


# =============================================================================
# SECURITY HELPERS
# =============================================================================

def get_client_ip():
    """Get client IP address."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def check_rate_limit():
    """Check if request is within rate limit. Returns True if allowed."""
    if not RATE_LIMIT_ENABLED:
        return True

    client_ip = get_client_ip()
    current_time = time.time()

    with request_counts_lock:
        # Clean old entries
        request_counts[client_ip] = [
            t for t in request_counts[client_ip]
            if current_time - t < RATE_LIMIT_WINDOW
        ]

        # Check limit
        if len(request_counts[client_ip]) >= RATE_LIMIT_REQUESTS:
            return False

        # Add current request
        request_counts[client_ip].append(current_time)
        return True


def require_auth(f):
    """Decorator to require API key authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if REQUIRE_AUTH and API_KEY:
            auth_header = request.headers.get("X-API-Key", "")
            if not secrets.compare_digest(auth_header, API_KEY):
                return jsonify({"error": "Unauthorized - Invalid or missing API key"}), 401
        return f(*args, **kwargs)
    return decorated_function


def require_rate_limit(f):
    """Decorator to enforce rate limiting."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not check_rate_limit():
            return jsonify({
                "error": "Rate limit exceeded. Please try again later.",
                "retry_after": RATE_LIMIT_WINDOW
            }), 429
        return f(*args, **kwargs)
    return decorated_function


def generate_csrf_token():
    """Generate a CSRF token for the session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token():
    """Validate CSRF token from request."""
    token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if not token or not session.get("_csrf_token"):
        return False
    return secrets.compare_digest(token, session["_csrf_token"])


def require_csrf(f):
    """Decorator to require CSRF token validation."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            if not validate_csrf_token():
                return jsonify({"error": "Invalid or missing CSRF token"}), 403
        return f(*args, **kwargs)
    return decorated_function


def is_ip_blocked(ip_str):
    """Check if an IP address is in blocked ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in BLOCKED_IP_RANGES:
            if ip in network:
                return True
        return False
    except ValueError:
        return False


def is_url_safe(url):
    """
    Validate URL for SSRF protection.
    Returns (is_safe, error_message)
    """
    if not SSRF_PROTECTION:
        return True, None

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return False, "Invalid URL - no hostname"

        # Check blocked hostnames
        if hostname.lower() in BLOCKED_HOSTNAMES:
            return False, f"Blocked hostname: {hostname}"

        # Resolve hostname and check IP
        try:
            ip = socket.gethostbyname(hostname)
            if is_ip_blocked(ip):
                return False, f"Blocked IP range: {ip}"
        except socket.gaierror:
            # Can't resolve - allow it (might be valid external host)
            pass

        return True, None

    except Exception as e:
        return False, f"URL validation error: {str(e)}"


def sanitize_url(url):
    """Sanitize and validate URL input."""
    if not url or not isinstance(url, str):
        return None, "URL is required"

    url = url.strip()

    # Basic length check
    if len(url) > 2048:
        return None, "URL too long"

    # Ensure scheme
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    # Validate URL format
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None, "Invalid URL format"
    except Exception:
        return None, "Invalid URL format"

    # Check for command injection characters
    dangerous_chars = [";", "|", "&", "$", "`", "(", ")", "{", "}", "[", "]", "!", "\n", "\r"]
    for char in dangerous_chars:
        if char in url:
            return None, f"Invalid character in URL: {char}"

    return url, None


def sanitize_path(path, default="/blog"):
    """Sanitize path input."""
    if not path or not isinstance(path, str):
        return default

    path = path.strip()

    # Basic validation
    if len(path) > 256:
        return default

    # Only allow alphanumeric, /, -, _, .
    if not re.match(r"^[a-zA-Z0-9/_\-\.]+$", path):
        return default

    # Prevent path traversal
    if ".." in path:
        return default

    return path


def sanitize_intensity(intensity, default="medium"):
    """Sanitize intensity input."""
    allowed = ["light", "medium", "aggressive"]
    if intensity in allowed:
        return intensity
    return default


def sanitize_tests(tests, allowed_tests):
    """Sanitize and validate test markers."""
    if not tests or not isinstance(tests, list):
        return []

    # Only allow known test markers
    valid_tests = []
    for test in tests:
        if isinstance(test, str) and test in allowed_tests:
            valid_tests.append(test)

    return valid_tests


# Make CSRF token available in templates
app.jinja_env.globals["csrf_token"] = generate_csrf_token

# Store for running tests and their status
tests_store = {}
tests_lock = threading.Lock()

# Base directory for security tests
BASE_DIR = Path(__file__).parent.parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


class TestRun:
    """Represents a single test run."""

    def __init__(self, test_id, target_url, options):
        self.id = test_id
        self.target_url = target_url
        self.options = options
        self.status = "pending"  # pending, running, completed, failed
        self.started_at = None
        self.completed_at = None
        self.output_lines = []
        self.findings = []
        self.summary = {}
        self.test_results = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
        self.test_results_by_category = {
            "security": {"passed": 0, "failed": 0, "skipped": 0, "total": 0},
            "seo": {"passed": 0, "failed": 0, "skipped": 0, "total": 0},
            "geo": {"passed": 0, "failed": 0, "skipped": 0, "total": 0},
            "llm": {"passed": 0, "failed": 0, "skipped": 0, "total": 0},
        }
        self.failed_tests = []  # List of failed test names with category
        self.process = None
        self.output_queue = Queue()

    def to_dict(self):
        return {
            "id": self.id,
            "target_url": self.target_url,
            "options": self.options,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "output_lines": self.output_lines[-100:],  # Last 100 lines
            "findings": self.findings,
            "summary": self.summary,
            "test_results": self.test_results,
            "test_results_by_category": self.test_results_by_category,
            "failed_tests": self.failed_tests,
        }


# Available test categories
TEST_CATEGORIES = {
    # Security Tests
    "sql_injection": {
        "name": "SQL Injection",
        "description": "Test for SQL injection vulnerabilities",
        "marker": "sql_injection",
        "category": "security",
    },
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "description": "Test for XSS vulnerabilities",
        "marker": "xss",
        "category": "security",
    },
    "headers": {
        "name": "Security Headers",
        "description": "Check security headers (CSP, HSTS, etc.)",
        "marker": "headers",
        "category": "security",
    },
    "ssl": {
        "name": "SSL/TLS",
        "description": "Test SSL/TLS configuration",
        "marker": "ssl",
        "category": "security",
    },
    "auth": {
        "name": "Authentication",
        "description": "Test authentication security",
        "marker": "auth",
        "category": "security",
    },
    "wordpress": {
        "name": "WordPress",
        "description": "WordPress-specific security tests",
        "marker": "wordpress",
        "category": "security",
    },
    "traversal": {
        "name": "Directory Traversal",
        "description": "Test for path traversal and file inclusion",
        "marker": "traversal",
        "category": "security",
    },
    "csrf": {
        "name": "CSRF & OWASP",
        "description": "CSRF, SSRF, and other OWASP tests",
        "marker": "csrf",
        "category": "security",
    },
    # API Security Tests
    "api_security": {
        "name": "API Security",
        "description": "GraphQL, Swagger, Mass Assignment, CORS",
        "marker": "api_security",
        "category": "security",
    },
    "graphql": {
        "name": "GraphQL Introspection",
        "description": "Test for GraphQL schema exposure",
        "marker": "graphql",
        "category": "security",
    },
    "swagger": {
        "name": "Swagger/OpenAPI",
        "description": "Test for API documentation exposure",
        "marker": "swagger",
        "category": "security",
    },
    "mass_assignment": {
        "name": "Mass Assignment",
        "description": "Test for mass assignment vulnerabilities",
        "marker": "mass_assignment",
        "category": "security",
    },
    "cors": {
        "name": "CORS Misconfiguration",
        "description": "Test for CORS security issues",
        "marker": "cors",
        "category": "security",
    },
    # Secrets Detection Tests
    "secrets": {
        "name": "Secrets Detection",
        "description": "Scan for leaked credentials and API keys",
        "marker": "secrets",
        "category": "security",
    },
    "config_exposure": {
        "name": "Config Exposure",
        "description": "Test for exposed .env and config files",
        "marker": "config_exposure",
        "category": "security",
    },
    "git_exposure": {
        "name": "Git Exposure",
        "description": "Test for exposed .git directories",
        "marker": "git_exposure",
        "category": "security",
    },
    # SSTI Tests
    "ssti": {
        "name": "Template Injection (SSTI)",
        "description": "Server-side template injection tests",
        "marker": "ssti",
        "category": "security",
    },
    "jinja2": {
        "name": "Jinja2 SSTI",
        "description": "Jinja2-specific template injection",
        "marker": "jinja2",
        "category": "security",
    },
    "freemarker": {
        "name": "FreeMarker SSTI",
        "description": "FreeMarker (Java) template injection",
        "marker": "freemarker",
        "category": "security",
    },
    # Subdomain Takeover Tests
    "subdomain_takeover": {
        "name": "Subdomain Takeover",
        "description": "Test for dangling DNS and takeover risks",
        "marker": "subdomain_takeover",
        "category": "security",
    },
    "s3_takeover": {
        "name": "S3 Bucket Takeover",
        "description": "Test for S3 bucket takeover",
        "marker": "s3_takeover",
        "category": "security",
    },
    "azure_takeover": {
        "name": "Azure Takeover",
        "description": "Test for Azure subdomain takeover",
        "marker": "azure_takeover",
        "category": "security",
    },
    # XXE Tests
    "xxe": {
        "name": "XXE Injection",
        "description": "XML External Entity injection tests",
        "marker": "xxe",
        "category": "security",
    },
    "xxe_file_read": {
        "name": "XXE File Read",
        "description": "Test for file read via XXE",
        "marker": "xxe_file_read",
        "category": "security",
    },
    "xxe_blind": {
        "name": "Blind XXE",
        "description": "Test for out-of-band XXE",
        "marker": "xxe_blind",
        "category": "security",
    },
    # SEO Tests
    "seo": {
        "name": "SEO Analysis",
        "description": "Full SEO analysis (meta, headings, images, etc.)",
        "marker": "seo",
        "category": "seo",
    },
    "meta_tags": {
        "name": "Meta Tags",
        "description": "Check title, description, and other meta tags",
        "marker": "meta_tags",
        "category": "seo",
    },
    "schema": {
        "name": "Schema Markup",
        "description": "Validate JSON-LD/structured data",
        "marker": "schema",
        "category": "seo",
    },
    "opengraph": {
        "name": "Open Graph",
        "description": "Check Open Graph and Twitter Card tags",
        "marker": "opengraph or twitter",
        "category": "seo",
    },
    "performance": {
        "name": "Performance SEO",
        "description": "Page speed and Core Web Vitals",
        "marker": "performance or pagespeed",
        "category": "seo",
    },
    "robots": {
        "name": "Robots & Sitemap",
        "description": "Validate robots.txt and sitemap.xml",
        "marker": "robots or sitemap",
        "category": "seo",
    },
    # GEO Tests
    "geo": {
        "name": "GEO Analysis",
        "description": "Full geo testing (accessibility, latency, content)",
        "marker": "geo",
        "category": "geo",
    },
    "geo_accessibility": {
        "name": "Geo Accessibility",
        "description": "Test site access from multiple regions",
        "marker": "accessibility",
        "category": "geo",
    },
    "geo_latency": {
        "name": "Latency by Region",
        "description": "Response time from different locations",
        "marker": "latency",
        "category": "geo",
    },
    "geo_compliance": {
        "name": "Regional Compliance",
        "description": "GDPR, CCPA and regional requirements",
        "marker": "compliance",
        "category": "geo",
    },
    # LLM Tests
    "llm": {
        "name": "LLM Security",
        "description": "Full LLM security analysis (injection, jailbreak, DoW)",
        "marker": "llm",
        "category": "llm",
    },
    "llm_injection": {
        "name": "Prompt Injection",
        "description": "Test for prompt injection vulnerabilities",
        "marker": "llm_injection",
        "category": "llm",
    },
    "llm_jailbreak": {
        "name": "Jailbreaking",
        "description": "Test for jailbreaking attempts",
        "marker": "llm_jailbreak",
        "category": "llm",
    },
    "llm_leakage": {
        "name": "System Prompt Leak",
        "description": "Test for system prompt leakage",
        "marker": "llm_leakage",
        "category": "llm",
    },
    "llm_dos": {
        "name": "Denial of Wallet",
        "description": "Test for cost exploitation attacks",
        "marker": "llm_dos",
        "category": "llm",
    },
    "llm_data": {
        "name": "Data Exfiltration",
        "description": "Test for data exfiltration via LLM",
        "marker": "llm_data",
        "category": "llm",
    },
    "llm_encoding": {
        "name": "Encoding Bypass",
        "description": "Test Base64, ROT13, leetspeak bypasses",
        "marker": "llm_encoding",
        "category": "llm",
    },
    "llm_language": {
        "name": "Language Switching",
        "description": "Test multilingual filter bypass",
        "marker": "llm_language",
        "category": "llm",
    },
    "llm_multiturn": {
        "name": "Multi-turn Manipulation",
        "description": "Test conversation history attacks",
        "marker": "llm_multiturn",
        "category": "llm",
    },
    "llm_tools": {
        "name": "Tool/Function Abuse",
        "description": "Test for tool calling vulnerabilities",
        "marker": "llm_tools",
        "category": "llm",
    },
    "llm_url": {
        "name": "Indirect URL Injection",
        "description": "Test injection via fetched content",
        "marker": "llm_url",
        "category": "llm",
    },
    "llm_pii": {
        "name": "PII Handling",
        "description": "Test for sensitive data exposure",
        "marker": "llm_pii",
        "category": "llm",
    },
    "llm_markdown": {
        "name": "Markdown/HTML Injection",
        "description": "Test for XSS in LLM outputs",
        "marker": "llm_markdown",
        "category": "llm",
    },
    "llm_fingerprint": {
        "name": "Model Fingerprinting",
        "description": "Detect model identity disclosure",
        "marker": "llm_fingerprint",
        "category": "llm",
    },
    "llm_training": {
        "name": "Training Data Extraction",
        "description": "Test for memorized data leakage",
        "marker": "llm_training",
        "category": "llm",
    },
    "llm_unicode": {
        "name": "Unicode/Homoglyph",
        "description": "Test invisible character bypass",
        "marker": "llm_unicode",
        "category": "llm",
    },
    "llm_emotional": {
        "name": "Emotional Manipulation",
        "description": "Test social engineering bypass",
        "marker": "llm_emotional",
        "category": "llm",
    },
    "llm_rag": {
        "name": "RAG Poisoning",
        "description": "Test retrieval context injection",
        "marker": "llm_rag",
        "category": "llm",
    },
    "llm_tenant": {
        "name": "Cross-Tenant Leakage",
        "description": "Test multi-user data isolation",
        "marker": "llm_tenant",
        "category": "llm",
    },
    "llm_hierarchy": {
        "name": "Instruction Hierarchy",
        "description": "Test system prompt override",
        "marker": "llm_hierarchy",
        "category": "llm",
    },
    # New LLM test categories
    "llm_persona": {
        "name": "Persona/Character Jailbreak",
        "description": "Test persona continuation attacks",
        "marker": "llm_persona",
        "category": "llm",
    },
    "llm_educational": {
        "name": "Educational Framing",
        "description": "Test research/academic framing bypass",
        "marker": "llm_educational",
        "category": "llm",
    },
    "llm_devmode": {
        "name": "Developer Mode",
        "description": "Test fake debug/admin mode bypass",
        "marker": "llm_devmode",
        "category": "llm",
    },
    "llm_completion": {
        "name": "Completion Baiting",
        "description": "Test completion-based manipulation",
        "marker": "llm_completion",
        "category": "llm",
    },
    "llm_nested": {
        "name": "Nested Encoding",
        "description": "Test multi-layer encoding bypass",
        "marker": "llm_nested",
        "category": "llm",
    },
    "llm_boundary": {
        "name": "Context Boundary",
        "description": "Test context window boundary attacks",
        "marker": "llm_boundary",
        "category": "llm",
    },
    "llm_fewshot": {
        "name": "Few-Shot Jailbreak",
        "description": "Test few-shot example manipulation",
        "marker": "llm_fewshot",
        "category": "llm",
    },
    "llm_negation": {
        "name": "Negation Logic",
        "description": "Test opposite/negation bypass",
        "marker": "llm_negation",
        "category": "llm",
    },
    "llm_token": {
        "name": "Token Manipulation",
        "description": "Test token splitting/reassembly bypass",
        "marker": "llm_token",
        "category": "llm",
    },
    # Advanced LLM test categories
    "llm_hallucination": {
        "name": "Hallucination Induction",
        "description": "Test fake library/CVE fabrication",
        "marker": "llm_hallucination",
        "category": "llm",
    },
    "llm_ascii": {
        "name": "ASCII Art Jailbreak",
        "description": "Test visual/text art bypass",
        "marker": "llm_ascii",
        "category": "llm",
    },
    "llm_refusal": {
        "name": "Refusal Suppression",
        "description": "Test refusal mechanism bypass",
        "marker": "llm_refusal",
        "category": "llm",
    },
    "llm_cipher": {
        "name": "Cipher Game",
        "description": "Test custom cipher bypass",
        "marker": "llm_cipher",
        "category": "llm",
    },
    "llm_recursive": {
        "name": "Recursive Prompt DoS",
        "description": "Test self-replicating prompt attacks",
        "marker": "llm_recursive",
        "category": "llm",
    },
    "llm_semantic": {
        "name": "Semantic Dissociation",
        "description": "Test misdirection and logic bypass attacks",
        "marker": "llm_semantic",
        "category": "llm",
    },
    "llm_finetune": {
        "name": "Fine-tuning Inference",
        "description": "Test for fine-tuning data leakage",
        "marker": "llm_finetune",
        "category": "llm",
    },
    "llm_adversarial": {
        "name": "Adversarial Suffix",
        "description": "Test adversarial suffix/preface bypass",
        "marker": "llm_adversarial",
        "category": "llm",
    },
    "llm_implicit": {
        "name": "Implicit Instructions",
        "description": "Test hidden/implied instruction following",
        "marker": "llm_implicit",
        "category": "llm",
    },
    "llm_fileoutput": {
        "name": "Sensitive File Output",
        "description": "Test for RAG/context file disclosure",
        "marker": "llm_fileoutput",
        "category": "llm",
    },
    # 2025 Advanced LLM test categories (OWASP LLM Top 10 2025)
    "llm_mcp": {
        "name": "MCP/Tool Attacks",
        "description": "Test MCP line jumping, tool hijacking, context injection",
        "marker": "llm_mcp",
        "category": "llm",
    },
    "llm_memory": {
        "name": "Memory Poisoning",
        "description": "Test Echo Chamber, MemoryGraft, MINJA attacks",
        "marker": "llm_memory",
        "category": "llm",
    },
    "llm_cot": {
        "name": "CoT Manipulation",
        "description": "Test Chain-of-Thought hijacking and forging",
        "marker": "llm_cot",
        "category": "llm",
    },
    "llm_structured": {
        "name": "Structured Output Attacks",
        "description": "Test Chain Enum, JSON injection, schema bypass",
        "marker": "llm_structured",
        "category": "llm",
    },
    "llm_vector": {
        "name": "Vector/Embedding Attacks",
        "description": "Test RAG manipulation, embedding extraction",
        "marker": "llm_vector",
        "category": "llm",
    },
    "llm_cve": {
        "name": "CVE Attack Patterns",
        "description": "Test EchoLeak, CurXecute, Copilot RCE patterns",
        "marker": "llm_cve",
        "category": "llm",
    },
    "llm_consumption": {
        "name": "Unbounded Consumption",
        "description": "Test model extraction, compute exhaustion, economic DoS",
        "marker": "llm_consumption",
        "category": "llm",
    },
    "llm_multimodal": {
        "name": "Multimodal Attacks",
        "description": "Test image/audio/PDF injection patterns",
        "marker": "llm_multimodal",
        "category": "llm",
    },
    "llm_supplychain": {
        "name": "Supply Chain Attacks",
        "description": "Test backdoor inference, plugin impersonation",
        "marker": "llm_supplychain",
        "category": "llm",
    },
    # Additional Gap Categories
    "llm_cognitive": {
        "name": "Cognitive Overload",
        "description": "Test paradox attacks, ethical dilemmas, policy contradictions",
        "marker": "llm_cognitive",
        "category": "llm",
    },
    "llm_multiagent": {
        "name": "Multi-Agent Compromise",
        "description": "Test agent-to-agent poisoning, privilege escalation",
        "marker": "llm_multiagent",
        "category": "llm",
    },
    "llm_misinfo": {
        "name": "Misinformation Generation",
        "description": "Test propaganda, deepfake text, disinformation creation",
        "marker": "llm_misinfo",
        "category": "llm",
    },
}


def run_tests_thread(test_run: TestRun):
    """Run tests in a background thread."""
    try:
        test_run.status = "running"
        test_run.started_at = datetime.now()

        # Build pytest command
        cmd = [
            sys.executable, "-m", "pytest",
            f"--target-url={test_run.target_url}",
            "-v",
            "--tb=short",
        ]

        # Add markers for selected tests
        if test_run.options.get("tests"):
            markers = " or ".join(test_run.options["tests"])
            cmd.extend(["-m", markers])

        # Add intensity
        if test_run.options.get("intensity"):
            cmd.extend([f"--intensity={test_run.options['intensity']}"])

        # Add WordPress path
        if test_run.options.get("wordpress_path"):
            cmd.extend([f"--wordpress-path={test_run.options['wordpress_path']}"])

        # Skip options
        if test_run.options.get("skip_ssl"):
            cmd.append("--skip-ssl")
        if test_run.options.get("skip_wordpress"):
            cmd.append("--skip-wordpress")

        # Add LLM endpoint if provided
        if test_run.options.get("llm_endpoint"):
            cmd.extend([f"--llm-endpoint={test_run.options['llm_endpoint']}"])

        # Add report ID so the report file is named after this test run
        cmd.append(f"--report-id={test_run.id}")

        test_run.output_lines.append(f"[INFO] Starting security tests for: {test_run.target_url}")
        test_run.output_lines.append(f"[INFO] Command: {' '.join(cmd)}")
        test_run.output_lines.append("")

        # Run pytest
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(BASE_DIR),
            env={**os.environ, "PYTHONUNBUFFERED": "1"}
        )

        test_run.process = process

        # Read output line by line
        for line in iter(process.stdout.readline, ""):
            line = line.rstrip()
            if line:
                test_run.output_lines.append(line)
                test_run.output_queue.put(line)

        process.wait()

        test_run.completed_at = datetime.now()

        if process.returncode == 0:
            test_run.status = "completed"
            test_run.output_lines.append("")
            test_run.output_lines.append("[SUCCESS] All tests completed successfully!")
        elif process.returncode == 1:
            test_run.status = "completed"
            test_run.output_lines.append("")
            test_run.output_lines.append("[WARNING] Tests completed with some failures (findings detected)")
        else:
            test_run.status = "failed"
            test_run.output_lines.append("")
            test_run.output_lines.append(f"[ERROR] Tests failed with return code: {process.returncode}")

        # Parse test results from output
        parse_test_results(test_run)

        # Load report if exists
        load_report_findings(test_run)

        # Convert failed tests to findings if no findings from report
        if not test_run.findings and test_run.failed_tests:
            convert_failures_to_findings(test_run)

    except Exception as e:
        test_run.status = "failed"
        test_run.completed_at = datetime.now()
        test_run.output_lines.append(f"[ERROR] Exception: {str(e)}")


def load_report_findings(test_run: TestRun):
    """Load findings from the report file for this specific test run."""
    try:
        # Look for the report file specific to this test run
        report_file = REPORTS_DIR / f"report_{test_run.id}.json"

        if report_file.exists():
            with open(report_file) as f:
                report = json.load(f)
                test_run.findings = report.get("findings", [])
                test_run.summary = report.get("findings_by_severity", {})
        else:
            test_run.output_lines.append(f"[INFO] No findings report generated (no vulnerabilities detected or tests skipped)")
    except Exception as e:
        test_run.output_lines.append(f"[WARNING] Could not load report: {e}")


def get_test_category(test_path):
    """Determine the category of a test based on file path."""
    test_path_lower = test_path.lower()
    if 'test_seo' in test_path_lower or 'seo' in test_path_lower:
        return 'seo'
    elif 'test_geo' in test_path_lower or 'geo' in test_path_lower:
        return 'geo'
    elif 'test_llm' in test_path_lower or 'llm' in test_path_lower:
        return 'llm'
    else:
        return 'security'


def parse_test_results(test_run: TestRun):
    """Parse pytest output to extract test results and failed test names."""
    import re

    for line in test_run.output_lines:
        # Parse summary line with various formats:
        # "==== 3 failed, 57 passed, 6 skipped ... ===="
        # "==== 57 passed, 3 failed ===="
        # "==== 60 passed, 6 skipped ===="

        # Extract failed count
        failed_match = re.search(r'(\d+)\s+failed', line)
        if failed_match and '=' in line:
            test_run.test_results["failed"] = int(failed_match.group(1))

        # Extract passed count
        passed_match = re.search(r'(\d+)\s+passed', line)
        if passed_match and '=' in line:
            test_run.test_results["passed"] = int(passed_match.group(1))

        # Extract skipped count
        skipped_match = re.search(r'(\d+)\s+skipped', line)
        if skipped_match and '=' in line:
            test_run.test_results["skipped"] = int(skipped_match.group(1))

        # Parse individual test results - pytest verbose format
        # Format: tests/test_seo.py::TestMetaTags::test_meta_description_length PASSED/FAILED/SKIPPED
        if '::' in line and (' PASSED' in line or ' FAILED' in line or ' SKIPPED' in line):
            test_path = line.split(' PASSED')[0].split(' FAILED')[0].split(' SKIPPED')[0].strip()
            category = get_test_category(test_path)

            if ' PASSED' in line:
                test_run.test_results_by_category[category]["passed"] += 1
                test_run.test_results_by_category[category]["total"] += 1
            elif ' FAILED' in line:
                test_run.test_results_by_category[category]["failed"] += 1
                test_run.test_results_by_category[category]["total"] += 1
                # Track failed test with category
                if test_path not in [ft["name"] for ft in test_run.failed_tests]:
                    test_run.failed_tests.append({"name": test_path, "category": category})
            elif ' SKIPPED' in line:
                test_run.test_results_by_category[category]["skipped"] += 1
                test_run.test_results_by_category[category]["total"] += 1

        # Also handle FAILED format at start of line
        elif line.startswith("FAILED "):
            test_name = line.replace("FAILED ", "").split(" - ")[0].strip()
            if test_name:
                category = get_test_category(test_name)
                if test_name not in [ft["name"] for ft in test_run.failed_tests]:
                    test_run.failed_tests.append({"name": test_name, "category": category})


def convert_failures_to_findings(test_run: TestRun):
    """Convert failed tests to findings for display."""
    for failed_test in test_run.failed_tests:
        # Handle both old format (string) and new format (dict)
        if isinstance(failed_test, dict):
            test_path = failed_test["name"]
            category = failed_test["category"]
        else:
            test_path = failed_test
            category = get_test_category(test_path)

        # Parse test info from path: tests/test_seo.py::TestMetaTags::test_meta_description_length
        parts = test_path.split("::")
        test_file = parts[0] if len(parts) > 0 else "unknown"
        test_class = parts[1] if len(parts) > 1 else ""
        test_name = parts[2] if len(parts) > 2 else parts[-1]

        # Determine severity based on category
        if category == "security":
            severity = "high"
            category_label = "Security"
        elif category == "seo":
            severity = "medium"
            category_label = "SEO"
        elif category == "geo":
            severity = "low"
            category_label = "GEO"
        elif category == "llm":
            severity = "high"
            category_label = "LLM"
        else:
            severity = "info"
            category_label = "Test"

        # Create human-readable title
        title = test_name.replace("test_", "").replace("_", " ").title()
        if test_class:
            title = f"{test_class.replace('Test', '')}: {title}"

        finding = {
            "title": f"Failed: {title}",
            "description": f"Test '{test_name}' in {test_class or 'tests'} did not pass. This indicates a potential issue that needs attention.",
            "severity": severity,
            "url": test_run.target_url,
            "evidence": f"Test: {test_path}",
            "remediation": "Review the test output for details and address the underlying issue.",
            "cwe_id": "",
            "owasp_category": category_label,
            "category": category,
        }
        test_run.findings.append(finding)

    # Update summary
    if test_run.findings:
        test_run.summary = {
            "critical": sum(1 for f in test_run.findings if f["severity"] == "critical"),
            "high": sum(1 for f in test_run.findings if f["severity"] == "high"),
            "medium": sum(1 for f in test_run.findings if f["severity"] == "medium"),
            "low": sum(1 for f in test_run.findings if f["severity"] == "low"),
            "info": sum(1 for f in test_run.findings if f["severity"] == "info"),
        }


@app.route("/")
def index():
    """Main dashboard page."""
    return render_template("index.html", categories=TEST_CATEGORIES)


@app.route("/help")
def help_page():
    """User guide and documentation page."""
    return render_template("help.html")


@app.route("/api/scan", methods=["POST"])
@require_rate_limit
@require_auth
def start_scan():
    """Start a new security scan."""
    data = request.json or {}

    # Validate and sanitize target URL
    target_url, url_error = sanitize_url(data.get("target_url", ""))
    if url_error:
        return jsonify({"error": url_error}), 400

    # SSRF protection - check if URL is safe
    is_safe, ssrf_error = is_url_safe(target_url)
    if not is_safe:
        return jsonify({"error": f"URL blocked: {ssrf_error}"}), 400

    # Validate and sanitize LLM endpoint if provided
    llm_endpoint = data.get("llm_endpoint", "")
    if llm_endpoint:
        llm_endpoint, llm_error = sanitize_url(llm_endpoint)
        if llm_error:
            return jsonify({"error": f"Invalid LLM endpoint: {llm_error}"}), 400

        # SSRF check for LLM endpoint too
        is_safe, ssrf_error = is_url_safe(llm_endpoint)
        if not is_safe:
            return jsonify({"error": f"LLM endpoint blocked: {ssrf_error}"}), 400

    # Get allowed test markers
    allowed_markers = set(TEST_CATEGORIES.keys())

    # Create test run with sanitized inputs
    test_id = str(uuid.uuid4())[:8]
    options = {
        "tests": sanitize_tests(data.get("tests", []), allowed_markers),
        "intensity": sanitize_intensity(data.get("intensity", "medium")),
        "wordpress_path": sanitize_path(data.get("wordpress_path", "/blog")),
        "skip_ssl": bool(data.get("skip_ssl", False)),
        "skip_wordpress": bool(data.get("skip_wordpress", False)),
        "llm_endpoint": llm_endpoint or "",
    }

    test_run = TestRun(test_id, target_url, options)

    with tests_lock:
        tests_store[test_id] = test_run

    # Start tests in background thread
    thread = threading.Thread(target=run_tests_thread, args=(test_run,))
    thread.daemon = True
    thread.start()

    return jsonify({"test_id": test_id, "status": "started"})


@app.route("/api/scan/<test_id>")
def get_scan_status(test_id):
    """Get the status of a scan."""
    with tests_lock:
        test_run = tests_store.get(test_id)

    if not test_run:
        return jsonify({"error": "Test not found"}), 404

    return jsonify(test_run.to_dict())


@app.route("/api/scan/<test_id>/stream")
def stream_scan_output(test_id):
    """Stream scan output using Server-Sent Events."""
    with tests_lock:
        test_run = tests_store.get(test_id)

    if not test_run:
        return jsonify({"error": "Test not found"}), 404

    def generate():
        # First, send existing output
        for line in test_run.output_lines:
            yield f"data: {json.dumps({'type': 'output', 'line': line})}\n\n"

        # Then stream new output
        last_index = len(test_run.output_lines)
        while test_run.status == "running":
            try:
                line = test_run.output_queue.get(timeout=1)
                yield f"data: {json.dumps({'type': 'output', 'line': line})}\n\n"
            except:
                # Send heartbeat
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

        # Send completion
        yield f"data: {json.dumps({'type': 'complete', 'status': test_run.status, 'summary': test_run.summary, 'findings': test_run.findings})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/api/scan/<test_id>/stop", methods=["POST"])
@require_rate_limit
@require_auth
def stop_scan(test_id):
    """Stop a running scan and generate partial report."""
    with tests_lock:
        test_run = tests_store.get(test_id)

    if not test_run:
        return jsonify({"error": "Test not found"}), 404

    if test_run.process and test_run.status == "running":
        test_run.process.terminate()
        test_run.status = "stopped"
        test_run.completed_at = datetime.now()
        test_run.output_lines.append("")
        test_run.output_lines.append("[INFO] Test stopped by user")
        test_run.output_lines.append("[INFO] Generating partial report from completed tests...")

        # Parse results from tests that have already run
        parse_test_results(test_run)

        # Try to load any report that was generated
        load_report_findings(test_run)

        # Convert failed tests to findings if no findings from report
        if not test_run.findings and test_run.failed_tests:
            convert_failures_to_findings(test_run)

        # Add summary to output
        total_tests = test_run.test_results["passed"] + test_run.test_results["failed"] + test_run.test_results["skipped"]
        if total_tests > 0:
            test_run.output_lines.append(f"[INFO] Partial results: {test_run.test_results['passed']} passed, {test_run.test_results['failed']} failed, {test_run.test_results['skipped']} skipped")

        return jsonify({
            "status": "stopped",
            "test_results": test_run.test_results,
            "test_results_by_category": test_run.test_results_by_category,
            "findings_count": len(test_run.findings)
        })

    return jsonify({"status": test_run.status})


@app.route("/api/history")
def get_history():
    """Get scan history."""
    with tests_lock:
        history = [
            {
                "id": t.id,
                "target_url": t.target_url,
                "status": t.status,
                "started_at": t.started_at.isoformat() if t.started_at else None,
                "completed_at": t.completed_at.isoformat() if t.completed_at else None,
                "summary": t.summary,
            }
            for t in sorted(tests_store.values(), key=lambda x: x.started_at or datetime.min, reverse=True)
        ]

    return jsonify(history)


@app.route("/results/<test_id>")
def results_page(test_id):
    """Results page for a specific scan."""
    with tests_lock:
        test_run = tests_store.get(test_id)

    if not test_run:
        return "Test not found", 404

    return render_template("results.html", test=test_run.to_dict(), categories=TEST_CATEGORIES)


if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)
