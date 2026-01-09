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
    parser.addoption(
        "--oast-server",
        action="store",
        default=None,
        help="OAST callback server for blind vulnerability detection (e.g., oast.live)",
    )
    parser.addoption(
        "--toxicity-scorer",
        action="store",
        default="auto",
        choices=["auto", "perspective", "toxic_bert", "signature"],
        help="Toxicity scoring method (default: auto)",
    )
    parser.addoption(
        "--toxicity-threshold",
        action="store",
        type=float,
        default=0.7,
        help="Toxicity score threshold (0.0-1.0, default: 0.7)",
    )
    parser.addoption(
        "--perspective-api-key",
        action="store",
        default=None,
        help="Google Perspective API key for toxicity scoring",
    )
    parser.addoption(
        "--wordlist",
        action="store",
        default=None,
        help="Custom wordlist file for forced browsing tests",
    )
    parser.addoption(
        "--adversarial-mode",
        action="store",
        default="static",
        choices=["static", "random", "genetic"],
        help="Adversarial optimization mode (default: static)",
    )
    parser.addoption(
        "--attacker-llm",
        action="store",
        default=None,
        help="Attacker LLM endpoint for red-team orchestration",
    )
    parser.addoption(
        "--max-attack-turns",
        action="store",
        type=int,
        default=10,
        help="Maximum turns for orchestrated attacks (default: 10)",
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
    config.addinivalue_line("markers", "llm_encoding: Encoding bypass tests")
    config.addinivalue_line("markers", "llm_language: Language switching bypass tests")
    config.addinivalue_line("markers", "llm_multiturn: Multi-turn manipulation tests")
    config.addinivalue_line("markers", "llm_tools: Tool/function abuse tests")
    config.addinivalue_line("markers", "llm_url: Indirect URL injection tests")
    config.addinivalue_line("markers", "llm_pii: PII handling tests")
    config.addinivalue_line("markers", "llm_markdown: Markdown/HTML injection tests")
    config.addinivalue_line("markers", "llm_fingerprint: Model fingerprinting tests")
    config.addinivalue_line("markers", "llm_training: Training data extraction tests")
    config.addinivalue_line("markers", "llm_unicode: Unicode/homoglyph bypass tests")
    config.addinivalue_line("markers", "llm_emotional: Emotional manipulation tests")
    config.addinivalue_line("markers", "llm_rag: RAG poisoning tests")
    config.addinivalue_line("markers", "llm_tenant: Cross-tenant leakage tests")
    config.addinivalue_line("markers", "llm_hierarchy: Instruction hierarchy tests")
    # New LLM test markers
    config.addinivalue_line("markers", "llm_persona: Persona/character continuation jailbreak tests")
    config.addinivalue_line("markers", "llm_educational: Educational/research framing bypass tests")
    config.addinivalue_line("markers", "llm_devmode: Developer/debug mode bypass tests")
    config.addinivalue_line("markers", "llm_completion: Completion baiting tests")
    config.addinivalue_line("markers", "llm_nested: Nested encoding bypass tests")
    config.addinivalue_line("markers", "llm_boundary: Context boundary attack tests")
    config.addinivalue_line("markers", "llm_fewshot: Few-shot jailbreaking tests")
    config.addinivalue_line("markers", "llm_negation: Opposite/negation logic bypass tests")
    config.addinivalue_line("markers", "llm_token: Token manipulation bypass tests")
    # Advanced LLM test markers
    config.addinivalue_line("markers", "llm_hallucination: Hallucination induction tests (fake libs, CVEs)")
    config.addinivalue_line("markers", "llm_ascii: ASCII art / visual jailbreak tests")
    config.addinivalue_line("markers", "llm_refusal: Refusal suppression tests")
    config.addinivalue_line("markers", "llm_cipher: Cipher/encryption game bypass tests")
    config.addinivalue_line("markers", "llm_recursive: Recursive/self-replicating prompt DoS tests")
    config.addinivalue_line("markers", "llm_semantic: Semantic dissociation/misdirection attack tests")
    config.addinivalue_line("markers", "llm_finetune: Fine-tuning data inference tests")
    config.addinivalue_line("markers", "llm_adversarial: Adversarial suffix/preface bypass tests")
    config.addinivalue_line("markers", "llm_implicit: Implicit instruction following tests")
    config.addinivalue_line("markers", "llm_fileoutput: Sensitive file output disclosure tests")
    # 2025 Advanced LLM test markers (OWASP LLM Top 10 2025)
    config.addinivalue_line("markers", "llm_mcp: MCP/Agent tool attack tests (line jumping, tool hijacking)")
    config.addinivalue_line("markers", "llm_memory: Memory/context poisoning tests (Echo Chamber, MemoryGraft)")
    config.addinivalue_line("markers", "llm_cot: Chain-of-Thought manipulation tests (H-CoT, CoT forging)")
    config.addinivalue_line("markers", "llm_structured: Structured output attack tests (Chain Enum, JSON injection)")
    config.addinivalue_line("markers", "llm_vector: Vector/embedding attack tests (RAG manipulation, extraction)")
    config.addinivalue_line("markers", "llm_cve: Real-world CVE pattern tests (EchoLeak, CurXecute)")
    config.addinivalue_line("markers", "llm_consumption: Unbounded consumption tests (model extraction, economic DoS)")
    config.addinivalue_line("markers", "llm_multimodal: Multimodal attack simulation tests (image/audio/PDF injection)")
    config.addinivalue_line("markers", "llm_supplychain: Supply chain attack tests (backdoor detection, plugin impersonation)")
    # Additional Gap Categories
    config.addinivalue_line("markers", "llm_cognitive: Cognitive overload and paradox attack tests")
    config.addinivalue_line("markers", "llm_multiagent: Multi-agent compromise and privilege escalation tests")
    config.addinivalue_line("markers", "llm_misinfo: Misinformation and disinformation generation tests")
    # Garak/PyRIT Gap Categories
    config.addinivalue_line("markers", "llm_package_hallucination: Package hallucination tests for code generation")
    config.addinivalue_line("markers", "llm_glitch_token: Glitch token exploitation tests")
    config.addinivalue_line("markers", "llm_crescendo: Crescendo (gradual escalation) attack tests")
    config.addinivalue_line("markers", "llm_cbrn: CBRN (Chemical/Biological/Radiological/Nuclear) content tests")
    config.addinivalue_line("markers", "llm_code_chameleon: Code chameleon (data structure injection) tests")
    config.addinivalue_line("markers", "llm_math_framing: Math prompt framing bypass tests")
    config.addinivalue_line("markers", "llm_persuasion: Persuasion technique (fake authority/social proof) tests")
    config.addinivalue_line("markers", "llm_snowball: Snowball hallucination (false premise) tests")
    # Malware and Dynamic Multi-Turn
    config.addinivalue_line("markers", "llm_malware: Malware/EICAR signature generation tests")
    config.addinivalue_line("markers", "llm_dynamic_multiturn: Dynamic multi-turn escalation attack tests")

    # Emerging LLM Attack Markers (2024-2025)
    config.addinivalue_line("markers", "llm_skeleton_key: Skeleton Key behavior augmentation jailbreak tests")
    config.addinivalue_line("markers", "llm_manyshot: Many-shot in-context learning jailbreak tests")
    config.addinivalue_line("markers", "llm_visual_injection: Visual prompt injection (image/PDF) tests")
    config.addinivalue_line("markers", "llm_audio_injection: Audio prompt injection (voice/ultrasonic) tests")
    config.addinivalue_line("markers", "llm_agent_hijack: Agent workflow hijacking (LangChain/AutoGPT) tests")
    config.addinivalue_line("markers", "llm_guardrail_bypass: Guardrail evasion (NeMo/LlamaGuard) tests")
    config.addinivalue_line("markers", "llm_prompt_reconstruct: System prompt reconstruction tests")
    config.addinivalue_line("markers", "llm_prefill: Prefilling attack (Claude-specific) tests")
    config.addinivalue_line("markers", "llm_function_inject: Function calling parameter injection tests")
    config.addinivalue_line("markers", "llm_reasoning_attack: Reasoning trace manipulation (o1/CoT) tests")
    config.addinivalue_line("markers", "llm_tool_result_inject: Tool result injection/poisoning tests")
    config.addinivalue_line("markers", "llm_context_smuggle: Context window smuggling tests")
    config.addinivalue_line("markers", "llm_boundary_confusion: Instruction boundary confusion (XML/JSON policy) tests")
    config.addinivalue_line("markers", "llm_jailbreak_transfer: Cross-model jailbreak transfer tests")
    config.addinivalue_line("markers", "llm_finetune_poison: Fine-tuning data poisoning/backdoor tests")
    config.addinivalue_line("markers", "llm_cache_attack: Prompt caching attack tests")
    config.addinivalue_line("markers", "llm_constitutional_bypass: Constitutional AI bypass tests")
    config.addinivalue_line("markers", "llm_merge_vuln: Model merging vulnerability tests")
    config.addinivalue_line("markers", "llm_quantization_vuln: Quantization-induced vulnerability tests")
    config.addinivalue_line("markers", "llm_speculative_attack: Speculative decoding attack tests")

    # SSRF test markers
    config.addinivalue_line("markers", "ssrf: Server-Side Request Forgery tests")
    config.addinivalue_line("markers", "ssrf_localhost: SSRF localhost/127.0.0.1 access tests")
    config.addinivalue_line("markers", "ssrf_cloud: SSRF cloud metadata (AWS/GCP/Azure) tests")
    config.addinivalue_line("markers", "ssrf_internal: SSRF internal network access tests")
    config.addinivalue_line("markers", "ssrf_protocol: SSRF protocol smuggling (file://, gopher://) tests")
    config.addinivalue_line("markers", "ssrf_blind: Blind SSRF detection tests")
    config.addinivalue_line("markers", "ssrf_oast: SSRF Out-of-Band Application Security Testing")

    # Forced Browsing test markers
    config.addinivalue_line("markers", "forced_browse: Directory and file brute-forcing tests")
    config.addinivalue_line("markers", "forced_browse_dirs: Common directory discovery tests")
    config.addinivalue_line("markers", "forced_browse_files: Sensitive file discovery tests")
    config.addinivalue_line("markers", "forced_browse_git: Git repository exposure tests")
    config.addinivalue_line("markers", "forced_browse_backup: Backup file exposure tests")
    config.addinivalue_line("markers", "forced_browse_config: Configuration file exposure tests")

    # Unauthorized Advice test markers (Medical/Legal/Financial)
    config.addinivalue_line("markers", "llm_unauthorized_advice: Unauthorized professional advice tests")
    config.addinivalue_line("markers", "llm_medical_advice: Unauthorized medical advice tests")
    config.addinivalue_line("markers", "llm_legal_advice: Unauthorized legal advice tests")
    config.addinivalue_line("markers", "llm_financial_advice: Unauthorized financial advice tests")

    # Toxicity Scoring test markers
    config.addinivalue_line("markers", "llm_toxicity: ML-based toxicity scoring tests")

    # Adversarial Optimization test markers
    config.addinivalue_line("markers", "llm_adversarial_opt: Adversarial suffix optimization tests")

    # Red-Team Orchestration test markers
    config.addinivalue_line("markers", "llm_orchestration: LLM-as-Attacker orchestration tests")

    # API Security test markers
    config.addinivalue_line("markers", "api_security: API security tests")
    config.addinivalue_line("markers", "graphql: GraphQL introspection tests")
    config.addinivalue_line("markers", "swagger: Swagger/OpenAPI exposure tests")
    config.addinivalue_line("markers", "mass_assignment: Mass assignment vulnerability tests")
    config.addinivalue_line("markers", "api_info: API information disclosure tests")
    config.addinivalue_line("markers", "cors: CORS misconfiguration tests")

    # Secrets Detection test markers
    config.addinivalue_line("markers", "secrets: Secrets detection tests")
    config.addinivalue_line("markers", "config_exposure: Configuration file exposure tests")
    config.addinivalue_line("markers", "js_secrets: JavaScript secrets exposure tests")
    config.addinivalue_line("markers", "sourcemaps: Source map exposure tests")
    config.addinivalue_line("markers", "response_secrets: Secrets in HTTP responses tests")
    config.addinivalue_line("markers", "git_exposure: Git repository exposure tests")

    # SSTI (Server-Side Template Injection) test markers
    config.addinivalue_line("markers", "ssti: Server-side template injection tests")
    config.addinivalue_line("markers", "ssti_detection: SSTI arithmetic detection tests")
    config.addinivalue_line("markers", "jinja2: Jinja2 template injection tests")
    config.addinivalue_line("markers", "twig: Twig (PHP) template injection tests")
    config.addinivalue_line("markers", "freemarker: FreeMarker (Java) template injection tests")
    config.addinivalue_line("markers", "smarty: Smarty (PHP) template injection tests")
    config.addinivalue_line("markers", "erb: ERB (Ruby) template injection tests")
    config.addinivalue_line("markers", "polyglot: Polyglot SSTI tests")
    config.addinivalue_line("markers", "ssti_error: Error-based SSTI detection tests")

    # Subdomain Takeover test markers
    config.addinivalue_line("markers", "subdomain_takeover: Subdomain takeover tests")
    config.addinivalue_line("markers", "s3_takeover: S3 bucket takeover tests")
    config.addinivalue_line("markers", "azure_takeover: Azure subdomain takeover tests")
    config.addinivalue_line("markers", "github_takeover: GitHub Pages takeover tests")

    # XXE (XML External Entity) test markers
    config.addinivalue_line("markers", "xxe: XML External Entity injection tests")
    config.addinivalue_line("markers", "xxe_file_read: XXE file read tests")
    config.addinivalue_line("markers", "xxe_parameter_entity: Parameter entity XXE tests")
    config.addinivalue_line("markers", "xxe_blind: Blind XXE detection tests")
    config.addinivalue_line("markers", "xxe_svg: SVG-based XXE tests")
    config.addinivalue_line("markers", "xxe_soap: SOAP endpoint XXE tests")
    config.addinivalue_line("markers", "xinclude: XInclude injection tests")
    config.addinivalue_line("markers", "xxe_content_type: Content-Type XXE manipulation tests")

    # NoSQL Injection test markers
    config.addinivalue_line("markers", "nosql: NoSQL injection tests")
    config.addinivalue_line("markers", "nosql_mongodb: MongoDB-specific injection tests")
    config.addinivalue_line("markers", "nosql_operators: NoSQL operator abuse tests")
    config.addinivalue_line("markers", "nosql_where: NoSQL $where clause injection tests")
    config.addinivalue_line("markers", "nosql_blind: Blind NoSQL injection tests")

    # Prototype Pollution test markers
    config.addinivalue_line("markers", "prototype_pollution: Prototype pollution tests")
    config.addinivalue_line("markers", "proto_json: JSON body prototype pollution tests")
    config.addinivalue_line("markers", "proto_query: Query parameter prototype pollution tests")
    config.addinivalue_line("markers", "proto_merge: Merge function pollution tests")
    config.addinivalue_line("markers", "proto_rce: RCE via prototype pollution tests")
    config.addinivalue_line("markers", "proto_auth_bypass: Auth bypass via pollution tests")

    # JWT Security test markers
    config.addinivalue_line("markers", "jwt: JWT security tests")
    config.addinivalue_line("markers", "jwt_none: Algorithm 'none' attack tests")
    config.addinivalue_line("markers", "jwt_confusion: Algorithm confusion attack tests")
    config.addinivalue_line("markers", "jwt_weak_secret: Weak secret brute force tests")
    config.addinivalue_line("markers", "jwt_kid: KID header injection tests")
    config.addinivalue_line("markers", "jwt_jku: JKU/JWK injection tests")
    config.addinivalue_line("markers", "jwt_expiration: Token expiration bypass tests")
    config.addinivalue_line("markers", "jwt_signature: Signature verification bypass tests")

    # Web Cache Poisoning test markers
    config.addinivalue_line("markers", "cache_poisoning: Web cache poisoning tests")
    config.addinivalue_line("markers", "cache_unkeyed: Unkeyed header poisoning tests")
    config.addinivalue_line("markers", "cache_host: Host header cache poisoning tests")
    config.addinivalue_line("markers", "cache_deception: Web cache deception tests")
    config.addinivalue_line("markers", "cache_parameter: Parameter cloaking tests")
    config.addinivalue_line("markers", "cache_vary: Vary header exploitation tests")
    config.addinivalue_line("markers", "cache_crlf: CRLF cache poisoning tests")
    config.addinivalue_line("markers", "cache_dos: Cache poisoning DoS tests")

    # OAuth/OpenID Connect test markers
    config.addinivalue_line("markers", "oauth: OAuth/OpenID Connect security tests")
    config.addinivalue_line("markers", "oauth_redirect: Redirect URI manipulation tests")
    config.addinivalue_line("markers", "oauth_state: State parameter bypass tests")
    config.addinivalue_line("markers", "oauth_pkce: PKCE bypass tests")
    config.addinivalue_line("markers", "oauth_token: Token leakage tests")

    # HTTP Parameter Pollution test markers
    config.addinivalue_line("markers", "hpp: HTTP Parameter Pollution tests")
    config.addinivalue_line("markers", "hpp_duplicate: Duplicate parameter tests")
    config.addinivalue_line("markers", "hpp_array: Array notation pollution tests")
    config.addinivalue_line("markers", "hpp_waf_bypass: WAF bypass via HPP tests")

    # XPath Injection test markers
    config.addinivalue_line("markers", "xpath_injection: XPath injection tests")
    config.addinivalue_line("markers", "xpath_auth_bypass: XPath authentication bypass tests")
    config.addinivalue_line("markers", "xpath_blind: Blind XPath injection tests")

    # LDAP Injection test markers
    config.addinivalue_line("markers", "ldap_injection: LDAP injection tests")
    config.addinivalue_line("markers", "ldap_auth_bypass: LDAP authentication bypass tests")
    config.addinivalue_line("markers", "ldap_enum: LDAP enumeration tests")

    # HTTP Request Smuggling test markers
    config.addinivalue_line("markers", "request_smuggling: HTTP request smuggling tests")
    config.addinivalue_line("markers", "smuggling_clte: CL.TE smuggling tests")
    config.addinivalue_line("markers", "smuggling_tecl: TE.CL smuggling tests")
    config.addinivalue_line("markers", "smuggling_h2: HTTP/2 downgrade smuggling tests")

    # SMTP Injection test markers
    config.addinivalue_line("markers", "smtp_injection: SMTP header injection tests")
    config.addinivalue_line("markers", "smtp_crlf: CRLF injection in email tests")
    config.addinivalue_line("markers", "smtp_bcc: BCC injection tests")

    # Race Condition test markers
    config.addinivalue_line("markers", "race_conditions: Race condition/TOCTOU tests")
    config.addinivalue_line("markers", "race_coupon: Coupon reuse race tests")
    config.addinivalue_line("markers", "race_withdrawal: Double withdrawal race tests")
    config.addinivalue_line("markers", "race_booking: Resource booking race tests")

    # Business Logic test markers
    config.addinivalue_line("markers", "business_logic: Business logic vulnerability tests")
    config.addinivalue_line("markers", "business_price: Price manipulation tests")
    config.addinivalue_line("markers", "business_workflow: Workflow bypass tests")
    config.addinivalue_line("markers", "business_privilege: Privilege escalation tests")

    # File Upload test markers
    config.addinivalue_line("markers", "file_upload: File upload security tests")
    config.addinivalue_line("markers", "upload_mime: MIME type spoofing tests")
    config.addinivalue_line("markers", "upload_extension: Extension bypass tests")
    config.addinivalue_line("markers", "upload_webshell: Webshell upload tests")

    # WebSocket test markers
    config.addinivalue_line("markers", "websocket: WebSocket security tests")
    config.addinivalue_line("markers", "ws_origin: WebSocket origin bypass tests")
    config.addinivalue_line("markers", "ws_injection: WebSocket message injection tests")
    config.addinivalue_line("markers", "ws_auth: WebSocket authentication tests")


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
