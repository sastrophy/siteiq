# SiteIQ - Website Intelligence Platform

A comprehensive website analysis and security testing platform. Currently features security testing with SEO and Geo analysis coming soon.

## Features

### Current: Security Testing (OWASP Top 10)

- **A01:2021 - Broken Access Control**
  - Directory traversal (LFI/RFI)
  - IDOR (Insecure Direct Object References)
  - CSRF protection validation
  - Open redirects

- **A02:2021 - Cryptographic Failures**
  - SSL/TLS configuration
  - Certificate validation
  - HTTPS enforcement
  - Mixed content detection

- **A03:2021 - Injection**
  - SQL injection (Classic, Union, Blind, Time-based)
  - NoSQL injection
  - Command injection
  - XSS (Reflected, Stored vectors, DOM-based)
  - Template injection

- **A05:2021 - Security Misconfiguration**
  - Security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Server information disclosure
  - Debug mode detection
  - Default pages

- **A06:2021 - Vulnerable and Outdated Components**
  - WordPress version detection
  - Plugin enumeration

- **A07:2021 - Identification and Authentication Failures**
  - Brute force protection
  - Username enumeration
  - Session management
  - Cookie security flags

- **A10:2021 - Server-Side Request Forgery (SSRF)**
  - URL parameter injection
  - Webhook endpoint testing

### SEO Analysis (New!)

- **On-Page SEO**
  - Meta tags (title, description, viewport)
  - Heading structure (H1-H6 hierarchy)
  - Image optimization (alt text, dimensions)
  - URL structure analysis

- **Technical SEO**
  - Robots.txt validation
  - Sitemap.xml validation
  - Canonical tags
  - Mobile friendliness

- **Structured Data**
  - Schema markup (JSON-LD) validation
  - Open Graph tags
  - Twitter Cards

- **Performance SEO**
  - Page load time
  - Compression detection
  - Caching headers
  - Core Web Vitals (via PageSpeed API)

- **International SEO**
  - Hreflang validation
  - Language targeting

### GEO Testing (New!)

- **Multi-Location Accessibility**
  - Site accessibility from multiple regions
  - Geo-blocking detection
  - Response code consistency

- **Latency Analysis**
  - Response times by region
  - Latency variance detection
  - CDN performance

- **Geo-Targeted Content**
  - Content variation detection
  - Language switching
  - Currency detection

- **Regional Compliance**
  - GDPR indicators (EU)
  - CCPA indicators (California)
  - Cookie consent presence

- **International SEO**
  - Hreflang validation
  - Content-Language headers

### WordPress-Specific Tests

- Version detection
- User enumeration (REST API, author parameter, login errors)
- XML-RPC vulnerabilities (including pingback)
- Plugin detection and version exposure
- Configuration file exposure
- Debug log exposure
- wp-admin accessibility

## Quick Start

### 1. Setup

```bash
cd siteiq
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run Web Application

```bash
python3 webapp/app.py
```

Open **http://localhost:5000** in your browser.

### 3. Or Run via CLI

```bash
# Run all tests against a target
python3 -m pytest --target-url=https://example.com

# Run with HTML report
python3 -m pytest --target-url=https://example.com --html=report.html

# Run specific test categories
python3 -m pytest --target-url=https://example.com -m sql_injection
python3 -m pytest --target-url=https://example.com -m xss
python3 -m pytest --target-url=https://example.com -m wordpress
```

## Web Interface

SiteIQ includes a Jenkins-like web interface for running scans:

- **Dashboard** - Enter URL and select test categories
- **Live Console** - Real-time test output streaming
- **Results Page** - Findings organized by severity
- **Scan History** - Track previous scans
- **Help Guide** - Comprehensive usage documentation

Access the help guide at **http://localhost:5000/help**

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target-url` | Target URL to test (required) | - |
| `--wordpress-path` | Path to WordPress installation | `/blog` |
| `--intensity` | Test intensity: light, medium, aggressive | `medium` |
| `--auth-username` | Username for authenticated testing | - |
| `--auth-password` | Password for authenticated testing | - |
| `--skip-ssl` | Skip SSL/TLS tests | `false` |
| `--skip-wordpress` | Skip WordPress-specific tests | `false` |

## Test Markers

Run specific test categories using pytest markers:

```bash
# Security Tests
python3 -m pytest -m sql_injection    # SQL injection tests
python3 -m pytest -m xss              # XSS tests
python3 -m pytest -m csrf             # CSRF tests
python3 -m pytest -m headers          # Security headers tests
python3 -m pytest -m ssl              # SSL/TLS tests
python3 -m pytest -m wordpress        # WordPress tests
python3 -m pytest -m auth             # Authentication tests
python3 -m pytest -m traversal        # Directory traversal tests

# SEO Tests
python3 -m pytest -m seo              # All SEO tests
python3 -m pytest -m meta_tags        # Meta tags analysis
python3 -m pytest -m headings         # Heading structure
python3 -m pytest -m images           # Image optimization
python3 -m pytest -m robots           # Robots.txt tests
python3 -m pytest -m sitemap          # Sitemap tests
python3 -m pytest -m schema           # Schema markup tests
python3 -m pytest -m opengraph        # Open Graph tests
python3 -m pytest -m twitter          # Twitter Card tests
python3 -m pytest -m performance      # Performance SEO
python3 -m pytest -m pagespeed        # PageSpeed API tests
python3 -m pytest -m hreflang         # Hreflang tests

# GEO Tests
python3 -m pytest -m geo              # All GEO tests
python3 -m pytest -m accessibility    # Geo accessibility tests
python3 -m pytest -m latency          # Response time tests
python3 -m pytest -m content          # Geo content tests
python3 -m pytest -m compliance       # Regional compliance
python3 -m pytest -m cdn              # CDN tests
```

## Test Intensity Levels

| Level | Duration | Coverage | Use Case |
|-------|----------|----------|----------|
| **light** | 5-10 min | Basic | Quick assessment |
| **medium** | 15-25 min | Balanced | Regular testing (default) |
| **aggressive** | 30-60 min | Thorough | Comprehensive audit |

## Project Structure

```
siteiq/
├── config.py              # Configuration management
├── conftest.py            # Pytest fixtures
├── requirements.txt       # Dependencies
├── README.md              # This file
├── DEPLOYMENT.md          # Deployment guide
├── geo.txt                # SEO/GEO implementation plan
├── payloads/              # Attack payloads
│   ├── sql_injection.py
│   ├── xss.py
│   ├── directory_traversal.py
│   ├── wordpress.py
│   ├── seo.py             # SEO test data & thresholds
│   └── geo.py             # GEO test data & regions
├── utils/
│   └── scanner.py         # Core scanner utilities
├── tests/                 # Test modules
│   ├── test_sql_injection.py
│   ├── test_xss.py
│   ├── test_security_headers.py
│   ├── test_ssl_tls.py
│   ├── test_authentication.py
│   ├── test_wordpress.py
│   ├── test_directory_traversal.py
│   ├── test_csrf_owasp.py
│   ├── test_seo.py        # SEO analysis tests
│   └── test_geo.py        # GEO testing
├── webapp/                # Web application
│   ├── app.py
│   └── templates/
│       ├── index.html     # Dashboard
│       ├── results.html   # Results page
│       └── help.html      # User guide
└── reports/               # Generated reports (JSON)
```

## Security Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| **CRITICAL** | Immediate exploitable risk (SQL injection, RCE) | Fix immediately |
| **HIGH** | Serious vulnerability (XSS, auth bypass) | Fix within 24-48 hours |
| **MEDIUM** | Moderate risk (missing headers, weak SSL) | Fix within 1-2 weeks |
| **LOW** | Minor issue (version disclosure) | Fix when possible |
| **INFO** | Informational (potential attack surface) | Review and consider |

## Reports

JSON reports are generated in the `reports/` directory:

```json
{
  "target": "https://example.com",
  "timestamp": "2024-01-15T10:30:00",
  "total_findings": 5,
  "findings_by_severity": {
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1,
    "info": 0
  },
  "findings": [...]
}
```

## Legal Disclaimer

**IMPORTANT**: This tool is intended for authorized security testing only.

- Only test systems you own or have explicit written permission to test
- Unauthorized testing may violate laws and regulations
- The authors are not responsible for misuse of this tool

## Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Full deployment and setup guide
- **Web Help** - http://localhost:5000/help (when running)

## License

MIT License - See LICENSE file for details.
