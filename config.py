"""
SiteIQ Configuration

This module handles configuration for SiteIQ - Website Intelligence Platform.
Includes settings for Security, SEO, and GEO testing.
URL and other settings can be provided via environment variables,
command line arguments, or this config file.
"""

import os
from dataclasses import dataclass, field
from typing import Optional, List
from urllib.parse import urlparse


@dataclass
class SiteIQConfig:
    """Configuration for SiteIQ tests."""

    # ==========================================================================
    # GENERAL SETTINGS
    # ==========================================================================

    # Target URL (required) - set via SITEIQ_TARGET_URL env var or --target-url flag
    target_url: str = field(default_factory=lambda: os.getenv("SITEIQ_TARGET_URL", ""))

    # Test intensity: "light", "medium", "aggressive"
    intensity: str = field(default_factory=lambda: os.getenv("TEST_INTENSITY", "medium"))

    # Request timeout in seconds
    timeout: int = field(default_factory=lambda: int(os.getenv("REQUEST_TIMEOUT", "10")))

    # Delay between requests (seconds) - to avoid overwhelming the server
    request_delay: float = field(default_factory=lambda: float(os.getenv("REQUEST_DELAY", "0.5")))

    # User agent string
    user_agent: str = field(default_factory=lambda: os.getenv(
        "USER_AGENT",
        "SiteIQ/1.0 (Website Intelligence Platform)"
    ))

    # Authentication credentials (if needed)
    auth_username: Optional[str] = field(default_factory=lambda: os.getenv("AUTH_USERNAME"))
    auth_password: Optional[str] = field(default_factory=lambda: os.getenv("AUTH_PASSWORD"))

    # Report output directory
    report_dir: str = field(default_factory=lambda: os.getenv("REPORT_DIR", "reports"))

    # ==========================================================================
    # SECURITY TESTING SETTINGS
    # ==========================================================================

    # WordPress blog path (relative to target_url)
    wordpress_path: str = field(default_factory=lambda: os.getenv("WORDPRESS_PATH", "/blog"))

    # Maximum number of payloads to test per endpoint (for aggressive testing)
    max_payloads: int = field(default_factory=lambda: int(os.getenv("MAX_PAYLOADS", "50")))

    # Paths to skip during testing
    skip_paths: list = field(default_factory=lambda: os.getenv("SKIP_PATHS", "").split(",") if os.getenv("SKIP_PATHS") else [])

    # Enable/disable specific security test categories
    test_sql_injection: bool = field(default_factory=lambda: os.getenv("TEST_SQL_INJECTION", "true").lower() == "true")
    test_xss: bool = field(default_factory=lambda: os.getenv("TEST_XSS", "true").lower() == "true")
    test_csrf: bool = field(default_factory=lambda: os.getenv("TEST_CSRF", "true").lower() == "true")
    test_headers: bool = field(default_factory=lambda: os.getenv("TEST_HEADERS", "true").lower() == "true")
    test_ssl: bool = field(default_factory=lambda: os.getenv("TEST_SSL", "true").lower() == "true")
    test_wordpress: bool = field(default_factory=lambda: os.getenv("TEST_WORDPRESS", "true").lower() == "true")
    test_auth: bool = field(default_factory=lambda: os.getenv("TEST_AUTH", "true").lower() == "true")
    test_directories: bool = field(default_factory=lambda: os.getenv("TEST_DIRECTORIES", "true").lower() == "true")

    # ==========================================================================
    # SEO TESTING SETTINGS
    # ==========================================================================

    # Enable SEO testing
    test_seo: bool = field(default_factory=lambda: os.getenv("TEST_SEO", "true").lower() == "true")

    # Number of pages to crawl for SEO analysis (default: 2)
    seo_crawl_depth: int = field(default_factory=lambda: int(os.getenv("SEO_CRAWL_DEPTH", "2")))

    # Check external links for broken links
    seo_check_external_links: bool = field(default_factory=lambda: os.getenv("SEO_CHECK_EXTERNAL_LINKS", "true").lower() == "true")

    # Google PageSpeed API key (optional, for Core Web Vitals)
    seo_pagespeed_api_key: str = field(default_factory=lambda: os.getenv("PAGESPEED_API_KEY", ""))

    # Minimum acceptable scores (0-100)
    seo_min_title_length: int = field(default_factory=lambda: int(os.getenv("SEO_MIN_TITLE_LENGTH", "30")))
    seo_max_title_length: int = field(default_factory=lambda: int(os.getenv("SEO_MAX_TITLE_LENGTH", "60")))
    seo_min_description_length: int = field(default_factory=lambda: int(os.getenv("SEO_MIN_DESC_LENGTH", "120")))
    seo_max_description_length: int = field(default_factory=lambda: int(os.getenv("SEO_MAX_DESC_LENGTH", "160")))

    # ==========================================================================
    # GEO TESTING SETTINGS
    # ==========================================================================

    # Enable GEO testing
    test_geo: bool = field(default_factory=lambda: os.getenv("TEST_GEO", "true").lower() == "true")

    # GEO test mode: "headers" (default, free) or "proxy" (requires proxy service)
    geo_test_mode: str = field(default_factory=lambda: os.getenv("GEO_TEST_MODE", "headers"))

    # Proxy provider for geo testing: "brightdata", "oxylabs", "custom"
    geo_proxy_provider: str = field(default_factory=lambda: os.getenv("GEO_PROXY_PROVIDER", ""))

    # Custom proxy URL (if using custom provider)
    geo_proxy_url: str = field(default_factory=lambda: os.getenv("GEO_PROXY_URL", ""))

    # Proxy authentication
    geo_proxy_username: str = field(default_factory=lambda: os.getenv("GEO_PROXY_USERNAME", ""))
    geo_proxy_password: str = field(default_factory=lambda: os.getenv("GEO_PROXY_PASSWORD", ""))

    # Regions to test (comma-separated)
    geo_test_regions: List[str] = field(default_factory=lambda: os.getenv(
        "GEO_TEST_REGIONS",
        "us-east,us-west,uk,de,fr,jp,au,br"
    ).split(","))

    # ==========================================================================
    # INITIALIZATION
    # ==========================================================================

    def __post_init__(self):
        if self.target_url:
            # Ensure URL has scheme
            if not self.target_url.startswith(("http://", "https://")):
                self.target_url = f"https://{self.target_url}"
            # Remove trailing slash
            self.target_url = self.target_url.rstrip("/")

        # Clean up geo regions
        self.geo_test_regions = [r.strip() for r in self.geo_test_regions if r.strip()]

    # ==========================================================================
    # PROPERTIES
    # ==========================================================================

    @property
    def base_url(self) -> str:
        return self.target_url

    @property
    def wordpress_url(self) -> str:
        return f"{self.target_url}{self.wordpress_path}"

    @property
    def parsed_url(self):
        return urlparse(self.target_url)

    @property
    def hostname(self) -> str:
        return self.parsed_url.hostname or ""

    @property
    def has_pagespeed_api(self) -> bool:
        return bool(self.seo_pagespeed_api_key)

    @property
    def use_proxy_for_geo(self) -> bool:
        return self.geo_test_mode == "proxy" and bool(self.geo_proxy_url or self.geo_proxy_provider)

    # ==========================================================================
    # VALIDATION
    # ==========================================================================

    def validate(self) -> bool:
        """Validate configuration."""
        if not self.target_url:
            raise ValueError("target_url is required. Set SITEIQ_TARGET_URL environment variable or use --target-url flag")

        parsed = urlparse(self.target_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid URL format: {self.target_url}")

        if self.intensity not in ("light", "medium", "aggressive"):
            raise ValueError(f"Invalid intensity: {self.intensity}. Must be light, medium, or aggressive")

        if self.geo_test_mode not in ("headers", "proxy"):
            raise ValueError(f"Invalid geo_test_mode: {self.geo_test_mode}. Must be 'headers' or 'proxy'")

        return True


# ==========================================================================
# GLOBAL CONFIG & HELPERS
# ==========================================================================

# Global config instance - will be populated by pytest fixtures
config = SiteIQConfig()


def get_config() -> SiteIQConfig:
    """Get the current configuration."""
    return config


def set_target_url(url: str):
    """Set the target URL."""
    global config
    config.target_url = url
    config.__post_init__()


# ==========================================================================
# GEO REGION CONFIGURATIONS
# ==========================================================================

GEO_REGIONS = {
    "us-east": {
        "name": "US East (Virginia)",
        "language": "en-US",
        "accept_language": "en-US,en;q=0.9",
        "timezone": "America/New_York",
        "currency": "USD",
        "sample_ip": "54.210.0.1",  # AWS us-east
    },
    "us-west": {
        "name": "US West (California)",
        "language": "en-US",
        "accept_language": "en-US,en;q=0.9",
        "timezone": "America/Los_Angeles",
        "currency": "USD",
        "sample_ip": "54.183.0.1",  # AWS us-west
    },
    "uk": {
        "name": "United Kingdom",
        "language": "en-GB",
        "accept_language": "en-GB,en;q=0.9",
        "timezone": "Europe/London",
        "currency": "GBP",
        "sample_ip": "52.56.0.1",  # AWS eu-west-2
    },
    "de": {
        "name": "Germany",
        "language": "de-DE",
        "accept_language": "de-DE,de;q=0.9,en;q=0.8",
        "timezone": "Europe/Berlin",
        "currency": "EUR",
        "sample_ip": "52.59.0.1",  # AWS eu-central-1
    },
    "fr": {
        "name": "France",
        "language": "fr-FR",
        "accept_language": "fr-FR,fr;q=0.9,en;q=0.8",
        "timezone": "Europe/Paris",
        "currency": "EUR",
        "sample_ip": "52.47.0.1",  # AWS eu-west-3
    },
    "jp": {
        "name": "Japan",
        "language": "ja-JP",
        "accept_language": "ja-JP,ja;q=0.9,en;q=0.8",
        "timezone": "Asia/Tokyo",
        "currency": "JPY",
        "sample_ip": "52.68.0.1",  # AWS ap-northeast-1
    },
    "au": {
        "name": "Australia",
        "language": "en-AU",
        "accept_language": "en-AU,en;q=0.9",
        "timezone": "Australia/Sydney",
        "currency": "AUD",
        "sample_ip": "52.62.0.1",  # AWS ap-southeast-2
    },
    "br": {
        "name": "Brazil",
        "language": "pt-BR",
        "accept_language": "pt-BR,pt;q=0.9,en;q=0.8",
        "timezone": "America/Sao_Paulo",
        "currency": "BRL",
        "sample_ip": "52.67.0.1",  # AWS sa-east-1
    },
    "in": {
        "name": "India",
        "language": "en-IN",
        "accept_language": "en-IN,en;q=0.9,hi;q=0.8",
        "timezone": "Asia/Kolkata",
        "currency": "INR",
        "sample_ip": "52.66.0.1",  # AWS ap-south-1
    },
    "sg": {
        "name": "Singapore",
        "language": "en-SG",
        "accept_language": "en-SG,en;q=0.9,zh;q=0.8",
        "timezone": "Asia/Singapore",
        "currency": "SGD",
        "sample_ip": "52.74.0.1",  # AWS ap-southeast-1
    },
    "ae": {
        "name": "UAE",
        "language": "ar-AE",
        "accept_language": "ar-AE,ar;q=0.9,en;q=0.8",
        "timezone": "Asia/Dubai",
        "currency": "AED",
        "sample_ip": "3.28.0.1",  # AWS me-south-1
    },
    "ca": {
        "name": "Canada",
        "language": "en-CA",
        "accept_language": "en-CA,en;q=0.9,fr;q=0.8",
        "timezone": "America/Toronto",
        "currency": "CAD",
        "sample_ip": "52.60.0.1",  # AWS ca-central-1
    },
}


# Backwards compatibility alias
SecurityTestConfig = SiteIQConfig
