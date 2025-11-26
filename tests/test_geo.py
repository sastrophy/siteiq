"""
SiteIQ GEO Tests - Geographic Testing Module

Tests for multi-location accessibility, geo-targeted content,
regional compliance, and latency measurements.
"""

import pytest
import time
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup

from config import get_config, GEO_REGIONS
from payloads.geo import (
    GEO_HEADERS, REGION_INFO,
    COMPLIANCE_CHECKS, GDPR_INDICATORS, CCPA_INDICATORS,
    CURRENCY_PATTERNS, LANGUAGE_INDICATORS,
    PERFORMANCE_THRESHOLDS, MAX_RESPONSE_TIME_VARIANCE,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def geo_regions():
    """Get configured geo test regions."""
    config = get_config()
    return config.geo_test_regions


@pytest.fixture
def region_responses(scanner, geo_regions):
    """Fetch responses from multiple regions using header simulation."""
    config = get_config()
    responses = {}

    for region in geo_regions:
        if region not in GEO_HEADERS:
            continue

        headers = GEO_HEADERS[region].copy()
        headers["User-Agent"] = config.user_agent

        try:
            start_time = time.time()
            response = scanner.get(config.target_url, headers=headers)
            response_time = time.time() - start_time

            responses[region] = {
                "response": response,
                "response_time": response_time,
                "status_code": response.status_code,
                "content": response.text,
                "headers": dict(response.headers),
            }
        except Exception as e:
            responses[region] = {
                "error": str(e),
                "response_time": None,
            }

        time.sleep(config.request_delay)

    return responses


# =============================================================================
# MULTI-LOCATION ACCESSIBILITY TESTS
# =============================================================================

@pytest.mark.geo
@pytest.mark.accessibility
class TestGeoAccessibility:
    """Test site accessibility from multiple geographic locations."""

    def test_site_accessible_from_all_regions(self, region_responses, geo_regions):
        """Check if site is accessible from all configured regions."""
        inaccessible = []

        for region in geo_regions:
            if region not in region_responses:
                continue

            resp = region_responses[region]
            if "error" in resp:
                inaccessible.append(f"{region}: {resp['error']}")
            elif resp["status_code"] >= 400:
                inaccessible.append(f"{region}: HTTP {resp['status_code']}")

        if inaccessible:
            pytest.fail(f"Site not accessible from: {inaccessible}")

        print(f"INFO: Site accessible from all {len(region_responses)} tested regions")

    def test_no_geo_blocking(self, region_responses, geo_regions):
        """Check if site blocks any geographic regions."""
        blocked = []
        block_indicators = [
            "access denied",
            "not available in your region",
            "geo-blocked",
            "country not supported",
            "unavailable in your location",
            "403",
            "restricted",
        ]

        for region in geo_regions:
            if region not in region_responses:
                continue

            resp = region_responses[region]
            if "error" in resp:
                continue

            content_lower = resp["content"].lower()

            # Check for 403 status
            if resp["status_code"] == 403:
                blocked.append(region)
                continue

            # Check for block indicators in content
            for indicator in block_indicators:
                if indicator in content_lower:
                    blocked.append(f"{region} ('{indicator}' detected)")
                    break

        if blocked:
            print(f"WARNING: Potential geo-blocking detected: {blocked}")

    def test_consistent_response_codes(self, region_responses, geo_regions):
        """Check if response codes are consistent across regions."""
        status_codes = {}

        for region in geo_regions:
            if region not in region_responses or "error" in region_responses[region]:
                continue

            code = region_responses[region]["status_code"]
            if code not in status_codes:
                status_codes[code] = []
            status_codes[code].append(region)

        if len(status_codes) > 1:
            print(f"INFO: Different response codes across regions: {status_codes}")


# =============================================================================
# RESPONSE TIME TESTS
# =============================================================================

@pytest.mark.geo
@pytest.mark.latency
class TestGeoLatency:
    """Test response times from different geographic locations."""

    def test_response_times_acceptable(self, region_responses, geo_regions):
        """Check if response times are acceptable from all regions."""
        slow_regions = []

        for region in geo_regions:
            if region not in region_responses or region_responses[region].get("response_time") is None:
                continue

            resp_time = region_responses[region]["response_time"]

            if resp_time > PERFORMANCE_THRESHOLDS["response_time_poor"]:
                slow_regions.append(f"{region}: {resp_time:.2f}s (poor)")
            elif resp_time > PERFORMANCE_THRESHOLDS["response_time_acceptable"]:
                slow_regions.append(f"{region}: {resp_time:.2f}s (slow)")

        if slow_regions:
            print(f"WARNING: Slow regions detected: {slow_regions}")

    def test_response_time_variance(self, region_responses, geo_regions):
        """Check for large variance in response times between regions."""
        times = {}

        for region in geo_regions:
            if region not in region_responses or region_responses[region].get("response_time") is None:
                continue

            times[region] = region_responses[region]["response_time"]

        if len(times) < 2:
            pytest.skip("Not enough regions to compare")

        min_time = min(times.values())
        max_time = max(times.values())
        variance = max_time - min_time

        print(f"INFO: Response time range: {min_time:.2f}s - {max_time:.2f}s (variance: {variance:.2f}s)")

        if variance > MAX_RESPONSE_TIME_VARIANCE:
            slowest = max(times, key=times.get)
            fastest = min(times, key=times.get)
            print(
                f"WARNING: Large latency variance detected. "
                f"Fastest: {fastest} ({times[fastest]:.2f}s), "
                f"Slowest: {slowest} ({times[slowest]:.2f}s)"
            )

    def test_response_times_by_region(self, region_responses, geo_regions):
        """Display response times by region."""
        times = []

        for region in geo_regions:
            if region not in region_responses or region_responses[region].get("response_time") is None:
                continue

            region_name = REGION_INFO.get(region, {}).get("name", region)
            resp_time = region_responses[region]["response_time"]
            times.append(f"{region_name}: {resp_time:.2f}s")

        if times:
            print(f"Response times by region: {', '.join(times)}")


# =============================================================================
# GEO-TARGETED CONTENT TESTS
# =============================================================================

@pytest.mark.geo
@pytest.mark.content
class TestGeoContent:
    """Test geo-targeted content variations."""

    def test_content_variation_detection(self, region_responses, geo_regions):
        """Detect if content varies by region."""
        contents = {}

        for region in geo_regions:
            if region not in region_responses or "error" in region_responses[region]:
                continue

            # Get text content length and hash as simple comparison
            content = region_responses[region]["content"]
            content_len = len(content)
            contents[region] = content_len

        if len(contents) < 2:
            pytest.skip("Not enough regions to compare")

        # Check for significant content size differences
        sizes = list(contents.values())
        avg_size = sum(sizes) / len(sizes)
        significant_diff = []

        for region, size in contents.items():
            diff_percent = abs(size - avg_size) / avg_size * 100
            if diff_percent > 10:  # More than 10% difference
                significant_diff.append(f"{region}: {diff_percent:.1f}% different")

        if significant_diff:
            print(f"INFO: Content size variations detected: {significant_diff}")

    def test_language_switching(self, region_responses, geo_regions):
        """Check if site auto-switches language based on region."""
        detected_languages = {}

        for region in geo_regions:
            if region not in region_responses or "error" in region_responses[region]:
                continue

            content = region_responses[region]["content"].lower()
            soup = BeautifulSoup(content, "html.parser")

            # Check html lang attribute
            html_tag = soup.find("html")
            if html_tag and html_tag.get("lang"):
                detected_languages[region] = html_tag.get("lang")
            else:
                # Try to detect language from content
                for lang, indicators in LANGUAGE_INDICATORS.items():
                    matches = sum(1 for ind in indicators if ind in content)
                    if matches >= 3:
                        detected_languages[region] = f"{lang} (detected)"
                        break

        if detected_languages:
            unique_languages = set(detected_languages.values())
            if len(unique_languages) > 1:
                print(f"INFO: Multiple languages detected: {detected_languages}")
            else:
                print(f"INFO: Same language across regions: {list(unique_languages)[0]}")

    def test_currency_detection(self, region_responses, geo_regions):
        """Check for region-specific currency display."""
        detected_currencies = {}

        for region in geo_regions:
            if region not in region_responses or "error" in region_responses[region]:
                continue

            content = region_responses[region]["content"]
            expected_currency = REGION_INFO.get(region, {}).get("currency")

            # Look for currency patterns
            found_currencies = []
            for currency, patterns in CURRENCY_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content):
                        found_currencies.append(currency)
                        break

            if found_currencies:
                detected_currencies[region] = list(set(found_currencies))

        if detected_currencies:
            print(f"INFO: Currencies detected by region: {detected_currencies}")


# =============================================================================
# REGIONAL COMPLIANCE TESTS
# =============================================================================

@pytest.mark.geo
@pytest.mark.compliance
class TestGeoCompliance:
    """Test regional compliance (GDPR, CCPA, etc.)."""

    def test_gdpr_compliance_for_eu(self, region_responses, geo_regions):
        """Check for GDPR compliance indicators for EU visitors."""
        eu_regions = [r for r in geo_regions if r in COMPLIANCE_CHECKS.get("gdpr", [])]

        if not eu_regions:
            pytest.skip("No EU regions in test configuration")

        missing_gdpr = []

        for region in eu_regions:
            if region not in region_responses or "error" in region_responses[region]:
                continue

            content = region_responses[region]["content"].lower()

            has_gdpr_indicator = any(ind in content for ind in GDPR_INDICATORS)

            if not has_gdpr_indicator:
                missing_gdpr.append(region)

        if missing_gdpr:
            print(
                f"WARNING: No GDPR compliance indicators detected for EU regions: {missing_gdpr}. "
                f"Consider adding cookie consent banners for EU visitors."
            )

    def test_ccpa_compliance_for_california(self, region_responses, geo_regions):
        """Check for CCPA compliance indicators for California visitors."""
        ccpa_regions = [r for r in geo_regions if r in COMPLIANCE_CHECKS.get("ccpa", [])]

        if not ccpa_regions:
            pytest.skip("No California regions in test configuration")

        for region in ccpa_regions:
            if region not in region_responses or "error" in region_responses[region]:
                continue

            content = region_responses[region]["content"].lower()

            has_ccpa_indicator = any(ind in content for ind in CCPA_INDICATORS)

            if not has_ccpa_indicator:
                print(
                    f"INFO: No CCPA compliance indicators detected for {region}. "
                    f"Consider 'Do Not Sell My Personal Information' links for California visitors."
                )

    def test_cookie_consent_presence(self, region_responses, geo_regions):
        """Check for cookie consent mechanisms."""
        cookie_indicators = [
            "cookie",
            "consent",
            "accept",
            "gdpr",
            "privacy",
            "tracking",
        ]

        regions_with_consent = []
        regions_without_consent = []

        for region in geo_regions:
            if region not in region_responses or "error" in region_responses[region]:
                continue

            content = region_responses[region]["content"].lower()

            # Look for cookie consent patterns
            consent_found = sum(1 for ind in cookie_indicators if ind in content) >= 2

            if consent_found:
                regions_with_consent.append(region)
            else:
                regions_without_consent.append(region)

        if regions_with_consent and regions_without_consent:
            print(
                f"INFO: Cookie consent varies by region. "
                f"Present: {regions_with_consent}, Absent: {regions_without_consent}"
            )


# =============================================================================
# GEO REDIRECT TESTS
# =============================================================================

@pytest.mark.geo
@pytest.mark.redirects
class TestGeoRedirects:
    """Test geo-based redirects."""

    def test_no_unexpected_redirects(self, scanner, geo_regions):
        """Check for unexpected geo-based redirects."""
        config = get_config()
        redirects = {}

        for region in geo_regions:
            if region not in GEO_HEADERS:
                continue

            headers = GEO_HEADERS[region].copy()
            headers["User-Agent"] = config.user_agent

            try:
                response = scanner.get(
                    config.target_url,
                    headers=headers,
                    allow_redirects=False
                )

                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location", "")
                    redirects[region] = {
                        "status": response.status_code,
                        "location": location,
                    }

            except Exception:
                continue

            time.sleep(config.request_delay)

        if redirects:
            print(f"INFO: Geo-based redirects detected: {redirects}")

    def test_redirect_destinations(self, scanner, geo_regions):
        """Verify redirect destinations are valid."""
        config = get_config()

        for region in geo_regions:
            if region not in GEO_HEADERS:
                continue

            headers = GEO_HEADERS[region].copy()
            headers["User-Agent"] = config.user_agent

            try:
                response = scanner.get(
                    config.target_url,
                    headers=headers,
                    allow_redirects=True
                )

                # Check final URL
                if response.url != config.target_url:
                    region_name = REGION_INFO.get(region, {}).get("name", region)
                    print(f"INFO: {region_name} redirects to: {response.url}")

            except Exception:
                continue

            time.sleep(config.request_delay)


# =============================================================================
# CDN AND EDGE LOCATION TESTS
# =============================================================================

@pytest.mark.geo
@pytest.mark.cdn
class TestGeoCDN:
    """Test CDN and edge server behavior."""

    def test_cdn_headers_present(self, region_responses, geo_regions):
        """Check for CDN headers indicating edge serving."""
        cdn_headers = [
            "cf-ray",  # Cloudflare
            "x-cache",  # Various CDNs
            "x-served-by",  # Fastly
            "x-amz-cf-id",  # CloudFront
            "x-akamai-request-id",  # Akamai
            "x-varnish",  # Varnish
            "x-cdn",  # Generic
            "via",  # Proxy/CDN
        ]

        cdn_detected = {}

        for region in geo_regions:
            if region not in region_responses or "error" in region_responses[region]:
                continue

            headers = region_responses[region]["headers"]

            for cdn_header in cdn_headers:
                header_lower = cdn_header.lower()
                for key in headers:
                    if key.lower() == header_lower:
                        if region not in cdn_detected:
                            cdn_detected[region] = []
                        cdn_detected[region].append(f"{key}: {headers[key][:50]}")

        if cdn_detected:
            print(f"INFO: CDN headers detected: {cdn_detected}")
        else:
            print("INFO: No CDN headers detected - site may not be using a CDN")

    def test_cache_headers_by_region(self, region_responses, geo_regions):
        """Check if cache headers are consistent across regions."""
        cache_headers = {}

        for region in geo_regions:
            if region not in region_responses or "error" in region_responses[region]:
                continue

            headers = region_responses[region]["headers"]

            cache_control = headers.get("Cache-Control", "")
            if cache_control:
                cache_headers[region] = cache_control

        if cache_headers:
            unique_values = set(cache_headers.values())
            if len(unique_values) > 1:
                print(f"INFO: Cache headers vary by region: {cache_headers}")
            else:
                print(f"INFO: Consistent cache headers: {list(unique_values)[0]}")


# =============================================================================
# INTERNATIONAL SEO TESTS
# =============================================================================

@pytest.mark.geo
@pytest.mark.international_seo
class TestInternationalSEO:
    """Test international SEO factors."""

    def test_hreflang_for_regions(self, region_responses, geo_regions):
        """Check if hreflang tags match tested regions."""
        # Get hreflang from first accessible region
        hreflang_tags = []

        for region in geo_regions:
            if region not in region_responses or "error" in region_responses[region]:
                continue

            content = region_responses[region]["content"]
            soup = BeautifulSoup(content, "html.parser")

            tags = soup.find_all("link", rel="alternate", hreflang=True)
            if tags:
                hreflang_tags = [tag.get("hreflang") for tag in tags]
                break

        if hreflang_tags:
            print(f"INFO: Hreflang tags found: {hreflang_tags}")

            # Check if tested regions have corresponding hreflang
            for region in geo_regions:
                region_lang = REGION_INFO.get(region, {}).get("language", "")
                if region_lang:
                    lang_match = any(
                        h.lower().startswith(region_lang.split("-")[0].lower())
                        for h in hreflang_tags
                    )
                    if not lang_match:
                        print(f"INFO: No hreflang for {region} ({region_lang})")
        else:
            print("INFO: No hreflang tags found (OK for single-language sites)")

    def test_content_language_header(self, region_responses, geo_regions):
        """Check Content-Language header by region."""
        languages = {}

        for region in geo_regions:
            if region not in region_responses or "error" in region_responses[region]:
                continue

            headers = region_responses[region]["headers"]
            content_lang = headers.get("Content-Language", "")

            if content_lang:
                languages[region] = content_lang

        if languages:
            print(f"INFO: Content-Language headers: {languages}")
