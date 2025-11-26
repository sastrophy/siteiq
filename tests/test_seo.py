"""
SiteIQ SEO Tests - Phase 1: Core SEO Analysis

Tests for on-page SEO elements including meta tags, headings,
images, robots.txt, sitemap.xml, and basic technical SEO.
"""

import pytest
import requests
import re
import json
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from xml.etree import ElementTree as ET

from config import get_config
from payloads.seo import (
    TITLE_REQUIREMENTS, DESCRIPTION_REQUIREMENTS,
    REQUIRED_META_TAGS, RECOMMENDED_META_TAGS,
    HEADING_RULES, IMAGE_RULES, URL_RULES,
    ROBOTS_TXT_CHECKS, ROBOTS_BLOCKED_PATHS,
    SITEMAP_LOCATIONS, SITEMAP_REQUIREMENTS,
    COMMON_SCHEMA_TYPES, REQUIRED_SCHEMA_PROPERTIES,
    REQUIRED_OG_TAGS, RECOMMENDED_OG_TAGS,
    REQUIRED_TWITTER_TAGS, RECOMMENDED_TWITTER_TAGS,
    CANONICAL_RULES, MOBILE_REQUIREMENTS, VIEWPORT_META_PATTERN,
    SEO_USER_AGENTS, COMMON_SEO_ISSUES,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def page_content(scanner):
    """Fetch and parse the main page content."""
    config = get_config()
    try:
        response = scanner.get(config.target_url)
        return {
            "response": response,
            "soup": BeautifulSoup(response.text, "html.parser"),
            "url": config.target_url,
            "status_code": response.status_code,
        }
    except Exception as e:
        pytest.skip(f"Could not fetch page: {e}")


@pytest.fixture
def crawled_pages(scanner):
    """Crawl multiple pages based on config crawl depth."""
    config = get_config()
    pages = []
    visited = set()
    to_visit = [config.target_url]

    max_pages = config.seo_crawl_depth

    while to_visit and len(pages) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue

        visited.add(url)

        try:
            response = scanner.get(url, timeout=config.timeout)
            if response.status_code == 200 and "text/html" in response.headers.get("content-type", ""):
                soup = BeautifulSoup(response.text, "html.parser")
                pages.append({
                    "url": url,
                    "response": response,
                    "soup": soup,
                })

                # Find more internal links
                if len(pages) < max_pages:
                    for link in soup.find_all("a", href=True):
                        href = link["href"]
                        full_url = urljoin(url, href)
                        parsed = urlparse(full_url)

                        # Only follow internal links
                        if parsed.netloc == urlparse(config.target_url).netloc:
                            if full_url not in visited and full_url not in to_visit:
                                to_visit.append(full_url)

        except Exception:
            continue

        time.sleep(config.request_delay)

    return pages


# =============================================================================
# META TAGS TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.meta_tags
class TestMetaTags:
    """Test meta tags for SEO compliance."""

    def test_title_tag_exists(self, page_content):
        """Check if title tag exists."""
        soup = page_content["soup"]
        title = soup.find("title")

        assert title is not None, COMMON_SEO_ISSUES["missing_title"]
        assert title.string and title.string.strip(), "Title tag is empty"

    def test_title_tag_length(self, page_content):
        """Check if title tag length is optimal."""
        soup = page_content["soup"]
        title = soup.find("title")

        if not title or not title.string:
            pytest.skip("No title tag found")

        title_text = title.string.strip()
        title_length = len(title_text)

        if title_length < TITLE_REQUIREMENTS["min_length"]:
            pytest.fail(
                f"{COMMON_SEO_ISSUES['title_too_short']} "
                f"(found {title_length} chars, minimum {TITLE_REQUIREMENTS['min_length']})"
            )

        if title_length > TITLE_REQUIREMENTS["max_length"]:
            pytest.fail(
                f"{COMMON_SEO_ISSUES['title_too_long']} "
                f"(found {title_length} chars, maximum {TITLE_REQUIREMENTS['max_length']})"
            )

    def test_meta_description_exists(self, page_content):
        """Check if meta description exists."""
        soup = page_content["soup"]
        description = soup.find("meta", attrs={"name": "description"})

        assert description is not None, COMMON_SEO_ISSUES["missing_description"]

        content = description.get("content", "")
        assert content.strip(), "Meta description is empty"

    def test_meta_description_length(self, page_content):
        """Check if meta description length is optimal."""
        soup = page_content["soup"]
        description = soup.find("meta", attrs={"name": "description"})

        if not description:
            pytest.skip("No meta description found")

        content = description.get("content", "").strip()
        desc_length = len(content)

        if desc_length < DESCRIPTION_REQUIREMENTS["min_length"]:
            pytest.fail(
                f"{COMMON_SEO_ISSUES['description_too_short']} "
                f"(found {desc_length} chars, minimum {DESCRIPTION_REQUIREMENTS['min_length']})"
            )

        if desc_length > DESCRIPTION_REQUIREMENTS["max_length"]:
            pytest.fail(
                f"{COMMON_SEO_ISSUES['description_too_long']} "
                f"(found {desc_length} chars, maximum {DESCRIPTION_REQUIREMENTS['max_length']})"
            )

    def test_viewport_meta_tag(self, page_content):
        """Check for viewport meta tag (mobile-friendly)."""
        soup = page_content["soup"]
        viewport = soup.find("meta", attrs={"name": "viewport"})

        assert viewport is not None, "Missing viewport meta tag - page may not be mobile-friendly"

        content = viewport.get("content", "")
        assert re.search(VIEWPORT_META_PATTERN, content), \
            f"Viewport meta tag should contain 'width=device-width', found: {content}"

    def test_robots_meta_tag(self, page_content):
        """Check robots meta tag configuration."""
        soup = page_content["soup"]
        robots = soup.find("meta", attrs={"name": "robots"})

        # Robots meta is optional, but if present, check it's not blocking
        if robots:
            content = robots.get("content", "").lower()

            if "noindex" in content:
                pytest.fail("Page has noindex directive - will not appear in search results")

            if "nofollow" in content:
                print("WARNING: Page has nofollow directive - links won't pass authority")

    def test_charset_declaration(self, page_content):
        """Check for proper charset declaration."""
        soup = page_content["soup"]

        # Check for charset meta tag
        charset = soup.find("meta", charset=True)
        if charset:
            return

        # Check for http-equiv charset
        http_equiv = soup.find("meta", attrs={"http-equiv": "Content-Type"})
        if http_equiv and "charset" in http_equiv.get("content", "").lower():
            return

        pytest.fail("Missing charset declaration - should have <meta charset='UTF-8'>")


# =============================================================================
# HEADING STRUCTURE TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.headings
class TestHeadingStructure:
    """Test heading structure for SEO compliance."""

    def test_h1_exists(self, page_content):
        """Check if H1 tag exists."""
        soup = page_content["soup"]
        h1_tags = soup.find_all("h1")

        assert len(h1_tags) > 0, COMMON_SEO_ISSUES["missing_h1"]

    def test_single_h1(self, page_content):
        """Check for single H1 tag (best practice)."""
        soup = page_content["soup"]
        h1_tags = soup.find_all("h1")

        if len(h1_tags) > HEADING_RULES["h1_max_count"]:
            pytest.fail(
                f"{COMMON_SEO_ISSUES['multiple_h1']} "
                f"(found {len(h1_tags)}, recommended max: {HEADING_RULES['h1_max_count']})"
            )

    def test_h1_length(self, page_content):
        """Check H1 tag length is appropriate."""
        soup = page_content["soup"]
        h1 = soup.find("h1")

        if not h1:
            pytest.skip("No H1 tag found")

        h1_text = h1.get_text(strip=True)
        h1_length = len(h1_text)

        if h1_length < HEADING_RULES["h1_min_length"]:
            pytest.fail(f"H1 tag is too short ({h1_length} chars, minimum {HEADING_RULES['h1_min_length']})")

        if h1_length > HEADING_RULES["h1_max_length"]:
            pytest.fail(f"H1 tag is too long ({h1_length} chars, maximum {HEADING_RULES['h1_max_length']})")

    def test_heading_hierarchy(self, page_content):
        """Check heading hierarchy (no skipping levels)."""
        soup = page_content["soup"]
        headings = soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])

        if not headings:
            pytest.skip("No headings found on page")

        # Get heading levels in order
        levels = [int(h.name[1]) for h in headings]

        # Check for skipped levels
        issues = []
        for i in range(1, len(levels)):
            if levels[i] > levels[i-1] + 1:
                issues.append(f"H{levels[i-1]} followed by H{levels[i]} (skipped level)")

        if issues:
            pytest.fail(f"Heading hierarchy issues: {'; '.join(issues)}")

    def test_no_empty_headings(self, page_content):
        """Check for empty heading tags."""
        soup = page_content["soup"]
        headings = soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])

        empty_headings = [h.name for h in headings if not h.get_text(strip=True)]

        if empty_headings:
            pytest.fail(f"Found empty heading tags: {empty_headings}")


# =============================================================================
# IMAGE OPTIMIZATION TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.images
class TestImageOptimization:
    """Test image optimization for SEO."""

    def test_images_have_alt_text(self, page_content):
        """Check if all images have alt attributes."""
        soup = page_content["soup"]
        images = soup.find_all("img")

        if not images:
            pytest.skip("No images found on page")

        missing_alt = []
        empty_alt = []

        for img in images:
            src = img.get("src", "unknown")

            if "alt" not in img.attrs:
                missing_alt.append(src)
            elif not img.get("alt", "").strip():
                # Empty alt is OK for decorative images, but flag it
                empty_alt.append(src)

        if missing_alt:
            pytest.fail(
                f"{COMMON_SEO_ISSUES['missing_alt_text']} - "
                f"{len(missing_alt)} images without alt attribute: {missing_alt[:5]}"
            )

    def test_alt_text_length(self, page_content):
        """Check alt text is appropriate length."""
        soup = page_content["soup"]
        images = soup.find_all("img", alt=True)

        if not images:
            pytest.skip("No images with alt text found")

        issues = []
        for img in images:
            alt = img.get("alt", "")
            src = img.get("src", "unknown")

            if alt and len(alt) > IMAGE_RULES["alt_max_length"]:
                issues.append(f"{src}: alt text too long ({len(alt)} chars)")

        if issues:
            pytest.fail(f"Alt text length issues: {issues[:5]}")

    def test_image_lazy_loading(self, page_content):
        """Check if images use lazy loading."""
        soup = page_content["soup"]
        images = soup.find_all("img")

        if not images:
            pytest.skip("No images found")

        # Check for native lazy loading
        lazy_count = sum(1 for img in images if img.get("loading") == "lazy")
        total_images = len(images)

        # First few images shouldn't be lazy loaded (above the fold)
        non_lazy = total_images - lazy_count

        if total_images > 5 and lazy_count == 0:
            print(f"INFO: Consider adding lazy loading to images ({total_images} images found)")

    def test_images_have_dimensions(self, page_content):
        """Check if images have width/height attributes (prevents CLS)."""
        soup = page_content["soup"]
        images = soup.find_all("img")

        if not images:
            pytest.skip("No images found")

        missing_dimensions = []
        for img in images:
            has_width = img.get("width") or "width" in img.get("style", "")
            has_height = img.get("height") or "height" in img.get("style", "")

            if not (has_width and has_height):
                missing_dimensions.append(img.get("src", "unknown"))

        if missing_dimensions and len(missing_dimensions) > len(images) / 2:
            print(
                f"WARNING: {len(missing_dimensions)} images missing width/height "
                f"(may cause layout shift): {missing_dimensions[:3]}"
            )


# =============================================================================
# ROBOTS.TXT TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.robots
class TestRobotsTxt:
    """Test robots.txt configuration."""

    def test_robots_txt_exists(self, scanner):
        """Check if robots.txt exists."""
        config = get_config()
        robots_url = urljoin(config.target_url, "/robots.txt")

        response = scanner.get(robots_url)

        assert response.status_code == 200, \
            f"{COMMON_SEO_ISSUES['missing_robots']} (status: {response.status_code})"

    def test_robots_txt_valid(self, scanner):
        """Check if robots.txt is valid and parseable."""
        config = get_config()
        robots_url = urljoin(config.target_url, "/robots.txt")

        response = scanner.get(robots_url)

        if response.status_code != 200:
            pytest.skip("robots.txt not found")

        content = response.text.lower()

        # Should have at least one User-agent directive
        assert "user-agent" in content, "robots.txt should contain User-agent directive"

    def test_robots_txt_allows_crawling(self, scanner):
        """Check that robots.txt doesn't block everything."""
        config = get_config()
        robots_url = urljoin(config.target_url, "/robots.txt")

        response = scanner.get(robots_url)

        if response.status_code != 200:
            pytest.skip("robots.txt not found")

        content = response.text

        # Check for global disallow
        lines = content.split("\n")
        in_all_agents = False

        for line in lines:
            line = line.strip().lower()

            if line.startswith("user-agent:") and "*" in line:
                in_all_agents = True
            elif line.startswith("user-agent:"):
                in_all_agents = False
            elif in_all_agents and line == "disallow: /":
                pytest.fail("robots.txt blocks all crawling with 'Disallow: /'")

    def test_robots_txt_references_sitemap(self, scanner):
        """Check if robots.txt references sitemap."""
        config = get_config()
        robots_url = urljoin(config.target_url, "/robots.txt")

        response = scanner.get(robots_url)

        if response.status_code != 200:
            pytest.skip("robots.txt not found")

        content = response.text.lower()

        if "sitemap:" not in content:
            print("INFO: robots.txt does not reference a sitemap (recommended)")


# =============================================================================
# SITEMAP TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.sitemap
class TestSitemap:
    """Test sitemap.xml configuration."""

    def test_sitemap_exists(self, scanner):
        """Check if sitemap.xml exists."""
        config = get_config()

        # Try common sitemap locations
        for path in SITEMAP_LOCATIONS:
            sitemap_url = urljoin(config.target_url, path)
            response = scanner.get(sitemap_url)

            if response.status_code == 200:
                return  # Found sitemap

        # Also check robots.txt for sitemap location
        robots_url = urljoin(config.target_url, "/robots.txt")
        robots_response = scanner.get(robots_url)

        if robots_response.status_code == 200:
            for line in robots_response.text.split("\n"):
                if line.lower().startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    response = scanner.get(sitemap_url)
                    if response.status_code == 200:
                        return  # Found sitemap

        pytest.fail(COMMON_SEO_ISSUES["missing_sitemap"])

    def test_sitemap_valid_xml(self, scanner):
        """Check if sitemap is valid XML."""
        config = get_config()

        sitemap_url = None
        response = None

        for path in SITEMAP_LOCATIONS:
            url = urljoin(config.target_url, path)
            resp = scanner.get(url)
            if resp.status_code == 200:
                sitemap_url = url
                response = resp
                break

        if not response:
            pytest.skip("Sitemap not found")

        try:
            ET.fromstring(response.content)
        except ET.ParseError as e:
            pytest.fail(f"Sitemap is not valid XML: {e}")

    def test_sitemap_has_urls(self, scanner):
        """Check if sitemap contains URLs."""
        config = get_config()

        for path in SITEMAP_LOCATIONS:
            sitemap_url = urljoin(config.target_url, path)
            response = scanner.get(sitemap_url)

            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.content)

                    # Handle namespace
                    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

                    # Try with namespace
                    urls = root.findall(".//sm:loc", ns)
                    if not urls:
                        # Try without namespace
                        urls = root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
                    if not urls:
                        # Try plain
                        urls = root.findall(".//loc")

                    assert len(urls) > 0, "Sitemap contains no URLs"
                    print(f"INFO: Sitemap contains {len(urls)} URLs")
                    return
                except ET.ParseError:
                    continue

        pytest.skip("Could not parse sitemap")

    def test_sitemap_urls_accessible(self, scanner):
        """Check if sitemap URLs are accessible (sample check)."""
        config = get_config()

        for path in SITEMAP_LOCATIONS:
            sitemap_url = urljoin(config.target_url, path)
            response = scanner.get(sitemap_url)

            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.content)

                    # Find all loc elements
                    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                    urls = root.findall(".//sm:loc", ns)
                    if not urls:
                        urls = root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
                    if not urls:
                        urls = root.findall(".//loc")

                    # Test sample of URLs (max 5)
                    sample_urls = [u.text for u in urls[:5] if u.text]
                    broken = []

                    for url in sample_urls:
                        try:
                            resp = scanner.head(url, timeout=config.timeout)
                            if resp.status_code >= 400:
                                broken.append(f"{url} ({resp.status_code})")
                        except Exception:
                            broken.append(f"{url} (error)")
                        time.sleep(config.request_delay)

                    if broken:
                        pytest.fail(f"Sitemap contains inaccessible URLs: {broken}")

                    return
                except ET.ParseError:
                    continue

        pytest.skip("Could not parse sitemap")


# =============================================================================
# CANONICAL TAG TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.canonical
class TestCanonicalTags:
    """Test canonical tag configuration."""

    def test_canonical_tag_exists(self, page_content):
        """Check if canonical tag exists."""
        soup = page_content["soup"]
        canonical = soup.find("link", rel="canonical")

        if not canonical:
            print(f"WARNING: {COMMON_SEO_ISSUES['missing_canonical']}")

    def test_canonical_is_absolute_url(self, page_content):
        """Check if canonical URL is absolute."""
        soup = page_content["soup"]
        canonical = soup.find("link", rel="canonical")

        if not canonical:
            pytest.skip("No canonical tag found")

        href = canonical.get("href", "")

        assert href.startswith("http"), \
            f"Canonical URL should be absolute, found: {href}"

    def test_canonical_matches_current_url(self, page_content):
        """Check if canonical is self-referencing or points elsewhere."""
        soup = page_content["soup"]
        canonical = soup.find("link", rel="canonical")

        if not canonical:
            pytest.skip("No canonical tag found")

        href = canonical.get("href", "").rstrip("/")
        current_url = page_content["url"].rstrip("/")

        if href != current_url:
            print(f"INFO: Page canonicalizes to different URL: {href}")


# =============================================================================
# LINK ANALYSIS TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.links
class TestLinkAnalysis:
    """Test internal and external link structure."""

    def test_internal_links_exist(self, page_content):
        """Check for internal links."""
        config = get_config()
        soup = page_content["soup"]

        base_domain = urlparse(config.target_url).netloc
        internal_links = []

        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(page_content["url"], href)
            parsed = urlparse(full_url)

            if parsed.netloc == base_domain:
                internal_links.append(full_url)

        assert len(internal_links) > 0, "Page has no internal links (orphan page risk)"

    def test_no_broken_internal_links(self, page_content, scanner):
        """Check for broken internal links (sample)."""
        config = get_config()
        soup = page_content["soup"]

        base_domain = urlparse(config.target_url).netloc
        internal_links = []

        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(page_content["url"], href)
            parsed = urlparse(full_url)

            if parsed.netloc == base_domain:
                internal_links.append(full_url)

        # Test sample of links
        broken_links = []
        for url in internal_links[:10]:
            try:
                response = scanner.head(url, timeout=config.timeout)
                if response.status_code >= 400:
                    broken_links.append(f"{url} ({response.status_code})")
            except Exception:
                broken_links.append(f"{url} (error)")
            time.sleep(config.request_delay / 2)

        if broken_links:
            pytest.fail(f"{COMMON_SEO_ISSUES['broken_links']}: {broken_links}")

    def test_external_links_have_appropriate_rel(self, page_content):
        """Check external links for appropriate rel attributes."""
        config = get_config()
        soup = page_content["soup"]

        base_domain = urlparse(config.target_url).netloc
        external_links = []

        for link in soup.find_all("a", href=True):
            href = link["href"]
            if href.startswith(("http://", "https://")):
                parsed = urlparse(href)
                if parsed.netloc != base_domain:
                    external_links.append({
                        "url": href,
                        "rel": link.get("rel", []),
                        "target": link.get("target"),
                    })

        if not external_links:
            pytest.skip("No external links found")

        # Check for target="_blank" without rel="noopener"
        security_issues = []
        for link in external_links:
            if link["target"] == "_blank":
                rel = link["rel"] if isinstance(link["rel"], list) else [link["rel"]]
                if "noopener" not in rel and "noreferrer" not in rel:
                    security_issues.append(link["url"])

        if security_issues:
            print(
                f"WARNING: External links with target='_blank' missing rel='noopener': "
                f"{security_issues[:3]}"
            )


# =============================================================================
# URL STRUCTURE TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.urls
class TestURLStructure:
    """Test URL structure for SEO."""

    def test_url_is_https(self, page_content):
        """Check if URL uses HTTPS."""
        url = page_content["url"]
        assert url.startswith("https://"), f"{COMMON_SEO_ISSUES['missing_ssl']}: {url}"

    def test_url_length(self, page_content):
        """Check URL length."""
        url = page_content["url"]
        parsed = urlparse(url)
        path = parsed.path

        if len(path) > URL_RULES["max_length"]:
            print(f"WARNING: URL path is long ({len(path)} chars): {path}")

    def test_url_is_lowercase(self, page_content):
        """Check if URL is lowercase."""
        url = page_content["url"]
        parsed = urlparse(url)
        path = parsed.path

        if path != path.lower():
            print(f"INFO: URL contains uppercase characters: {path}")

    def test_url_no_special_characters(self, page_content):
        """Check URL for problematic characters."""
        url = page_content["url"]
        parsed = urlparse(url)
        path = parsed.path

        issues = []
        for char in URL_RULES["avoid_characters"]:
            if char in path:
                issues.append(char)

        if issues:
            print(f"INFO: URL contains characters to avoid: {issues}")


# =============================================================================
# MOBILE FRIENDLINESS TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.mobile
class TestMobileFriendliness:
    """Test mobile-friendliness indicators."""

    def test_viewport_configured(self, page_content):
        """Check viewport is properly configured."""
        soup = page_content["soup"]
        viewport = soup.find("meta", attrs={"name": "viewport"})

        assert viewport is not None, COMMON_SEO_ISSUES["not_mobile_friendly"]

        content = viewport.get("content", "")

        # Check for common viewport issues
        if "user-scalable=no" in content or "maximum-scale=1" in content:
            print("WARNING: Viewport may prevent user zooming (accessibility issue)")

    def test_responsive_design_hints(self, page_content):
        """Check for responsive design indicators."""
        soup = page_content["soup"]

        # Check for responsive CSS indicators
        style_tags = soup.find_all("style")
        link_tags = soup.find_all("link", rel="stylesheet")

        has_media_queries = False

        for style in style_tags:
            if style.string and "@media" in style.string:
                has_media_queries = True
                break

        # Check for Bootstrap or other responsive frameworks
        for link in link_tags:
            href = link.get("href", "").lower()
            if any(f in href for f in ["bootstrap", "tailwind", "foundation"]):
                has_media_queries = True
                break

        if not has_media_queries:
            print("INFO: No clear responsive design indicators found")

    def test_text_size_readable(self, page_content):
        """Check for readable text size on mobile."""
        soup = page_content["soup"]

        # Look for font-size declarations that might be too small
        style_tags = soup.find_all("style")

        small_font_warning = False
        for style in style_tags:
            if style.string:
                # Simple check for very small font sizes
                if re.search(r"font-size:\s*(8|9|10|11)px", style.string):
                    small_font_warning = True
                    break

        if small_font_warning:
            print("WARNING: Found potentially small font sizes (< 12px)")


# =============================================================================
# SCHEMA MARKUP (JSON-LD) TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.schema
class TestSchemaMarkup:
    """Test structured data / schema markup."""

    def test_schema_markup_exists(self, page_content):
        """Check if page has any schema markup."""
        soup = page_content["soup"]

        # Check for JSON-LD
        json_ld = soup.find_all("script", type="application/ld+json")

        # Check for microdata
        microdata = soup.find_all(attrs={"itemtype": True})

        # Check for RDFa
        rdfa = soup.find_all(attrs={"typeof": True})

        has_schema = len(json_ld) > 0 or len(microdata) > 0 or len(rdfa) > 0

        if not has_schema:
            print(f"INFO: {COMMON_SEO_ISSUES['missing_schema']}")

    def test_json_ld_valid(self, page_content):
        """Check if JSON-LD is valid JSON."""
        soup = page_content["soup"]
        json_ld_scripts = soup.find_all("script", type="application/ld+json")

        if not json_ld_scripts:
            pytest.skip("No JSON-LD found")

        for i, script in enumerate(json_ld_scripts):
            try:
                data = json.loads(script.string)
            except json.JSONDecodeError as e:
                pytest.fail(f"Invalid JSON-LD in script #{i+1}: {e}")

    def test_json_ld_has_type(self, page_content):
        """Check if JSON-LD has @type defined."""
        soup = page_content["soup"]
        json_ld_scripts = soup.find_all("script", type="application/ld+json")

        if not json_ld_scripts:
            pytest.skip("No JSON-LD found")

        for i, script in enumerate(json_ld_scripts):
            try:
                data = json.loads(script.string)

                # Handle @graph format
                if "@graph" in data:
                    items = data["@graph"]
                else:
                    items = [data]

                for item in items:
                    if isinstance(item, dict) and "@type" not in item:
                        pytest.fail(f"JSON-LD item missing @type: {item}")

            except json.JSONDecodeError:
                pass  # Already tested in previous test

    def test_schema_types_recognized(self, page_content):
        """Check if schema types are common/recognized."""
        soup = page_content["soup"]
        json_ld_scripts = soup.find_all("script", type="application/ld+json")

        if not json_ld_scripts:
            pytest.skip("No JSON-LD found")

        found_types = []

        for script in json_ld_scripts:
            try:
                data = json.loads(script.string)

                if "@graph" in data:
                    items = data["@graph"]
                else:
                    items = [data]

                for item in items:
                    if isinstance(item, dict) and "@type" in item:
                        schema_type = item["@type"]
                        if isinstance(schema_type, list):
                            found_types.extend(schema_type)
                        else:
                            found_types.append(schema_type)

            except json.JSONDecodeError:
                pass

        if found_types:
            print(f"INFO: Found schema types: {found_types}")

            # Check for common types
            common_found = [t for t in found_types if t in COMMON_SCHEMA_TYPES]
            if common_found:
                print(f"INFO: Recognized schema types: {common_found}")

    def test_organization_schema(self, page_content):
        """Check for Organization schema on homepage."""
        config = get_config()

        # Only check homepage
        if page_content["url"].rstrip("/") != config.target_url.rstrip("/"):
            pytest.skip("Not testing homepage")

        soup = page_content["soup"]
        json_ld_scripts = soup.find_all("script", type="application/ld+json")

        has_organization = False

        for script in json_ld_scripts:
            try:
                data = json.loads(script.string)

                if "@graph" in data:
                    items = data["@graph"]
                else:
                    items = [data]

                for item in items:
                    if isinstance(item, dict):
                        schema_type = item.get("@type", "")
                        if schema_type == "Organization" or (
                            isinstance(schema_type, list) and "Organization" in schema_type
                        ):
                            has_organization = True
                            break

            except json.JSONDecodeError:
                pass

        if not has_organization:
            print("INFO: Consider adding Organization schema to homepage")


# =============================================================================
# OPEN GRAPH TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.opengraph
class TestOpenGraph:
    """Test Open Graph meta tags."""

    def test_og_tags_exist(self, page_content):
        """Check if Open Graph tags exist."""
        soup = page_content["soup"]

        og_tags = soup.find_all("meta", property=lambda x: x and x.startswith("og:"))

        if not og_tags:
            print(f"INFO: {COMMON_SEO_ISSUES['missing_og_tags']}")

    def test_required_og_tags(self, page_content):
        """Check for required Open Graph tags."""
        soup = page_content["soup"]

        missing = []
        for tag_name in REQUIRED_OG_TAGS:
            tag = soup.find("meta", property=tag_name)
            if not tag or not tag.get("content"):
                missing.append(tag_name)

        if missing:
            print(f"WARNING: Missing required Open Graph tags: {missing}")

    def test_og_title(self, page_content):
        """Check og:title content."""
        soup = page_content["soup"]
        og_title = soup.find("meta", property="og:title")

        if not og_title:
            pytest.skip("No og:title found")

        content = og_title.get("content", "")

        if not content.strip():
            pytest.fail("og:title is empty")

        if len(content) > 60:
            print(f"INFO: og:title is long ({len(content)} chars)")

    def test_og_description(self, page_content):
        """Check og:description content."""
        soup = page_content["soup"]
        og_desc = soup.find("meta", property="og:description")

        if not og_desc:
            print("INFO: Missing og:description tag")
            return

        content = og_desc.get("content", "")

        if not content.strip():
            print("WARNING: og:description is empty")

        if len(content) > 200:
            print(f"INFO: og:description is long ({len(content)} chars)")

    def test_og_image(self, page_content, scanner):
        """Check og:image is valid and accessible."""
        soup = page_content["soup"]
        og_image = soup.find("meta", property="og:image")

        if not og_image:
            print("INFO: Missing og:image tag")
            return

        image_url = og_image.get("content", "")

        if not image_url:
            pytest.fail("og:image is empty")

        # Check if absolute URL
        if not image_url.startswith("http"):
            print("WARNING: og:image should be an absolute URL")

        # Check if image is accessible
        try:
            config = get_config()
            response = scanner.head(image_url, timeout=config.timeout)
            if response.status_code >= 400:
                pytest.fail(f"og:image not accessible (status: {response.status_code})")
        except Exception as e:
            print(f"WARNING: Could not verify og:image: {e}")

    def test_og_url(self, page_content):
        """Check og:url matches canonical."""
        soup = page_content["soup"]

        og_url = soup.find("meta", property="og:url")
        canonical = soup.find("link", rel="canonical")

        if not og_url:
            print("INFO: Missing og:url tag")
            return

        og_url_content = og_url.get("content", "").rstrip("/")

        if canonical:
            canonical_href = canonical.get("href", "").rstrip("/")
            if og_url_content != canonical_href:
                print(f"WARNING: og:url ({og_url_content}) doesn't match canonical ({canonical_href})")


# =============================================================================
# TWITTER CARD TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.twitter
class TestTwitterCards:
    """Test Twitter Card meta tags."""

    def test_twitter_card_exists(self, page_content):
        """Check if Twitter Card tags exist."""
        soup = page_content["soup"]

        twitter_card = soup.find("meta", attrs={"name": "twitter:card"})

        if not twitter_card:
            print(f"INFO: {COMMON_SEO_ISSUES['missing_twitter_cards']}")

    def test_twitter_card_type_valid(self, page_content):
        """Check Twitter Card type is valid."""
        soup = page_content["soup"]

        twitter_card = soup.find("meta", attrs={"name": "twitter:card"})

        if not twitter_card:
            pytest.skip("No twitter:card found")

        card_type = twitter_card.get("content", "")

        from payloads.seo import TWITTER_CARD_TYPES
        assert card_type in TWITTER_CARD_TYPES, \
            f"Invalid twitter:card type: {card_type}. Valid types: {TWITTER_CARD_TYPES}"

    def test_twitter_title(self, page_content):
        """Check twitter:title or fallback to og:title."""
        soup = page_content["soup"]

        twitter_title = soup.find("meta", attrs={"name": "twitter:title"})
        og_title = soup.find("meta", property="og:title")

        if not twitter_title and not og_title:
            print("WARNING: No twitter:title or og:title for Twitter Card")

    def test_twitter_description(self, page_content):
        """Check twitter:description or fallback."""
        soup = page_content["soup"]

        twitter_desc = soup.find("meta", attrs={"name": "twitter:description"})
        og_desc = soup.find("meta", property="og:description")

        if not twitter_desc and not og_desc:
            print("WARNING: No twitter:description or og:description for Twitter Card")

    def test_twitter_image(self, page_content):
        """Check twitter:image or fallback to og:image."""
        soup = page_content["soup"]

        twitter_image = soup.find("meta", attrs={"name": "twitter:image"})
        og_image = soup.find("meta", property="og:image")

        if not twitter_image and not og_image:
            print("WARNING: No twitter:image or og:image for Twitter Card")


# =============================================================================
# PERFORMANCE SEO TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.performance
class TestPerformanceSEO:
    """Test page performance metrics for SEO."""

    def test_page_load_time(self, scanner):
        """Check basic page load time."""
        config = get_config()

        start_time = time.time()
        response = scanner.get(config.target_url)
        load_time = time.time() - start_time

        print(f"INFO: Page load time: {load_time:.2f}s")

        if load_time > 3.0:
            pytest.fail(f"{COMMON_SEO_ISSUES['slow_page_speed']} ({load_time:.2f}s > 3s)")

        if load_time > 2.0:
            print(f"WARNING: Page load time is slow ({load_time:.2f}s)")

    def test_response_size(self, scanner):
        """Check HTML response size."""
        config = get_config()
        response = scanner.get(config.target_url)

        size_kb = len(response.content) / 1024
        print(f"INFO: HTML size: {size_kb:.1f} KB")

        if size_kb > 500:
            print(f"WARNING: HTML response is large ({size_kb:.1f} KB)")

    def test_compression_enabled(self, scanner):
        """Check if compression (gzip/brotli) is enabled."""
        config = get_config()

        # Request with Accept-Encoding
        headers = {"Accept-Encoding": "gzip, deflate, br"}
        response = scanner.get(config.target_url, headers=headers)

        content_encoding = response.headers.get("Content-Encoding", "")

        if content_encoding in ("gzip", "br", "deflate"):
            print(f"INFO: Compression enabled: {content_encoding}")
        else:
            print("WARNING: No compression detected (gzip/brotli recommended)")

    def test_cache_headers(self, scanner):
        """Check for caching headers."""
        config = get_config()
        response = scanner.get(config.target_url)

        cache_control = response.headers.get("Cache-Control", "")
        etag = response.headers.get("ETag", "")
        expires = response.headers.get("Expires", "")

        if not cache_control and not etag and not expires:
            print("WARNING: No caching headers found (Cache-Control, ETag, or Expires)")
        else:
            print(f"INFO: Caching headers: Cache-Control={cache_control or 'N/A'}")

    def test_render_blocking_resources(self, page_content):
        """Check for render-blocking CSS/JS."""
        soup = page_content["soup"]

        # Check CSS in head (blocking by default)
        head = soup.find("head")
        if head:
            blocking_css = head.find_all("link", rel="stylesheet")
            blocking_js = head.find_all("script", src=True)

            # Count JS without async/defer
            sync_js = [
                s for s in blocking_js
                if not s.get("async") and not s.get("defer")
            ]

            if len(blocking_css) > 5:
                print(f"INFO: {len(blocking_css)} CSS files in head (consider bundling)")

            if sync_js:
                print(f"WARNING: {len(sync_js)} synchronous JS files in head (use async/defer)")

    def test_inline_critical_css(self, page_content):
        """Check for inline critical CSS."""
        soup = page_content["soup"]

        head = soup.find("head")
        if head:
            inline_styles = head.find_all("style")
            if inline_styles:
                print(f"INFO: Found {len(inline_styles)} inline style blocks (good for critical CSS)")
            else:
                print("INFO: No inline critical CSS found (consider adding for above-the-fold content)")


# =============================================================================
# PAGESPEED API INTEGRATION
# =============================================================================

@pytest.mark.seo
@pytest.mark.pagespeed
class TestPageSpeedAPI:
    """Test using Google PageSpeed Insights API."""

    PAGESPEED_API_URL = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"

    def test_pagespeed_score(self, scanner):
        """Get PageSpeed performance score."""
        config = get_config()

        if not config.has_pagespeed_api:
            pytest.skip("PageSpeed API key not configured (set PAGESPEED_API_KEY)")

        params = {
            "url": config.target_url,
            "key": config.seo_pagespeed_api_key,
            "strategy": "mobile",
            "category": ["performance", "accessibility", "best-practices", "seo"],
        }

        try:
            response = requests.get(self.PAGESPEED_API_URL, params=params, timeout=60)
            response.raise_for_status()
            data = response.json()

            # Extract scores
            lighthouse = data.get("lighthouseResult", {})
            categories = lighthouse.get("categories", {})

            scores = {}
            for cat_name, cat_data in categories.items():
                score = cat_data.get("score", 0) * 100
                scores[cat_name] = score

            print(f"PageSpeed Scores: {scores}")

            # Check performance score
            perf_score = scores.get("performance", 0)
            from payloads.seo import PAGESPEED_SCORE_THRESHOLDS

            if perf_score < PAGESPEED_SCORE_THRESHOLDS["needs_improvement"]:
                pytest.fail(f"Performance score is poor: {perf_score}")
            elif perf_score < PAGESPEED_SCORE_THRESHOLDS["good"]:
                print(f"WARNING: Performance score needs improvement: {perf_score}")

        except requests.exceptions.Timeout:
            pytest.skip("PageSpeed API request timed out")
        except requests.exceptions.RequestException as e:
            pytest.skip(f"PageSpeed API error: {e}")

    def test_core_web_vitals(self, scanner):
        """Check Core Web Vitals using PageSpeed API."""
        config = get_config()

        if not config.has_pagespeed_api:
            pytest.skip("PageSpeed API key not configured")

        params = {
            "url": config.target_url,
            "key": config.seo_pagespeed_api_key,
            "strategy": "mobile",
        }

        try:
            response = requests.get(self.PAGESPEED_API_URL, params=params, timeout=60)
            response.raise_for_status()
            data = response.json()

            # Extract Core Web Vitals from field data
            loading_exp = data.get("loadingExperience", {})
            metrics = loading_exp.get("metrics", {})

            from payloads.seo import CORE_WEB_VITALS

            vitals = {}

            # LCP
            lcp_data = metrics.get("LARGEST_CONTENTFUL_PAINT_MS", {})
            if lcp_data:
                lcp_value = lcp_data.get("percentile", 0) / 1000  # Convert to seconds
                vitals["LCP"] = lcp_value
                if lcp_value > CORE_WEB_VITALS["LCP"]["poor"]:
                    print(f"WARNING: LCP is poor ({lcp_value:.2f}s)")

            # FID / INP
            fid_data = metrics.get("FIRST_INPUT_DELAY_MS", {})
            if fid_data:
                fid_value = fid_data.get("percentile", 0)
                vitals["FID"] = fid_value
                if fid_value > CORE_WEB_VITALS["FID"]["poor"]:
                    print(f"WARNING: FID is poor ({fid_value}ms)")

            inp_data = metrics.get("INTERACTION_TO_NEXT_PAINT", {})
            if inp_data:
                inp_value = inp_data.get("percentile", 0)
                vitals["INP"] = inp_value
                if inp_value > CORE_WEB_VITALS["INP"]["poor"]:
                    print(f"WARNING: INP is poor ({inp_value}ms)")

            # CLS
            cls_data = metrics.get("CUMULATIVE_LAYOUT_SHIFT_SCORE", {})
            if cls_data:
                cls_value = cls_data.get("percentile", 0) / 100  # API returns as percentage
                vitals["CLS"] = cls_value
                if cls_value > CORE_WEB_VITALS["CLS"]["poor"]:
                    print(f"WARNING: CLS is poor ({cls_value})")

            if vitals:
                print(f"Core Web Vitals: {vitals}")
            else:
                print("INFO: No field data available (site may not have enough traffic)")

        except requests.exceptions.Timeout:
            pytest.skip("PageSpeed API request timed out")
        except requests.exceptions.RequestException as e:
            pytest.skip(f"PageSpeed API error: {e}")

    def test_pagespeed_opportunities(self, scanner):
        """Get PageSpeed optimization opportunities."""
        config = get_config()

        if not config.has_pagespeed_api:
            pytest.skip("PageSpeed API key not configured")

        params = {
            "url": config.target_url,
            "key": config.seo_pagespeed_api_key,
            "strategy": "mobile",
        }

        try:
            response = requests.get(self.PAGESPEED_API_URL, params=params, timeout=60)
            response.raise_for_status()
            data = response.json()

            lighthouse = data.get("lighthouseResult", {})
            audits = lighthouse.get("audits", {})

            # Find failed audits with potential savings
            opportunities = []

            priority_audits = [
                "render-blocking-resources",
                "unused-css-rules",
                "unused-javascript",
                "modern-image-formats",
                "uses-optimized-images",
                "efficient-animated-content",
                "uses-text-compression",
                "uses-responsive-images",
                "server-response-time",
                "uses-rel-preconnect",
            ]

            for audit_id in priority_audits:
                audit = audits.get(audit_id, {})
                if audit.get("score") is not None and audit.get("score") < 1:
                    title = audit.get("title", audit_id)
                    savings = audit.get("details", {}).get("overallSavingsMs", 0)
                    if savings > 0:
                        opportunities.append(f"{title}: {savings}ms potential savings")
                    else:
                        opportunities.append(title)

            if opportunities:
                print(f"PageSpeed Opportunities: {opportunities[:5]}")

        except requests.exceptions.RequestException:
            pytest.skip("PageSpeed API request failed")


# =============================================================================
# HREFLANG TESTS
# =============================================================================

@pytest.mark.seo
@pytest.mark.hreflang
class TestHreflang:
    """Test hreflang tags for international SEO."""

    def test_hreflang_tags_present(self, page_content):
        """Check if hreflang tags are present."""
        soup = page_content["soup"]

        hreflang_tags = soup.find_all("link", rel="alternate", hreflang=True)

        if hreflang_tags:
            print(f"INFO: Found {len(hreflang_tags)} hreflang tags")
            languages = [tag.get("hreflang") for tag in hreflang_tags]
            print(f"INFO: Languages: {languages}")
        else:
            print("INFO: No hreflang tags found (OK if site is single-language)")

    def test_hreflang_valid_codes(self, page_content):
        """Check hreflang language codes are valid."""
        soup = page_content["soup"]

        hreflang_tags = soup.find_all("link", rel="alternate", hreflang=True)

        if not hreflang_tags:
            pytest.skip("No hreflang tags found")

        from payloads.seo import VALID_LANGUAGE_CODES

        invalid_codes = []
        for tag in hreflang_tags:
            code = tag.get("hreflang")
            if code and code not in VALID_LANGUAGE_CODES:
                # Check if it matches pattern xx-XX
                if not re.match(r"^[a-z]{2}(-[A-Z]{2})?$", code) and code != "x-default":
                    invalid_codes.append(code)

        if invalid_codes:
            print(f"WARNING: Potentially invalid hreflang codes: {invalid_codes}")

    def test_hreflang_has_x_default(self, page_content):
        """Check for x-default hreflang."""
        soup = page_content["soup"]

        hreflang_tags = soup.find_all("link", rel="alternate", hreflang=True)

        if not hreflang_tags:
            pytest.skip("No hreflang tags found")

        has_x_default = any(tag.get("hreflang") == "x-default" for tag in hreflang_tags)

        if not has_x_default and len(hreflang_tags) > 1:
            print("INFO: Consider adding x-default hreflang for fallback")

    def test_hreflang_self_reference(self, page_content):
        """Check hreflang includes self-referencing tag."""
        soup = page_content["soup"]
        current_url = page_content["url"].rstrip("/")

        hreflang_tags = soup.find_all("link", rel="alternate", hreflang=True)

        if not hreflang_tags:
            pytest.skip("No hreflang tags found")

        hrefs = [tag.get("href", "").rstrip("/") for tag in hreflang_tags]

        if current_url not in hrefs:
            print("WARNING: Hreflang tags should include self-referencing URL")
