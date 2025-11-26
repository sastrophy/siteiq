"""
SiteIQ SEO Payloads and Test Data

Test data, patterns, and validation rules for SEO analysis.
"""

# =============================================================================
# META TAG VALIDATION
# =============================================================================

# Title tag requirements
TITLE_REQUIREMENTS = {
    "min_length": 30,
    "max_length": 60,
    "optimal_length": (50, 60),
}

# Meta description requirements
DESCRIPTION_REQUIREMENTS = {
    "min_length": 120,
    "max_length": 160,
    "optimal_length": (150, 160),
}

# Required meta tags
REQUIRED_META_TAGS = [
    "description",
    "viewport",
]

# Recommended meta tags
RECOMMENDED_META_TAGS = [
    "robots",
    "author",
    "keywords",
]

# =============================================================================
# HEADING STRUCTURE
# =============================================================================

HEADING_RULES = {
    "h1_required": True,
    "h1_max_count": 1,  # Only one H1 per page
    "h1_min_length": 10,
    "h1_max_length": 70,
    "hierarchy_required": True,  # No skipping levels (H1 -> H3 without H2)
}

# =============================================================================
# IMAGE OPTIMIZATION
# =============================================================================

IMAGE_RULES = {
    "alt_required": True,
    "alt_min_length": 5,
    "alt_max_length": 125,
    "max_file_size_kb": 500,  # KB
    "preferred_formats": ["webp", "avif"],
    "acceptable_formats": ["jpg", "jpeg", "png", "gif", "svg", "webp", "avif"],
}

# =============================================================================
# URL STRUCTURE
# =============================================================================

URL_RULES = {
    "max_length": 75,
    "avoid_characters": ["_", " ", "%20", "%"],
    "preferred_separator": "-",
    "lowercase_required": True,
}

# =============================================================================
# ROBOTS.TXT VALIDATION
# =============================================================================

ROBOTS_TXT_CHECKS = [
    "user-agent",
    "allow",
    "disallow",
    "sitemap",
]

# Paths that should typically be blocked
ROBOTS_BLOCKED_PATHS = [
    "/admin",
    "/wp-admin",
    "/login",
    "/private",
    "/tmp",
    "/cache",
    "/cgi-bin",
]

# Paths that should typically be allowed
ROBOTS_ALLOWED_PATHS = [
    "/",
    "/css/",
    "/js/",
    "/images/",
]

# =============================================================================
# SITEMAP VALIDATION
# =============================================================================

SITEMAP_LOCATIONS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap/sitemap.xml",
    "/sitemaps/sitemap.xml",
]

SITEMAP_REQUIREMENTS = {
    "max_urls": 50000,  # Per sitemap file
    "max_size_mb": 50,  # Uncompressed size
    "required_tags": ["loc"],
    "recommended_tags": ["lastmod", "changefreq", "priority"],
}

# =============================================================================
# SCHEMA MARKUP (JSON-LD)
# =============================================================================

COMMON_SCHEMA_TYPES = [
    "Organization",
    "WebSite",
    "WebPage",
    "Article",
    "Product",
    "LocalBusiness",
    "Person",
    "BreadcrumbList",
    "FAQPage",
    "HowTo",
    "Review",
    "Event",
    "Recipe",
    "VideoObject",
]

REQUIRED_SCHEMA_PROPERTIES = {
    "Organization": ["name", "url"],
    "WebSite": ["name", "url"],
    "Article": ["headline", "datePublished", "author"],
    "Product": ["name", "description"],
    "LocalBusiness": ["name", "address", "telephone"],
    "BreadcrumbList": ["itemListElement"],
    "FAQPage": ["mainEntity"],
}

# =============================================================================
# OPEN GRAPH TAGS
# =============================================================================

REQUIRED_OG_TAGS = [
    "og:title",
    "og:type",
    "og:url",
    "og:image",
]

RECOMMENDED_OG_TAGS = [
    "og:description",
    "og:site_name",
    "og:locale",
    "og:image:width",
    "og:image:height",
    "og:image:alt",
]

OG_IMAGE_REQUIREMENTS = {
    "min_width": 200,
    "min_height": 200,
    "recommended_width": 1200,
    "recommended_height": 630,
    "max_size_mb": 8,
}

# =============================================================================
# TWITTER CARDS
# =============================================================================

REQUIRED_TWITTER_TAGS = [
    "twitter:card",
]

RECOMMENDED_TWITTER_TAGS = [
    "twitter:title",
    "twitter:description",
    "twitter:image",
    "twitter:site",
    "twitter:creator",
]

TWITTER_CARD_TYPES = [
    "summary",
    "summary_large_image",
    "app",
    "player",
]

# =============================================================================
# HREFLANG TAGS
# =============================================================================

VALID_LANGUAGE_CODES = [
    "en", "en-US", "en-GB", "en-AU", "en-CA",
    "es", "es-ES", "es-MX", "es-AR",
    "fr", "fr-FR", "fr-CA",
    "de", "de-DE", "de-AT", "de-CH",
    "it", "it-IT",
    "pt", "pt-BR", "pt-PT",
    "nl", "nl-NL",
    "ru", "ru-RU",
    "ja", "ja-JP",
    "zh", "zh-CN", "zh-TW", "zh-HK",
    "ko", "ko-KR",
    "ar", "ar-SA", "ar-AE",
    "hi", "hi-IN",
    "x-default",
]

# =============================================================================
# PERFORMANCE METRICS THRESHOLDS
# =============================================================================

CORE_WEB_VITALS = {
    "LCP": {  # Largest Contentful Paint
        "good": 2.5,  # seconds
        "needs_improvement": 4.0,
        "poor": 4.0,  # Above this is poor
    },
    "FID": {  # First Input Delay
        "good": 100,  # milliseconds
        "needs_improvement": 300,
        "poor": 300,
    },
    "INP": {  # Interaction to Next Paint (replacing FID)
        "good": 200,  # milliseconds
        "needs_improvement": 500,
        "poor": 500,
    },
    "CLS": {  # Cumulative Layout Shift
        "good": 0.1,
        "needs_improvement": 0.25,
        "poor": 0.25,
    },
}

PAGESPEED_SCORE_THRESHOLDS = {
    "good": 90,
    "needs_improvement": 50,
    "poor": 0,
}

# =============================================================================
# CONTENT ANALYSIS
# =============================================================================

CONTENT_REQUIREMENTS = {
    "min_word_count": 300,
    "optimal_word_count": (1000, 2500),
    "max_keyword_density": 3.0,  # Percentage
    "min_keyword_density": 0.5,
}

# Readability targets (Flesch-Kincaid)
READABILITY_TARGETS = {
    "min_score": 60,  # 60-70 is considered standard
    "optimal_score": (60, 80),
}

# =============================================================================
# LINK ANALYSIS
# =============================================================================

LINK_RULES = {
    "max_internal_links": 100,
    "max_external_links": 50,
    "external_nofollow_recommended": False,
    "sponsored_rel_for_ads": True,
    "ugc_rel_for_user_content": True,
}

# =============================================================================
# SECURITY-RELATED SEO
# =============================================================================

HTTPS_REQUIREMENTS = {
    "required": True,
    "hsts_recommended": True,
    "mixed_content_forbidden": True,
}

# =============================================================================
# MOBILE FRIENDLINESS
# =============================================================================

MOBILE_REQUIREMENTS = {
    "viewport_meta_required": True,
    "responsive_design": True,
    "min_tap_target_size": 48,  # pixels
    "min_font_size": 16,  # pixels
}

VIEWPORT_META_PATTERN = r'width=device-width'

# =============================================================================
# CANONICALIZATION
# =============================================================================

CANONICAL_RULES = {
    "self_referencing_required": True,
    "single_canonical_required": True,
    "absolute_url_required": True,
}

# =============================================================================
# REDIRECT CHAINS
# =============================================================================

REDIRECT_RULES = {
    "max_chain_length": 2,
    "prefer_301_over_302": True,
    "avoid_redirect_loops": True,
}

# =============================================================================
# COMMON SEO ISSUES
# =============================================================================

COMMON_SEO_ISSUES = {
    "missing_title": "Page is missing a title tag",
    "duplicate_title": "Multiple pages have the same title",
    "title_too_short": "Title tag is too short (less than 30 characters)",
    "title_too_long": "Title tag is too long (more than 60 characters)",
    "missing_description": "Page is missing a meta description",
    "description_too_short": "Meta description is too short",
    "description_too_long": "Meta description is too long",
    "missing_h1": "Page is missing an H1 tag",
    "multiple_h1": "Page has multiple H1 tags",
    "missing_alt_text": "Images are missing alt text",
    "broken_links": "Page contains broken links",
    "missing_canonical": "Page is missing a canonical tag",
    "missing_robots": "Site is missing robots.txt",
    "missing_sitemap": "Site is missing sitemap.xml",
    "slow_page_speed": "Page load time is too slow",
    "not_mobile_friendly": "Page is not mobile-friendly",
    "missing_ssl": "Site is not using HTTPS",
    "mixed_content": "Page contains mixed HTTP/HTTPS content",
    "redirect_chain": "Page has a redirect chain",
    "orphan_page": "Page has no internal links pointing to it",
    "thin_content": "Page has too little content",
    "keyword_stuffing": "Page appears to have keyword stuffing",
    "missing_schema": "Page is missing structured data markup",
    "missing_og_tags": "Page is missing Open Graph tags",
    "missing_twitter_cards": "Page is missing Twitter Card tags",
}

# =============================================================================
# USER AGENTS FOR TESTING
# =============================================================================

SEO_USER_AGENTS = {
    "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "googlebot_mobile": "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "bingbot": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "chrome_desktop": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "chrome_mobile": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
}
