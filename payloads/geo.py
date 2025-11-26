"""
SiteIQ GEO Testing Payloads and Configuration

Test data, headers, and configuration for geographic testing.
"""

# =============================================================================
# GEO REGION HEADERS
# =============================================================================

GEO_HEADERS = {
    "us-east": {
        "Accept-Language": "en-US,en;q=0.9",
        "X-Forwarded-For": "54.210.0.1",  # AWS us-east
        "CF-IPCountry": "US",
        "X-Country-Code": "US",
    },
    "us-west": {
        "Accept-Language": "en-US,en;q=0.9",
        "X-Forwarded-For": "54.183.0.1",  # AWS us-west
        "CF-IPCountry": "US",
        "X-Country-Code": "US",
    },
    "uk": {
        "Accept-Language": "en-GB,en;q=0.9",
        "X-Forwarded-For": "52.56.0.1",  # AWS eu-west-2
        "CF-IPCountry": "GB",
        "X-Country-Code": "GB",
    },
    "de": {
        "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
        "X-Forwarded-For": "52.59.0.1",  # AWS eu-central-1
        "CF-IPCountry": "DE",
        "X-Country-Code": "DE",
    },
    "fr": {
        "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
        "X-Forwarded-For": "52.47.0.1",  # AWS eu-west-3
        "CF-IPCountry": "FR",
        "X-Country-Code": "FR",
    },
    "jp": {
        "Accept-Language": "ja-JP,ja;q=0.9,en;q=0.8",
        "X-Forwarded-For": "52.68.0.1",  # AWS ap-northeast-1
        "CF-IPCountry": "JP",
        "X-Country-Code": "JP",
    },
    "au": {
        "Accept-Language": "en-AU,en;q=0.9",
        "X-Forwarded-For": "52.62.0.1",  # AWS ap-southeast-2
        "CF-IPCountry": "AU",
        "X-Country-Code": "AU",
    },
    "br": {
        "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
        "X-Forwarded-For": "52.67.0.1",  # AWS sa-east-1
        "CF-IPCountry": "BR",
        "X-Country-Code": "BR",
    },
    "in": {
        "Accept-Language": "en-IN,en;q=0.9,hi;q=0.8",
        "X-Forwarded-For": "52.66.0.1",  # AWS ap-south-1
        "CF-IPCountry": "IN",
        "X-Country-Code": "IN",
    },
    "sg": {
        "Accept-Language": "en-SG,en;q=0.9,zh;q=0.8",
        "X-Forwarded-For": "52.74.0.1",  # AWS ap-southeast-1
        "CF-IPCountry": "SG",
        "X-Country-Code": "SG",
    },
    "ae": {
        "Accept-Language": "ar-AE,ar;q=0.9,en;q=0.8",
        "X-Forwarded-For": "3.28.0.1",  # AWS me-south-1
        "CF-IPCountry": "AE",
        "X-Country-Code": "AE",
    },
    "ca": {
        "Accept-Language": "en-CA,en;q=0.9,fr;q=0.8",
        "X-Forwarded-For": "52.60.0.1",  # AWS ca-central-1
        "CF-IPCountry": "CA",
        "X-Country-Code": "CA",
    },
}

# =============================================================================
# REGION METADATA
# =============================================================================

REGION_INFO = {
    "us-east": {
        "name": "US East (Virginia)",
        "country": "United States",
        "country_code": "US",
        "currency": "USD",
        "currency_symbol": "$",
        "timezone": "America/New_York",
        "language": "en-US",
    },
    "us-west": {
        "name": "US West (California)",
        "country": "United States",
        "country_code": "US",
        "currency": "USD",
        "currency_symbol": "$",
        "timezone": "America/Los_Angeles",
        "language": "en-US",
    },
    "uk": {
        "name": "United Kingdom",
        "country": "United Kingdom",
        "country_code": "GB",
        "currency": "GBP",
        "currency_symbol": "£",
        "timezone": "Europe/London",
        "language": "en-GB",
    },
    "de": {
        "name": "Germany",
        "country": "Germany",
        "country_code": "DE",
        "currency": "EUR",
        "currency_symbol": "€",
        "timezone": "Europe/Berlin",
        "language": "de-DE",
    },
    "fr": {
        "name": "France",
        "country": "France",
        "country_code": "FR",
        "currency": "EUR",
        "currency_symbol": "€",
        "timezone": "Europe/Paris",
        "language": "fr-FR",
    },
    "jp": {
        "name": "Japan",
        "country": "Japan",
        "country_code": "JP",
        "currency": "JPY",
        "currency_symbol": "¥",
        "timezone": "Asia/Tokyo",
        "language": "ja-JP",
    },
    "au": {
        "name": "Australia",
        "country": "Australia",
        "country_code": "AU",
        "currency": "AUD",
        "currency_symbol": "$",
        "timezone": "Australia/Sydney",
        "language": "en-AU",
    },
    "br": {
        "name": "Brazil",
        "country": "Brazil",
        "country_code": "BR",
        "currency": "BRL",
        "currency_symbol": "R$",
        "timezone": "America/Sao_Paulo",
        "language": "pt-BR",
    },
    "in": {
        "name": "India",
        "country": "India",
        "country_code": "IN",
        "currency": "INR",
        "currency_symbol": "₹",
        "timezone": "Asia/Kolkata",
        "language": "en-IN",
    },
    "sg": {
        "name": "Singapore",
        "country": "Singapore",
        "country_code": "SG",
        "currency": "SGD",
        "currency_symbol": "$",
        "timezone": "Asia/Singapore",
        "language": "en-SG",
    },
    "ae": {
        "name": "UAE",
        "country": "United Arab Emirates",
        "country_code": "AE",
        "currency": "AED",
        "currency_symbol": "د.إ",
        "timezone": "Asia/Dubai",
        "language": "ar-AE",
    },
    "ca": {
        "name": "Canada",
        "country": "Canada",
        "country_code": "CA",
        "currency": "CAD",
        "currency_symbol": "$",
        "timezone": "America/Toronto",
        "language": "en-CA",
    },
}

# =============================================================================
# COMPLIANCE CHECKS BY REGION
# =============================================================================

COMPLIANCE_CHECKS = {
    # GDPR applies to EU countries
    "gdpr": ["uk", "de", "fr"],  # EU/UK

    # CCPA applies to California visitors
    "ccpa": ["us-west"],

    # LGPD applies to Brazil
    "lgpd": ["br"],

    # PDPA applies to Singapore
    "pdpa": ["sg"],
}

GDPR_INDICATORS = [
    "cookie consent",
    "cookie banner",
    "accept cookies",
    "privacy policy",
    "gdpr",
    "data protection",
    "cookie settings",
    "manage cookies",
    "reject all",
    "accept all",
]

CCPA_INDICATORS = [
    "do not sell",
    "california privacy",
    "ccpa",
    "opt out",
    "privacy rights",
    "personal information",
]

# =============================================================================
# CURRENCY PATTERNS
# =============================================================================

CURRENCY_PATTERNS = {
    "USD": [r"\$[\d,]+\.?\d*", r"USD", r"US\$"],
    "GBP": [r"£[\d,]+\.?\d*", r"GBP"],
    "EUR": [r"€[\d,]+\.?\d*", r"EUR"],
    "JPY": [r"¥[\d,]+", r"JPY", r"円"],
    "AUD": [r"A\$[\d,]+\.?\d*", r"AUD"],
    "CAD": [r"C\$[\d,]+\.?\d*", r"CAD"],
    "BRL": [r"R\$[\d,]+\.?\d*", r"BRL"],
    "INR": [r"₹[\d,]+\.?\d*", r"INR", r"Rs\.?"],
    "SGD": [r"S\$[\d,]+\.?\d*", r"SGD"],
    "AED": [r"AED[\d,]+\.?\d*", r"د\.إ"],
}

# =============================================================================
# LANGUAGE DETECTION PATTERNS
# =============================================================================

LANGUAGE_INDICATORS = {
    "en": ["the", "and", "is", "to", "of", "in", "for", "with"],
    "de": ["und", "der", "die", "das", "ist", "ein", "für", "mit"],
    "fr": ["et", "le", "la", "les", "de", "des", "pour", "avec"],
    "ja": ["の", "は", "を", "が", "に", "で", "と", "です"],
    "pt": ["o", "a", "os", "as", "de", "para", "com", "é"],
    "ar": ["و", "في", "من", "على", "إلى", "ال"],
}

# =============================================================================
# GEO TESTING THRESHOLDS
# =============================================================================

PERFORMANCE_THRESHOLDS = {
    "response_time_good": 1.0,  # seconds
    "response_time_acceptable": 3.0,  # seconds
    "response_time_poor": 5.0,  # seconds
}

# Maximum acceptable difference in response time between regions
MAX_RESPONSE_TIME_VARIANCE = 2.0  # seconds

# =============================================================================
# PROXY PROVIDERS CONFIGURATION
# =============================================================================

PROXY_PROVIDERS = {
    "brightdata": {
        "url_format": "http://{username}:{password}@brd.superproxy.io:22225",
        "country_param": "country",
    },
    "oxylabs": {
        "url_format": "http://{username}:{password}@pr.oxylabs.io:7777",
        "country_param": "cc",
    },
}
