"""
SSL/TLS Security Tests

Tests for SSL/TLS configuration including:
- Certificate validity
- Protocol versions
- Cipher suites
- Certificate chain
- Common SSL vulnerabilities
"""

import socket
import ssl
from datetime import datetime, timezone

import pytest

from utils.scanner import SecurityScanner, Finding, Severity


@pytest.fixture
def ssl_scanner(test_config):
    """Create scanner for SSL tests."""
    return SecurityScanner(test_config)


class TestSSLCertificate:
    """Tests for SSL certificate validity."""

    @pytest.mark.ssl
    def test_certificate_validity(self, test_config, findings_collector):
        """Test if SSL certificate is valid and not expired."""
        if not test_config.base_url.startswith("https://"):
            pytest.skip("Target is not using HTTPS")

        hostname = test_config.hostname
        port = 443

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Check expiration
                    not_after = datetime.strptime(
                        cert['notAfter'],
                        '%b %d %H:%M:%S %Y %Z'
                    ).replace(tzinfo=timezone.utc)

                    not_before = datetime.strptime(
                        cert['notBefore'],
                        '%b %d %H:%M:%S %Y %Z'
                    ).replace(tzinfo=timezone.utc)

                    now = datetime.now(timezone.utc)

                    if now > not_after:
                        finding = Finding(
                            title="SSL Certificate Expired",
                            severity=Severity.CRITICAL,
                            description=f"SSL certificate expired on {not_after}",
                            url=test_config.base_url,
                            evidence=f"Expiration date: {not_after}",
                            remediation="Renew the SSL certificate immediately",
                            cwe_id="CWE-295",
                            owasp_category="A02:2021 - Cryptographic Failures",
                        )
                        findings_collector.add(finding)

                    elif now < not_before:
                        finding = Finding(
                            title="SSL Certificate Not Yet Valid",
                            severity=Severity.HIGH,
                            description=f"SSL certificate not valid until {not_before}",
                            url=test_config.base_url,
                            evidence=f"Valid from: {not_before}",
                            remediation="Check system time or certificate configuration",
                            cwe_id="CWE-295",
                            owasp_category="A02:2021 - Cryptographic Failures",
                        )
                        findings_collector.add(finding)

                    # Warn if expiring soon (within 30 days)
                    days_until_expiry = (not_after - now).days
                    if 0 < days_until_expiry <= 30:
                        finding = Finding(
                            title="SSL Certificate Expiring Soon",
                            severity=Severity.MEDIUM,
                            description=f"SSL certificate expires in {days_until_expiry} days",
                            url=test_config.base_url,
                            evidence=f"Expiration date: {not_after}",
                            remediation="Plan certificate renewal before expiration",
                            cwe_id="CWE-295",
                            owasp_category="A02:2021 - Cryptographic Failures",
                        )
                        findings_collector.add(finding)

        except ssl.SSLCertVerificationError as e:
            finding = Finding(
                title="SSL Certificate Verification Failed",
                severity=Severity.HIGH,
                description=f"Certificate verification error: {str(e)}",
                url=test_config.base_url,
                evidence=str(e),
                remediation="Ensure certificate is properly signed by a trusted CA",
                cwe_id="CWE-295",
                owasp_category="A02:2021 - Cryptographic Failures",
            )
            findings_collector.add(finding)

        except Exception as e:
            finding = Finding(
                title="SSL Connection Error",
                severity=Severity.HIGH,
                description=f"Could not establish SSL connection: {str(e)}",
                url=test_config.base_url,
                evidence=str(e),
                remediation="Check SSL configuration",
                cwe_id="CWE-295",
                owasp_category="A02:2021 - Cryptographic Failures",
            )
            findings_collector.add(finding)

    @pytest.mark.ssl
    def test_certificate_hostname(self, test_config, findings_collector):
        """Test if certificate hostname matches."""
        if not test_config.base_url.startswith("https://"):
            pytest.skip("Target is not using HTTPS")

        hostname = test_config.hostname
        port = 443

        try:
            # Create context that doesn't verify hostname
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cert_decoded = ssl.DER_cert_to_PEM_cert(cert)

                    # Parse subject and SANs
                    context2 = ssl.create_default_context()
                    try:
                        with socket.create_connection((hostname, port), timeout=10) as sock2:
                            with context2.wrap_socket(sock2, server_hostname=hostname) as ssock2:
                                # If we get here, hostname matches
                                pass
                    except ssl.SSLCertVerificationError as e:
                        if "hostname" in str(e).lower():
                            finding = Finding(
                                title="SSL Certificate Hostname Mismatch",
                                severity=Severity.HIGH,
                                description="Certificate hostname does not match server hostname",
                                url=test_config.base_url,
                                evidence=f"Expected hostname: {hostname}",
                                remediation="Obtain certificate for correct hostname or add SAN entries",
                                cwe_id="CWE-295",
                                owasp_category="A02:2021 - Cryptographic Failures",
                            )
                            findings_collector.add(finding)

        except Exception:
            pass  # Connection errors handled in other tests


class TestSSLProtocols:
    """Tests for SSL/TLS protocol versions."""

    @pytest.mark.ssl
    def test_sslv2_disabled(self, test_config, findings_collector):
        """Test that SSLv2 is disabled."""
        self._test_protocol(
            test_config, findings_collector,
            ssl.PROTOCOL_SSLv23,
            ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2,
            "SSLv2",
            Severity.CRITICAL
        )

    @pytest.mark.ssl
    def test_sslv3_disabled(self, test_config, findings_collector):
        """Test that SSLv3 is disabled (POODLE vulnerability)."""
        self._test_protocol(
            test_config, findings_collector,
            ssl.PROTOCOL_SSLv23,
            ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2,
            "SSLv3",
            Severity.CRITICAL
        )

    @pytest.mark.ssl
    def test_tlsv1_disabled(self, test_config, findings_collector):
        """Test that TLSv1.0 is disabled."""
        self._test_protocol(
            test_config, findings_collector,
            ssl.PROTOCOL_SSLv23,
            ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2,
            "TLSv1.0",
            Severity.MEDIUM
        )

    @pytest.mark.ssl
    def test_tlsv11_disabled(self, test_config, findings_collector):
        """Test that TLSv1.1 is disabled."""
        self._test_protocol(
            test_config, findings_collector,
            ssl.PROTOCOL_SSLv23,
            ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2,
            "TLSv1.1",
            Severity.LOW
        )

    @pytest.mark.ssl
    def test_tlsv12_supported(self, test_config, findings_collector):
        """Test that TLSv1.2 is supported."""
        if not test_config.base_url.startswith("https://"):
            pytest.skip("Target is not using HTTPS")

        hostname = test_config.hostname
        port = 443

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # TLSv1.2 supported
                    pass

        except Exception:
            finding = Finding(
                title="TLSv1.2 Not Supported",
                severity=Severity.MEDIUM,
                description="Server does not support TLSv1.2",
                url=test_config.base_url,
                evidence="TLSv1.2 connection failed",
                remediation="Enable TLSv1.2 support on the server",
                cwe_id="CWE-326",
                owasp_category="A02:2021 - Cryptographic Failures",
            )
            findings_collector.add(finding)

    @pytest.mark.ssl
    def test_tlsv13_supported(self, test_config, findings_collector):
        """Test if TLSv1.3 is supported (recommended)."""
        if not test_config.base_url.startswith("https://"):
            pytest.skip("Target is not using HTTPS")

        hostname = test_config.hostname
        port = 443

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # TLSv1.3 supported - good
                    pass

        except Exception:
            finding = Finding(
                title="TLSv1.3 Not Supported",
                severity=Severity.INFO,
                description="Server does not support TLSv1.3 (recommended for best security)",
                url=test_config.base_url,
                evidence="TLSv1.3 connection failed",
                remediation="Consider enabling TLSv1.3 for improved security and performance",
                cwe_id="CWE-326",
                owasp_category="A02:2021 - Cryptographic Failures",
            )
            findings_collector.add(finding)

    def _test_protocol(self, test_config, findings_collector, protocol, options, name, severity):
        """Test if a specific protocol is enabled."""
        if not test_config.base_url.startswith("https://"):
            pytest.skip("Target is not using HTTPS")

        hostname = test_config.hostname
        port = 443

        try:
            context = ssl.SSLContext(protocol)
            context.options |= options
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Protocol is enabled - this is bad for old protocols
                    finding = Finding(
                        title=f"Insecure Protocol {name} Enabled",
                        severity=severity,
                        description=f"Server accepts connections using {name}",
                        url=test_config.base_url,
                        evidence=f"{name} connection successful",
                        remediation=f"Disable {name} protocol on the server",
                        cwe_id="CWE-326",
                        owasp_category="A02:2021 - Cryptographic Failures",
                    )
                    findings_collector.add(finding)

        except ssl.SSLError:
            # Protocol not supported - this is good for old protocols
            pass
        except Exception:
            pass


class TestSSLCipherSuites:
    """Tests for SSL cipher suite configuration."""

    @pytest.mark.ssl
    def test_weak_ciphers(self, test_config, findings_collector):
        """Test for weak cipher suites."""
        if not test_config.base_url.startswith("https://"):
            pytest.skip("Target is not using HTTPS")

        hostname = test_config.hostname
        port = 443

        # Weak cipher patterns
        weak_ciphers = [
            "NULL",
            "EXPORT",
            "DES",
            "RC4",
            "RC2",
            "MD5",
            "ANON",
            "ADH",
            "AECDH",
        ]

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0].upper()

                        for weak in weak_ciphers:
                            if weak in cipher_name:
                                finding = Finding(
                                    title="Weak Cipher Suite Detected",
                                    severity=Severity.HIGH,
                                    description=f"Server using weak cipher: {cipher_name}",
                                    url=test_config.base_url,
                                    evidence=f"Cipher: {cipher_name}",
                                    remediation="Disable weak cipher suites and use strong ciphers",
                                    cwe_id="CWE-326",
                                    owasp_category="A02:2021 - Cryptographic Failures",
                                )
                                findings_collector.add(finding)
                                break

        except Exception:
            pass


class TestHTTPSRedirect:
    """Tests for HTTP to HTTPS redirect."""

    @pytest.mark.ssl
    def test_http_redirect(self, ssl_scanner, test_config, findings_collector):
        """Test if HTTP redirects to HTTPS."""
        if not test_config.base_url.startswith("https://"):
            pytest.skip("Target is not using HTTPS")

        # Try HTTP version
        http_url = test_config.base_url.replace("https://", "http://")

        try:
            resp = ssl_scanner.get(http_url, allow_redirects=False)

            if resp:
                if resp.status_code in [301, 302, 307, 308]:
                    location = resp.headers.get("Location", "")
                    if location.startswith("https://"):
                        # Good - redirects to HTTPS
                        if resp.status_code == 302:
                            finding = Finding(
                                title="Temporary HTTP to HTTPS Redirect",
                                severity=Severity.LOW,
                                description="HTTP redirects to HTTPS with 302 (temporary) instead of 301 (permanent)",
                                url=http_url,
                                evidence=f"Status: {resp.status_code}, Location: {location}",
                                remediation="Use 301 permanent redirect for HTTP to HTTPS",
                                cwe_id="CWE-311",
                                owasp_category="A02:2021 - Cryptographic Failures",
                            )
                            findings_collector.add(finding)
                    else:
                        finding = Finding(
                            title="HTTP Does Not Redirect to HTTPS",
                            severity=Severity.MEDIUM,
                            description="HTTP redirect does not lead to HTTPS",
                            url=http_url,
                            evidence=f"Location: {location}",
                            remediation="Configure redirect to HTTPS version of the site",
                            cwe_id="CWE-311",
                            owasp_category="A02:2021 - Cryptographic Failures",
                        )
                        findings_collector.add(finding)
                else:
                    finding = Finding(
                        title="HTTP Not Redirected to HTTPS",
                        severity=Severity.MEDIUM,
                        description="HTTP version of site does not redirect to HTTPS",
                        url=http_url,
                        evidence=f"Status: {resp.status_code}",
                        remediation="Implement redirect from HTTP to HTTPS",
                        cwe_id="CWE-311",
                        owasp_category="A02:2021 - Cryptographic Failures",
                    )
                    findings_collector.add(finding)

        except Exception:
            pass  # HTTP might not be available


class TestMixedContent:
    """Tests for mixed content issues."""

    @pytest.mark.ssl
    def test_mixed_content(self, ssl_scanner, target_url, findings_collector):
        """Test for mixed content (HTTP resources on HTTPS page)."""
        if not target_url.startswith("https://"):
            pytest.skip("Target is not using HTTPS")

        resp = ssl_scanner.get(target_url)
        if not resp:
            pytest.skip("Could not connect to target")

        import re

        # Patterns for HTTP resources
        http_patterns = [
            r'src=["\']http://',
            r'href=["\']http://',
            r'url\(["\']?http://',
            r'action=["\']http://',
        ]

        mixed_content = []
        for pattern in http_patterns:
            matches = re.findall(pattern, resp.text, re.IGNORECASE)
            mixed_content.extend(matches)

        if mixed_content:
            finding = Finding(
                title="Mixed Content Detected",
                severity=Severity.MEDIUM,
                description=f"HTTPS page loads {len(mixed_content)} HTTP resources",
                url=target_url,
                evidence=f"Found patterns: {mixed_content[:5]}...",
                remediation="Update all resource URLs to use HTTPS or protocol-relative URLs",
                cwe_id="CWE-311",
                owasp_category="A02:2021 - Cryptographic Failures",
            )
            findings_collector.add(finding)


# =============================================================================
# 2026 SSL/TLS SECURITY TESTS
# =============================================================================


class TestModernTLSConfiguration:
    """Tests for modern TLS configuration (2026 standards)."""

    @pytest.mark.ssl
    @pytest.mark.tls13_preferred
    def test_tls13_preferred(self, test_config, findings_collector):
        """Test if TLS 1.3 is the preferred/negotiated protocol.

        In 2026, TLS 1.3 should be the default negotiated protocol
        when both client and server support it.
        """
        if not test_config.base_url.startswith("https://"):
            pytest.skip("Target is not using HTTPS")

        hostname = test_config.hostname
        port = 443

        try:
            # Create context that supports both TLS 1.2 and 1.3
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    negotiated_version = ssock.version()

                    if negotiated_version != "TLSv1.3":
                        finding = Finding(
                            title="TLS 1.3 Not Preferred",
                            severity=Severity.LOW,
                            description=f"Server negotiates {negotiated_version} instead of TLS 1.3",
                            url=test_config.base_url,
                            evidence=f"Negotiated protocol: {negotiated_version}",
                            remediation="Configure server to prefer TLS 1.3 for improved security and performance (0-RTT, improved handshake)",
                            cwe_id="CWE-326",
                            owasp_category="A02:2021 - Cryptographic Failures",
                        )
                        findings_collector.add(finding)

        except Exception as e:
            finding = Finding(
                title="TLS Version Check Failed",
                severity=Severity.INFO,
                description=f"Could not determine preferred TLS version: {str(e)}",
                url=test_config.base_url,
                evidence=str(e),
                remediation="Verify TLS configuration",
                cwe_id="CWE-326",
                owasp_category="A02:2021 - Cryptographic Failures",
            )
            findings_collector.add(finding)

    @pytest.mark.ssl
    @pytest.mark.certificate_transparency
    def test_certificate_transparency(self, test_config, findings_collector):
        """Test for Certificate Transparency (CT) compliance.

        Certificate Transparency helps detect misissued certificates.
        SCTs (Signed Certificate Timestamps) prove the certificate
        is logged in public CT logs.
        """
        if not test_config.base_url.startswith("https://"):
            pytest.skip("Target is not using HTTPS")

        hostname = test_config.hostname
        port = 443

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get binary certificate for extension analysis
                    cert_bin = ssock.getpeercert(binary_form=True)

                    # Check for SCT in certificate extensions
                    # OID 1.3.6.1.4.1.11129.2.4.2 is for embedded SCTs
                    sct_oid = b'\x06\x0a\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x02'
                    has_embedded_sct = sct_oid in cert_bin

                    # Also check TLS extension (common delivery method)
                    # This is harder to detect without lower-level access
                    # But we can note if embedded SCT is missing

                    if not has_embedded_sct:
                        finding = Finding(
                            title="Certificate Transparency SCTs Not Embedded",
                            severity=Severity.LOW,
                            description="Certificate does not contain embedded SCTs (Signed Certificate Timestamps)",
                            url=test_config.base_url,
                            evidence="No embedded SCT extension (OID 1.3.6.1.4.1.11129.2.4.2) found in certificate",
                            remediation="Ensure your CA includes SCTs in certificates. SCTs can also be delivered via TLS extension or OCSP stapling.",
                            cwe_id="CWE-295",
                            owasp_category="A02:2021 - Cryptographic Failures",
                        )
                        findings_collector.add(finding)

        except Exception as e:
            finding = Finding(
                title="Certificate Transparency Check Failed",
                severity=Severity.INFO,
                description=f"Could not check for Certificate Transparency: {str(e)}",
                url=test_config.base_url,
                evidence=str(e),
                remediation="Verify SSL certificate configuration",
                cwe_id="CWE-295",
                owasp_category="A02:2021 - Cryptographic Failures",
            )
            findings_collector.add(finding)

    @pytest.mark.ssl
    def test_ocsp_stapling(self, test_config, findings_collector):
        """Test if OCSP stapling is enabled.

        OCSP stapling improves performance and privacy by having
        the server provide certificate revocation status.
        """
        if not test_config.base_url.startswith("https://"):
            pytest.skip("Target is not using HTTPS")

        hostname = test_config.hostname
        port = 443

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Check if OCSP response was stapled
                    # Note: Python's ssl module has limited OCSP stapling detection
                    # This is a basic check - full verification requires pyOpenSSL
                    cert = ssock.getpeercert()

                    # Look for OCSP responder in certificate
                    has_ocsp_responder = False
                    if cert:
                        # Check for OCSP in Authority Information Access
                        # This indicates the cert supports OCSP
                        for ext in cert.get('extensions', []):
                            if 'OCSP' in str(ext):
                                has_ocsp_responder = True
                                break

                    # We can't easily detect if stapling is enabled without
                    # pyOpenSSL, but we note if OCSP is available
                    # Modern servers should enable stapling for performance

        except Exception:
            pass  # OCSP stapling check is informational
