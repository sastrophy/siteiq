"""
API Security Test Payloads

Payloads for testing modern API vulnerabilities including:
- GraphQL introspection
- Swagger/OpenAPI exposure
- Mass assignment attacks
- API versioning issues
"""

# Common GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/api/graphql/",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/gql",
    "/graphiql",
    "/playground",
    "/api/query",
    "/graphql/console",
    "/graphql/explorer",
]

# GraphQL introspection query (full schema dump)
GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""

# Simplified introspection query
GRAPHQL_INTROSPECTION_SIMPLE = """
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
"""

# Query to get all types
GRAPHQL_TYPES_QUERY = """
{
  __schema {
    types {
      name
      kind
      description
    }
  }
}
"""

# Swagger/OpenAPI documentation paths
SWAGGER_PATHS = [
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/",
    "/swagger/index.html",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger-ui/index.html",
    "/api-docs",
    "/api-docs/",
    "/api-docs.json",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api/swagger-ui.html",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi/",
    "/api/openapi.json",
    "/docs",
    "/docs/",
    "/redoc",
    "/redoc/",
    "/api/docs",
    "/api/v1/docs",
    "/api/v2/docs",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/.well-known/openapi.json",
    "/api-explorer",
    "/api-explorer/",
    "/developer/docs",
    "/apidocs",
    "/apidocs/",
]

# Indicators of valid Swagger/OpenAPI documentation
SWAGGER_INDICATORS = [
    "swagger",
    "openapi",
    "paths",
    "definitions",
    "components",
    "schemas",
    "info",
    "basePath",
    "host",
    "securityDefinitions",
    "api-docs",
]

# Mass assignment attack payloads - common privilege escalation parameters
MASS_ASSIGNMENT_PAYLOADS = [
    # Admin/Role escalation
    {"is_admin": True},
    {"isAdmin": True},
    {"admin": True},
    {"is_superuser": True},
    {"isSuperuser": True},
    {"superuser": True},
    {"role": "admin"},
    {"role": "administrator"},
    {"role": "superuser"},
    {"role": "root"},
    {"user_role": "admin"},
    {"userRole": "admin"},
    {"access_level": "admin"},
    {"accessLevel": "admin"},
    {"privilege": "admin"},
    {"privileges": ["admin", "write", "delete"]},
    {"permissions": ["admin", "all"]},
    {"is_staff": True},
    {"isStaff": True},
    {"staff": True},
    {"is_moderator": True},
    {"moderator": True},

    # Account verification bypass
    {"verified": True},
    {"is_verified": True},
    {"isVerified": True},
    {"email_verified": True},
    {"emailVerified": True},
    {"phone_verified": True},
    {"confirmed": True},
    {"is_confirmed": True},
    {"active": True},
    {"is_active": True},
    {"isActive": True},
    {"enabled": True},
    {"is_enabled": True},
    {"approved": True},
    {"is_approved": True},

    # Account status manipulation
    {"status": "active"},
    {"status": "approved"},
    {"status": "premium"},
    {"account_status": "active"},
    {"accountStatus": "active"},
    {"banned": False},
    {"is_banned": False},
    {"isBanned": False},
    {"suspended": False},
    {"is_suspended": False},
    {"locked": False},
    {"is_locked": False},

    # Premium/subscription bypass
    {"premium": True},
    {"is_premium": True},
    {"isPremium": True},
    {"pro": True},
    {"is_pro": True},
    {"subscription": "premium"},
    {"subscription_type": "enterprise"},
    {"subscriptionType": "enterprise"},
    {"plan": "enterprise"},
    {"tier": "enterprise"},
    {"paid": True},
    {"is_paid": True},

    # ID manipulation
    {"id": 1},
    {"user_id": 1},
    {"userId": 1},
    {"owner_id": 1},
    {"ownerId": 1},
    {"created_by": 1},
    {"createdBy": 1},
    {"organization_id": 1},
    {"organizationId": 1},
    {"tenant_id": 1},
    {"tenantId": 1},

    # Credit/balance manipulation
    {"balance": 999999},
    {"credits": 999999},
    {"points": 999999},
    {"coins": 999999},
    {"tokens": 999999},
    {"quota": 999999},
    {"limit": 999999},

    # Password/security bypass
    {"password_reset_required": False},
    {"passwordResetRequired": False},
    {"mfa_enabled": False},
    {"mfaEnabled": False},
    {"two_factor": False},
    {"twoFactor": False},
    {"otp_required": False},
]

# Common API endpoints to test mass assignment
MASS_ASSIGNMENT_ENDPOINTS = [
    "/api/user",
    "/api/users",
    "/api/profile",
    "/api/account",
    "/api/settings",
    "/api/me",
    "/api/v1/user",
    "/api/v1/users",
    "/api/v1/profile",
    "/api/v1/account",
    "/api/v2/user",
    "/api/v2/users",
    "/user",
    "/users",
    "/profile",
    "/account",
    "/settings",
    "/me",
    "/api/register",
    "/api/signup",
    "/api/update",
    "/api/edit",
]

# HTTP methods to test for mass assignment
MASS_ASSIGNMENT_METHODS = ["POST", "PUT", "PATCH"]

# API versioning endpoints to check for deprecated/insecure versions
API_VERSION_PATHS = [
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/api/1.0/",
    "/api/2.0/",
    "/api/latest/",
    "/api/beta/",
    "/api/alpha/",
    "/api/legacy/",
    "/api/old/",
    "/api/deprecated/",
]

# CORS misconfiguration test origins
CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://localhost",
    "https://127.0.0.1",
]

# Rate limiting test - endpoints to probe
RATE_LIMIT_ENDPOINTS = [
    "/api/login",
    "/api/auth",
    "/api/authenticate",
    "/api/token",
    "/api/password/reset",
    "/api/forgot-password",
    "/api/register",
    "/api/signup",
    "/api/otp",
    "/api/verify",
]

# JWT-related paths
JWT_PATHS = [
    "/api/token",
    "/api/auth/token",
    "/api/jwt",
    "/api/refresh",
    "/api/auth/refresh",
    "/oauth/token",
    "/oauth2/token",
    "/auth/token",
    "/login",
    "/api/login",
]

# Common REST API info disclosure paths
API_INFO_DISCLOSURE_PATHS = [
    "/api",
    "/api/",
    "/api/health",
    "/api/status",
    "/api/version",
    "/api/info",
    "/api/debug",
    "/api/config",
    "/api/metrics",
    "/api/stats",
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/mappings",
    "/actuator/beans",
    "/manage",
    "/management",
    "/admin/api",
    "/_health",
    "/_status",
    "/healthz",
    "/readyz",
    "/livez",
]
