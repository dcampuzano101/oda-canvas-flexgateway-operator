"""
ExposedAPI spec → Anypoint policy payload mapper.

Reads the ExposedAPI CRD spec and returns lists of Anypoint API Manager
policy payloads ready to be applied via anypoint_client.apply_policy().

Tier 1 policies: rate-limiting, CORS, OAS validation, API key verification.
Tier 2 policies: agentic-layer policies keyed by apiType (openapi, mcp, a2a).
JWT validation: Keycloak JWKS-based token verification with claims-to-headers.

Policy versions and payload structures are ported directly from
provision-customer-network-v2.sh and apply-security.sh.
"""

MULESOFT_ORG = "68ef9520-24e9-4cf2-b2f5-620025690913"

# Default minor versions used to resolve the latest patch via Exchange API
_POLICY_MINOR_VERSIONS = {
    "rate-limiting": "1.4",
    "ip-allowlist": "1.1",
    "cors": "1.0",
    "openapi-validator": "1.0",
    "header-injection": "1.3",
    "tracing": "1.1",
    "a-two-a-agent-card": "1.0",
    "agent-connection-telemetry": "1.0",
    "mcp-support": "1.0",
    "jwt-validation": "1.3",
}


def get_minor_version(policy_name: str) -> str:
    """Return the default minor version string for a well-known policy."""
    return _POLICY_MINOR_VERSIONS.get(policy_name, "1.0")


# ------------------------------------------------------------------
# Tier 1: CRD-driven standard policies
# ------------------------------------------------------------------

def map_tier1_policies(spec: dict) -> list[dict]:
    """
    Read rateLimit, CORS, OASValidation, apiKeyVerification from the
    ExposedAPI spec and return a list of policy descriptors.

    Each descriptor contains:
      groupId, assetId, minorVersion, config
    """
    policies: list[dict] = []

    rate_limit = spec.get("rateLimit", {})
    if rate_limit.get("enabled"):
        identifier = rate_limit.get("identifier", "IP")
        key_expr = {
            "IP": "#[attributes.remoteAddress]",
            "header": "#[attributes.headers['client_id']]",
        }.get(identifier, "#[attributes.remoteAddress]")

        policies.append({
            "groupId": MULESOFT_ORG,
            "assetId": "rate-limiting",
            "minorVersion": get_minor_version("rate-limiting"),
            "config": {
                "rateLimits": [{
                    "maximumRequests": int(rate_limit.get("limit", 100)),
                    "timePeriodInMilliseconds": _interval_ms(
                        rate_limit.get("interval", "pm")
                    ),
                }],
                "keySelector": key_expr,
                "clusterizable": True,
                "exposeHeaders": True,
            },
        })

    cors = spec.get("CORS", {})
    if cors.get("enabled"):
        policies.append({
            "groupId": MULESOFT_ORG,
            "assetId": "cors",
            "minorVersion": get_minor_version("cors"),
            "config": {
                "allowCredentials": cors.get("allowCredentials", False),
                "origins": cors.get("allowOrigins", "*"),
                "methods": "GET,POST,PUT,DELETE,OPTIONS",
                "headers": "Content-Type,Authorization",
                "exposedHeaders": "",
                "maxAge": 3600,
            },
        })

    oas = spec.get("OASValidation", {})
    if oas.get("requestEnabled") or oas.get("responseEnabled"):
        policies.append({
            "groupId": MULESOFT_ORG,
            "assetId": "openapi-validator",
            "minorVersion": get_minor_version("openapi-validator"),
            "config": {
                "validateRequest": oas.get("requestEnabled", False),
                "validateResponse": oas.get("responseEnabled", False),
                "allowUnspecifiedHeaders": oas.get(
                    "allowUnspecifiedHeaders", False
                ),
                "allowUnspecifiedQueryParams": oas.get(
                    "allowUnspecifiedQueryParams", False
                ),
                "allowUnspecifiedCookies": oas.get(
                    "allowUnspecifiedCookies", False
                ),
            },
        })

    return policies


# ------------------------------------------------------------------
# Tier 2: Agentic policies based on apiType
# ------------------------------------------------------------------

def map_tier2_policies(spec: dict, api_id="") -> list[dict]:
    """
    Return agentic policy payloads based on the ExposedAPI apiType field.

    apiType values: openapi, mcp, a2a
    """
    api_type = spec.get("apiType", "openapi")
    policies: list[dict] = []

    policies.append({
        "groupId": MULESOFT_ORG,
        "assetId": "tracing",
        "minorVersion": get_minor_version("tracing"),
        "config": {
            "spanName": f"[API] {spec.get('name', 'unknown')}",
            "sampling": {"client": 100, "random": 100, "overall": 100},
            "labels": [
                {
                    "type": "literal",
                    "name": "mulesoft.api.instance.id",
                    "defaultValue": str(api_id),
                },
                {
                    "type": "literal",
                    "name": "mulesoft.api.type",
                    "defaultValue": api_type,
                },
            ],
        },
    })

    policies.append({
        "groupId": MULESOFT_ORG,
        "assetId": "header-injection",
        "minorVersion": get_minor_version("header-injection"),
        "config": {
            "inboundHeaders": [
                {"key": "x-anypoint-api-instance-id", "value": str(api_id)},
            ],
            "outboundHeaders": [],
        },
    })

    if api_type == "a2a":
        policies.append({
            "groupId": MULESOFT_ORG,
            "assetId": "a-two-a-agent-card",
            "minorVersion": get_minor_version("a-two-a-agent-card"),
            "config": {"cardPath": "/.well-known/agent-card.json"},
        })

        policies.append({
            "groupId": MULESOFT_ORG,
            "assetId": "agent-connection-telemetry",
            "minorVersion": get_minor_version("agent-connection-telemetry"),
            "config": {
                "sourceAgentId": (
                    "#[attributes.headers['x-anypoint-api-instance-id']]"
                ),
            },
        })

    elif api_type == "mcp":
        policies.append({
            "groupId": MULESOFT_ORG,
            "assetId": "mcp-support",
            "minorVersion": get_minor_version("mcp-support"),
            "config": {},
        })

        policies.append({
            "groupId": MULESOFT_ORG,
            "assetId": "agent-connection-telemetry",
            "minorVersion": get_minor_version("agent-connection-telemetry"),
            "config": {
                "sourceAgentId": (
                    "#[attributes.headers['x-anypoint-api-instance-id']]"
                ),
            },
        })

    return policies


# ------------------------------------------------------------------
# JWT Validation — Keycloak JWKS
# ------------------------------------------------------------------

def build_jwt_validation_policy(
    jwks_url: str,
    audience: str,
    *,
    policy_version: str = "0.11.1",
) -> dict:
    """
    Return the JWT validation policy payload pointing to the Keycloak JWKS URL.

    Uses the exact payload structure proven in apply-security.sh, including
    claimsToHeaders that inject X-Agent-Scopes and X-Agent-Client-Id into
    downstream requests.
    """
    return {
        "groupId": MULESOFT_ORG,
        "assetId": "jwt-validation",
        "assetVersion": policy_version,
        "configurationData": {
            "jwtOrigin": "httpBearerAuthenticationHeader",
            "jwtExpression": "#[attributes.headers['jwt']]",
            "signingMethod": "rsa",
            "signingKeyLength": 256,
            "jwtKeyOrigin": "jwks",
            "textKey": "your-(256|384|512)-bit-secret",
            "jwksUrl": jwks_url,
            "jwksServiceTimeToLive": 60,
            "jwksServiceConnectionTimeout": 10000,
            "customKeyExpression": (
                "#[authentication.properties"
                "['key_to_your_public_pem_certificate']]"
            ),
            "skipClientIdValidation": True,
            "clientIdExpression": "#[vars.claimSet.client_id]",
            "validateAudClaim": True,
            "mandatoryAudClaim": True,
            "supportedAudiences": audience,
            "mandatoryExpClaim": True,
            "mandatoryNbfClaim": False,
            "validateCustomClaim": False,
            "claimsToHeaders": [
                {"claimName": "scope", "headerName": "X-Agent-Scopes"},
                {"claimName": "client_id", "headerName": "X-Agent-Client-Id"},
            ],
        },
        "pointcutData": None,
    }


# ------------------------------------------------------------------
# Policy config dispatcher — used by template-driven policy application
# ------------------------------------------------------------------

def build_policy_config(
    asset_id: str,
    spec: dict,
    api_id,
    jwks_url: str = "",
    audience: str = "",
) -> dict | None:
    """
    Return the configurationData dict for a given policy asset_id.
    Returns None for unknown policies (caller should skip).
    """
    if asset_id == "jwt-validation":
        jwt = build_jwt_validation_policy(jwks_url, audience)
        return jwt["configurationData"]

    if asset_id == "rate-limiting":
        rate_limit = spec.get("rateLimit", {})
        identifier = rate_limit.get("identifier", "IP")
        key_expr = {
            "IP": "#[attributes.remoteAddress]",
            "header": "#[attributes.headers['client_id']]",
        }.get(identifier, "#[attributes.remoteAddress]")
        return {
            "rateLimits": [{
                "maximumRequests": int(rate_limit.get("limit", 100)),
                "timePeriodInMilliseconds": _interval_ms(rate_limit.get("interval", "pm")),
            }],
            "keySelector": key_expr,
            "clusterizable": True,
            "exposeHeaders": True,
        }

    if asset_id == "cors":
        cors = spec.get("CORS", {})
        return {
            "allowCredentials": cors.get("allowCredentials", False),
            "origins": cors.get("allowOrigins", "*"),
            "methods": "GET,POST,PUT,DELETE,OPTIONS",
            "headers": "Content-Type,Authorization",
            "exposedHeaders": "",
            "maxAge": 3600,
        }

    if asset_id == "tracing":
        return {
            "spanName": f"[API] {spec.get('name', 'unknown')}",
            "sampling": {"client": 100, "random": 100, "overall": 100},
            "labels": [
                {"type": "literal", "name": "mulesoft.api.instance.id", "defaultValue": str(api_id)},
                {"type": "literal", "name": "mulesoft.api.type", "defaultValue": spec.get("apiType", "openapi")},
            ],
        }

    if asset_id == "header-injection":
        return {
            "inboundHeaders": [{"key": "x-anypoint-api-instance-id", "value": str(api_id)}],
            "outboundHeaders": [],
        }

    if asset_id == "a-two-a-agent-card":
        return {"cardPath": "/.well-known/agent-card.json"}

    if asset_id == "agent-connection-telemetry":
        return {"sourceAgentId": "#[attributes.headers['x-anypoint-api-instance-id']]"}

    if asset_id == "mcp-support":
        return {}

    return None


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _interval_ms(interval: str) -> int:
    """Convert CRD interval shorthand (ps, pm) to milliseconds."""
    return {"ps": 1_000, "pm": 60_000}.get(interval, 60_000)
