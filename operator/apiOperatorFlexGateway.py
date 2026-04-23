import json
import logging
import os
import threading

import requests as _requests
import yaml as _yaml

import kopf
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from anypoint_client import AnypointClient
from policy_mapper import (
    MULESOFT_ORG,
    build_policy_config,
    build_jwt_validation_policy,
    map_tier1_policies,
    map_tier2_policies,
)

# ── CRD coordinates ────────────────────────────────────────────────────────────
GROUP       = "oda.tmforum.org"
VERSION     = "v1"
APIS_PLURAL = "exposedapis"

# ── Operator config ────────────────────────────────────────────────────────────
ANYPOINT_CLIENT_ID     = os.environ["ANYPOINT_CLIENT_ID"]
ANYPOINT_CLIENT_SECRET = os.environ["ANYPOINT_CLIENT_SECRET"]
ANYPOINT_ORG_ID        = os.environ["ANYPOINT_ORG_ID"]
ANYPOINT_ENV_ID        = os.environ["ANYPOINT_ENV_ID"]
ANYPOINT_HOST          = os.environ["ANYPOINT_HOST"]
FLEX_GW_TARGET_ID      = os.environ["FLEX_GW_TARGET_ID"]
FLEX_GW_NAME           = os.environ["FLEX_GW_NAME"]
KEYCLOAK_JWKS_URL      = os.environ["KEYCLOAK_JWKS_URL"]
KEYCLOAK_AUDIENCE      = os.environ["KEYCLOAK_AUDIENCE"]

logging_level = os.environ.get("LOGGING", "INFO")
logger = logging.getLogger("apiOperatorFlexGateway")
logger.setLevel(getattr(logging, logging_level.upper(), logging.INFO))

# Patch for Python 3.14: logging.Handler.lock can be None, breaking kopf's
# success/error log calls. Patch at the class level so ALL handlers are covered,
# including ones kopf creates lazily after module load.
_original_logging_handle = logging.Handler.handle

def _safe_logging_handle(self, record):
    if getattr(self, "lock", None) is None:
        self.lock = threading.RLock()
    return _original_logging_handle(self, record)

logging.Handler.handle = _safe_logging_handle

# ── apiType mappings ───────────────────────────────────────────────────────────
_SUPPORTED_API_TYPES = {"mcp", "a2a", "openapi"}

_ENDPOINT_TYPE = {
    "mcp":     "mcp",
    "a2a":     "a2a",
    "openapi": "http",
}

_EXCHANGE_TYPE = {
    "mcp":     "mcp",
    "a2a":     "agent",
    "openapi": "rest-api",
}


# ── Default policy templates (fallback when ConfigMap is absent) ───────────────
_DEFAULT_POLICY_TEMPLATES = {
    "mcp": [
        {"assetId": "jwt-validation",           "minorVersion": "0.11"},
        {"assetId": "tracing",                  "minorVersion": "1.1"},
        {"assetId": "header-injection",         "minorVersion": "1.3"},
        {"assetId": "mcp-support",              "minorVersion": "1.0"},
        {"assetId": "agent-connection-telemetry","minorVersion": "1.0"},
    ],
    "a2a": [
        {"assetId": "jwt-validation",           "minorVersion": "0.11"},
        {"assetId": "tracing",                  "minorVersion": "1.1"},
        {"assetId": "header-injection",         "minorVersion": "1.3"},
        {"assetId": "a-two-a-agent-card",       "minorVersion": "1.0"},
        {"assetId": "agent-connection-telemetry","minorVersion": "1.0"},
    ],
    "openapi": [
        {"assetId": "rate-limiting",  "minorVersion": "1.4", "condition": "rateLimit.enabled"},
        {"assetId": "cors",           "minorVersion": "1.0", "condition": "CORS.enabled"},
        {"assetId": "jwt-validation", "minorVersion": "0.11"},
        {"assetId": "tracing",        "minorVersion": "1.1"},
        {"assetId": "header-injection","minorVersion": "1.3"},
    ],
}

POLICY_TEMPLATES_CONFIGMAP = "flexgateway-policy-templates"
OPERATOR_NAMESPACE = os.environ.get("OPERATOR_NAMESPACE", "operators")


def _load_policy_templates() -> dict:
    """
    Read policy templates from the flexgateway-policy-templates ConfigMap.
    Falls back to _DEFAULT_POLICY_TEMPLATES if the ConfigMap is absent.
    """
    try:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        v1 = client.CoreV1Api()
        cm = v1.read_namespaced_config_map(POLICY_TEMPLATES_CONFIGMAP, OPERATOR_NAMESPACE)
        templates = {k: _yaml.safe_load(v) for k, v in cm.data.items()}
        logger.info("Loaded policy templates from ConfigMap %s/%s",
                    OPERATOR_NAMESPACE, POLICY_TEMPLATES_CONFIGMAP)
        return templates
    except ApiException as e:
        if e.status == 404:
            logger.info("Policy templates ConfigMap not found — using built-in defaults")
        else:
            logger.warning("Could not read policy templates ConfigMap: %s — using defaults", e)
    except Exception as e:
        logger.warning("Error loading policy templates: %s — using defaults", e)
    return _DEFAULT_POLICY_TEMPLATES


def _condition_met(condition: str, api_spec: dict) -> bool:
    """Evaluate a dot-notation condition path against api_spec (e.g. 'rateLimit.enabled')."""
    val = api_spec
    for key in condition.split("."):
        if not isinstance(val, dict):
            return False
        val = val.get(key)
    return bool(val)


# ── Startup ────────────────────────────────────────────────────────────────────
@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    settings.watching.server_timeout = 60


# ── Helpers ────────────────────────────────────────────────────────────────────
def _build_client() -> AnypointClient:
    return AnypointClient(
        client_id=ANYPOINT_CLIENT_ID,
        client_secret=ANYPOINT_CLIENT_SECRET,
        org_id=ANYPOINT_ORG_ID,
        env_id=ANYPOINT_ENV_ID,
        host=ANYPOINT_HOST,
    )


def _get_istio_ingress_host() -> str:
    # ISTIO_INGRESS_HOST env var bypasses K8s discovery — used for local/Phase B testing.
    # Leave unset in production; the operator discovers the real Istio ingress IP.
    override = os.environ.get("ISTIO_INGRESS_HOST")
    if override:
        logger.info("Using ISTIO_INGRESS_HOST override: %s", override)
        return override

    try:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

        v1 = client.CoreV1Api()
        svcs = v1.list_service_for_all_namespaces(label_selector="istio=ingressgateway")
        if not svcs.items:
            return ""
        lb = svcs.items[0].status.load_balancer.ingress or []
        if lb:
            return lb[0].ip or lb[0].hostname or ""
    except ApiException as e:
        logger.error("Istio ingress discovery failed: %s", e)
    return ""


def _ensure_gateway(anypoint: AnypointClient) -> tuple[str, str]:
    """Return (gateway_id, gateway_public_url) for the pre-provisioned Flex Gateway."""
    gateways = anypoint.list_gateways()
    for gw in gateways:
        if gw["name"] == FLEX_GW_NAME:
            gw_id = gw["id"]
            detail = anypoint.get_gateway_detail(gw_id)
            public_url = (
                detail.get("configuration", {})
                .get("ingress", {})
                .get("publicUrl", "")
                .rstrip("/")
            )
            logger.info("[OK] Gateway found: %s  id=%s", FLEX_GW_NAME, gw_id)
            return gw_id, public_url
    raise kopf.TemporaryError(
        f"Flex Gateway '{FLEX_GW_NAME}' not found — ensure it is pre-provisioned "
        f"(FLEX_GW_TARGET_ID={FLEX_GW_TARGET_ID})",
        delay=60,
    )


# ── A2A card builder ───────────────────────────────────────────────────────────
def _build_a2a_card(
    spec_name: str,
    asset_id: str,
    upstream_url: str,
) -> tuple[bytes, bytes]:
    """
    Generate minimal A2A card and agent-metadata JSON bytes for Exchange publishing.
    protocolVersion "0.3.0" is required by Exchange AMF validation.
    """
    card = {
        "name": spec_name,
        "description": f"ODA Canvas A2A Agent — {spec_name}",
        "url": upstream_url,
        "protocolVersion": "0.3.0",
        "version": "1.0.0",
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": asset_id,
                "name": spec_name,
                "description": f"Agent capability for {spec_name}",
                "tags": ["query", "read"],
            }
        ],
        "capabilities": {"pushNotifications": False, "streaming": False},
    }
    metadata = {
        "protocol": "a2a",
        "platform": "mulesoft",
        "description": f"ODA Canvas A2A Agent — {spec_name}",
        "connections": [],
    }
    return json.dumps(card).encode(), json.dumps(metadata).encode()


def _fetch_spec_content(url: str) -> tuple:
    """Fetch OAS spec bytes from URL. Returns (content, filename) or (None, None)."""
    try:
        resp = _requests.get(url, timeout=10)
        resp.raise_for_status()
        filename = url.split("/")[-1] or "spec.yaml"
        return resp.content, filename
    except Exception as e:
        logger.warning("Could not fetch OAS spec from %s: %s", url, e)
        return None, None


# ── Create / Resume / Update ───────────────────────────────────────────────────
@kopf.on.resume(GROUP, VERSION, APIS_PLURAL, retries=5)
@kopf.on.create(GROUP, VERSION, APIS_PLURAL, retries=5)
@kopf.on.update(GROUP, VERSION, APIS_PLURAL, retries=5)
def manage_exposedapi(spec, name, namespace, status, **kwargs):
    api_spec = {
        "name":           spec.get("name"),
        "apiType":        spec.get("apiType"),
        "implementation": spec.get("implementation"),
        "path":           spec.get("path"),
        "port":           spec.get("port"),
        "rateLimit":      dict(spec.get("rateLimit", {})),
        "CORS":           dict(spec.get("CORS", {})),
    }

    # ── Idempotency check ──────────────────────────────────────────────────────
    stored = status.get("flexGatewayBind", {}).get("spec")
    if stored == api_spec:
        logger.info("[SKIP] %s — spec unchanged, no-op", name)
        return

    # ── Validate required fields ───────────────────────────────────────────────
    for field in ("name", "apiType", "path"):
        if not api_spec.get(field):
            raise kopf.PermanentError(f"ExposedAPI '{name}' missing required field: spec.{field}")

    if api_spec["apiType"] not in _SUPPORTED_API_TYPES:
        raise kopf.PermanentError(
            f"ExposedAPI '{name}' has unsupported apiType '{api_spec['apiType']}'. "
            f"This operator handles: {sorted(_SUPPORTED_API_TYPES)}"
        )

    # ── Authenticate ───────────────────────────────────────────────────────────
    anypoint = _build_client()
    try:
        anypoint.authenticate()
    except Exception as e:
        raise kopf.TemporaryError(f"Anypoint auth failed: {e}", delay=30)

    # ── Discover Istio ingress ─────────────────────────────────────────────────
    istio_host = _get_istio_ingress_host()
    if not istio_host:
        raise kopf.TemporaryError("No Istio ingressgateway external IP found", delay=30)
    upstream_url = f"https://{istio_host}{spec['path']}"
    logger.info("[%s] Upstream URL: %s", name, upstream_url)

    # ── Ensure Flex Gateway ────────────────────────────────────────────────────
    gw_id, gw_public_url = _ensure_gateway(anypoint)

    # ── Create API instance (idempotent) ───────────────────────────────────────
    endpoint_type = _ENDPOINT_TYPE.get(api_spec["apiType"], "http")
    exchange_type = _EXCHANGE_TYPE.get(api_spec["apiType"], "rest-api")

    # ── Publish Exchange asset (idempotent) ────────────────────────────────────
    if not anypoint.exchange_asset_exists(name):
        a2a_card = a2a_meta = None
        oas_content = oas_filename = None

        if api_spec["apiType"] == "a2a":
            a2a_card, a2a_meta = _build_a2a_card(
                api_spec["name"], name, upstream_url
            )
        elif api_spec["apiType"] == "openapi":
            spec_url = spec.get("specification", {}).get("url") if spec.get("specification") else None
            if spec_url:
                oas_content, oas_filename = _fetch_spec_content(spec_url)
            if not oas_content:
                logger.warning("[%s] No OAS spec available — falling back to http-api Exchange type", name)
                exchange_type = "http-api"

        try:
            status_url = anypoint.publish_exchange_asset(
                name=api_spec["name"],
                asset_id=name,
                exchange_type=exchange_type,
                a2a_card=a2a_card,
                agent_metadata=a2a_meta,
                oas_content=oas_content,
                oas_filename=oas_filename,
            )
            anypoint.wait_for_exchange_publish(status_url)
            logger.info("[OK] Exchange asset published: %s (%s)", name, exchange_type)
        except Exception as e:
            raise kopf.TemporaryError(
                f"Exchange publish failed for {name}: {e}", delay=30
            )
    else:
        logger.info("[SKIP] Exchange asset exists: %s", name)

    existing = anypoint.find_api_instance_by_label(name)
    if existing:
        api_id = existing["id"]
        logger.info("[SKIP] API instance exists: %s  id=%s", name, api_id)
    else:
        api = anypoint.create_api_instance(
            spec_asset_id=name,
            endpoint_uri=upstream_url,
            label=name,
            proxy_path=name,
            gateway_url=gw_public_url,
            endpoint_type=endpoint_type,
        )
        api_id = api["id"]
        logger.info("[OK] API instance created: %s  id=%s", name, api_id)

    # ── Deploy to gateway ──────────────────────────────────────────────────────
    anypoint.deploy_to_gateway(api_id, gw_id, FLEX_GW_NAME)

    # ── Apply policies (template-driven) ──────────────────────────────────────
    templates = _load_policy_templates()
    policy_list = templates.get(api_spec["apiType"], [])
    policies_applied = []

    for policy_def in policy_list:
        asset_id = policy_def["assetId"]
        minor_version = policy_def.get("minorVersion", "1.0")
        condition = policy_def.get("condition")

        if condition and not _condition_met(condition, api_spec):
            continue

        policy_config = build_policy_config(
            asset_id, api_spec, api_id,
            jwks_url=KEYCLOAK_JWKS_URL,
            audience=KEYCLOAK_AUDIENCE,
        )
        if policy_config is None:
            logger.warning("[%s] Unknown policy '%s' in template — skipping", name, asset_id)
            continue

        version = anypoint.resolve_policy_version(MULESOFT_ORG, asset_id, minor_version)
        anypoint.apply_policy(api_id, asset_id, version, MULESOFT_ORG, policy_config)
        policies_applied.append(asset_id)

    logger.info("[%s] Policies applied: %s", name, policies_applied)

    # ── Write status directly via K8s API (bypasses kopf return-value mechanism) ─
    api_public_url = f"{gw_public_url}/{name}"
    status_body = {
        "status": {
            "flexGatewayBind": {
                "apiInstanceId":   str(api_id),
                "gatewayId":       gw_id,
                "apiPublicUrl":    api_public_url,
                "policiesApplied": policies_applied,
                "spec":            api_spec,
            },
            "implementation": {"ready": True},
            "url": api_public_url,
        }
    }
    try:
        coa = client.CustomObjectsApi()
        coa.patch_namespaced_custom_object(
            GROUP, VERSION, namespace, APIS_PLURAL, name, status_body
        )
        logger.info("[%s] Status written: url=%s", name, api_public_url)
    except ApiException as e:
        logger.warning("[%s] Status writeback failed (non-fatal): %s", name, e)


# ── Delete ─────────────────────────────────────────────────────────────────────
@kopf.on.delete(GROUP, VERSION, APIS_PLURAL, retries=1)
def delete_exposedapi(status, name, **kwargs):
    api_instance_id = status.get("flexGatewayBind", {}).get("apiInstanceId")
    if not api_instance_id:
        logger.info("[SKIP] %s — no apiInstanceId in status, nothing to clean up", name)
        return

    anypoint = _build_client()
    try:
        anypoint.authenticate()
        anypoint.delete_api_instance(int(api_instance_id))
        logger.info("[OK] Deleted API instance %s for %s", api_instance_id, name)
    except Exception as e:
        raise kopf.TemporaryError(f"Delete failed for {name}: {e}", delay=30)
