import json
import logging
import os
import threading
import hashlib

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
ISTIO_SECRET_NAME      = os.environ.get("ISTIO_SECRET_NAME")
ISTIO_SECRET_NAMESPACE = os.environ.get("ISTIO_SECRET_NAMESPACE", "istio-ingress")
GATEWAY_TLS_SECRET_NAME = os.environ.get("GATEWAY_TLS_SECRET_NAME")
MANAGE_OUTBOUND_TLS     = bool(ISTIO_SECRET_NAME and GATEWAY_TLS_SECRET_NAME)
VERIFY_UPSTREAM_TLS     = os.environ.get("VERIFY_UPSTREAM_TLS", "false").lower() == "true"
        
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

def _parse_template_ref(template_ref: str) -> tuple[str, str]:
    """
    Parse gatewayConfiguration.template.
    Expected format:
      <configmap-name>/<key.yaml>
    Example:
      productcatalog-flexgateway-templates/openapi.yaml
    """
    if not template_ref or "/" not in template_ref:
        raise kopf.PermanentError(
            "gatewayConfiguration.template must use format '<configmap-name>/<key.yaml>'"
        )
    
    cm_name, key = template_ref.split("/", 1)

    if not cm_name or not key:
        raise kopf.PermanentError(
            "gatewayConfiguration.template must use format '<configmap-name>/<key.yaml>'"
        )

    return cm_name, key

def _load_policy_template_from_ref(template_ref: str, namespace: str) -> tuple[list, str]:
    """
    Load a policy template from a ConfigMap referenced by gatewayConfiguration.template.
    Returns:
      policy_list, template_digest
    """
    cm_name, key = _parse_template_ref(template_ref)

    try:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

        v1 = client.CoreV1Api()
        cm = v1.read_namespaced_config_map(cm_name, namespace)

        if not cm.data or key not in cm.data:
            raise kopf.PermanentError(
                f"Template key '{key}' not found in ConfigMap '{namespace}/{cm_name}'"
            )

        raw_template = cm.data[key]
        policy_list = _yaml.safe_load(raw_template)

        if not isinstance(policy_list, list):
            raise kopf.PermanentError(
                f"Template '{template_ref}' must contain a YAML list of policy definitions"
            )

        template_digest = hashlib.sha256(raw_template.encode("utf-8")).hexdigest()

        logger.info(
            "Loaded policy template %s from ConfigMap %s/%s",
            key,
            namespace,
            cm_name,
        )

        return policy_list, template_digest

    except ApiException as e:
        if e.status == 404:
            raise kopf.PermanentError(
                f"Template ConfigMap '{namespace}/{cm_name}' not found"
            )
        raise kopf.TemporaryError(
            f"Could not read template ConfigMap '{namespace}/{cm_name}': {e}",
            delay=30,
        )
    
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

    settings.persistence.finalizer = "oda.tmforum.org/flexgateway-operator-finalizer"
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(
        prefix="flexgateway.oda.tmforum.org"
    )
    settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix="flexgateway.oda.tmforum.org",
        key="last-handled-configuration",
    )


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

def _resolve_upstream_url(spec: dict, name: str) -> str:
    """
    Resolve the upstream URL that Flex Gateway should forward to.

    Use istio ingress host + spec.path
    """
    istio_host = _get_istio_ingress_host()
    if not istio_host:
        raise kopf.TemporaryError("No Istio ingressgateway external IP found", delay=30)

    path = spec.get("path") or "/"
    upstream_url = _join_url("https", istio_host, path, trailing_slash=True)

    logger.info(
        "[%s] Upstream URL resolution: istio_host=%s path=%r trailing_slash=True upstream_url=%r endswith_slash=%s",
        name,
        istio_host,
        path,
        upstream_url,
        upstream_url.endswith("/"),
    )
    return upstream_url

def _join_url(scheme: str, host: str, path: str, trailing_slash: bool = False) -> str:
    host = host.rstrip("/")
    path = path or "/"

    if not path.startswith("/"):
        path = f"/{path}"

    if trailing_slash:
        path = path.rstrip("/") + "/"

    if host.startswith("http://") or host.startswith("https://"):
        result = f"{host.rstrip('/')}{path}"
    else:
        result = f"{scheme}://{host}{path}"
 
    logger.info(
        "URL join: scheme=%s host=%r path=%r trailing_slash=%s result=%r endswith_slash=%s",
        scheme,
        host,
        path,
        trailing_slash,
        result,
        result.endswith("/"),
    )
    return result

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

def _agent_card_url(upstream_url: str) -> str:
    return upstream_url.rstrip("/") + "/.well-known/agent-card.json"

def _build_a2a_metadata(spec_name: str, asset_id: str, upstream_url: str) -> bytes:
    metadata = {
        "protocol": "a2a",
        "platform": "mulesoft",
        "description": f"ODA Canvas A2A Agent — {spec_name}",
        "connections": [],
    }
    return json.dumps(metadata).encode()

def _fetch_spec_content(url: str) -> tuple:
    """Fetch OAS spec bytes from URL. Returns (content, filename) or (None, None)."""
    try:
        resp = _requests.get(url, timeout=10, verify=VERIFY_UPSTREAM_TLS,)
        resp.raise_for_status()
        filename = url.split("/")[-1] or "spec.yaml"
        logger.info(
            "Fetched spec content from %s status=%s bytes=%s",
            url,
            resp.status_code,
            len(resp.content),
        )
        return resp.content, filename
    except Exception as e:
        logger.warning("Could not fetch spec from %s: %s", url, e)
        return None, None

def _has_flex_template(spec, **_):
    return bool(
        spec.get("gatewayConfiguration", {}).get("template")
        or spec.get("template")
    )

# ── Create / Resume / Update ───────────────────────────────────────────────────
@kopf.on.resume(GROUP, VERSION, APIS_PLURAL, retries=5, when=_has_flex_template)
@kopf.on.create(GROUP, VERSION, APIS_PLURAL, retries=5, when=_has_flex_template)
@kopf.on.field(GROUP, VERSION, APIS_PLURAL, field="spec", retries=5, when=_has_flex_template)
def manage_exposedapi(spec, name, namespace, status, old=None, new=None, **kwargs):
    template_ref = (
        spec.get("gatewayConfiguration", {}).get("template")
        or spec.get("template")
    )
    if not template_ref:
        logger.info("[SKIP] %s — no gatewayConfiguration.template or template specified, skipping policy application", name)
        return    

    specification_url = (
        spec.get("specification", {}).get("url")
        if spec.get("specification") 
        else None
    )

    api_spec = {
        "name":             spec.get("name"),
        "apiType":          spec.get("apiType"),
        "implementation":   spec.get("implementation"),
        "path":             spec.get("path"),
        "port":             spec.get("port"),
        "rateLimit":        dict(spec.get("rateLimit", {})),
        "CORS":             dict(spec.get("CORS", {})),
        "specificationUrl": specification_url,
        "templateRef":      template_ref,
    }

    # ── Validate required fields ───────────────────────────────────────────────
    for field in ("name", "apiType", "path"):
        if not api_spec.get(field):
            raise kopf.PermanentError(f"ExposedAPI '{name}' missing required field: spec.{field}")
    
    if api_spec["apiType"] not in _SUPPORTED_API_TYPES:
        logger.info(
            "[SKIP] %s - apiType '%s' is not handled by Flex Gateway operator",
            name,
            api_spec["apiType"],
        )
        return

    # ── Load policy template before idempotency check ──────────────────────────
    template_digest = None

    if template_ref:
        policy_list, template_digest = _load_policy_template_from_ref(template_ref, namespace)
        for policy in policy_list:
            if "assetId" not in policy:
                raise kopf.PermanentError(
                    f"Invalid policy definition in template '{template_ref}': missing 'assetId'"
                )
    else:
        templates = _load_policy_templates()
        policy_list = templates.get(api_spec["apiType"], [])
        template_digest = hashlib.sha256(_yaml.safe_dump(policy_list).encode("utf-8")).hexdigest()

    desired_state = {
        **api_spec,
        "templateDigest": template_digest,
    }

    # ── Discover Istio ingress ─────────────────────────────────────────────────
#    istio_host = _get_istio_ingress_host()
#    if not istio_host:
#        raise kopf.TemporaryError("No Istio ingressgateway external IP found", delay=30)
#    upstream_url = f"https://{istio_host}{spec['path']}"
#    logger.info("[%s] Upstream URL: %s", name, upstream_url)

    # ── Resolve upstream URL through existing Canvas/Istio exposure ────────────────
    upstream_url = _resolve_upstream_url(spec, name)
    # ── Create API instance (idempotent) ───────────────────────────────────────
    endpoint_type = _ENDPOINT_TYPE.get(api_spec["apiType"], "http")
    exchange_type = _EXCHANGE_TYPE.get(api_spec["apiType"], "rest-api")
    exchange_asset_id = f"{name}-{api_spec['apiType']}"
    if api_spec["apiType"] == "openapi" and not specification_url:
        logger.warning("[%s] No OAS spec URL — publishing Exchange asset as http-api", name)
        exchange_type = "http-api"

    desired_state["exchangeAssetId"] = exchange_asset_id
    desired_state["exchangeType"] = exchange_type
    desired_state["endpointType"] = endpoint_type

    desired_state["upstreamUrl"] = upstream_url
    logger.info(
        "[%s] Desired upstreamUrl set: %r endswith_slash=%s",
        name,
        desired_state["upstreamUrl"],
        desired_state["upstreamUrl"].endswith("/"),
    )

    # ── Idempotency check ──────────────────────────────────────────────────────
    stored_upstream_url = (
        status.get("flexGatewayBind", {})
        .get("desiredState", {})
        .get("upstreamUrl")
    )
    stored = status.get("flexGatewayBind", {}).get("desiredState")
    logger.info(
        "[%s] Idempotency check: stored_upstreamUrl=%r stored_endswith_slash=%s desired_upstreamUrl=%r desired_endswith_slash=%s stored_equals_desired=%s",
        name,
        stored_upstream_url,
        stored_upstream_url.endswith("/") if isinstance(stored_upstream_url, str) else None,
        upstream_url,
        upstream_url.endswith("/"),
        stored == desired_state,
    )

    current_api_status_url = status.get("apiStatus", {}).get("url")
    current_flex_gw_url = status.get("flexGatewayBind", {}).get("apiPublicUrl")

    if (
        stored == desired_state
        and current_flex_gw_url
        and current_api_status_url == current_flex_gw_url
    ):
        logger.info("[SKIP] %s — desired state and public URL unchanged, no-op", name)
        return    

    status_only_drift = (
        stored == desired_state
        and current_flex_gw_url
        and current_api_status_url != current_flex_gw_url
    )

    if status_only_drift:
        logger.info(
            "[%s] Public URL drift detected; restoring Flex Gateway URL without Anypoint calls",
            name,
        )

        existing_api_status = dict(status.get("apiStatus", {}))
        existing_api_status["url"] = current_flex_gw_url

        status_body = {
            "status": {
                "apiStatus": existing_api_status,
            }
        }

        try:
            coa = client.CustomObjectsApi()
            coa.patch_namespaced_custom_object(
                GROUP, VERSION, namespace, APIS_PLURAL, name, status_body
            )
            logger.info("[%s] Restored apiStatus.url=%s", name, current_flex_gw_url)
        except ApiException as e:
            logger.warning("[%s] Failed to restore apiStatus.url: %s", name, e)
        return
    # ── Authenticate ───────────────────────────────────────────────────────────
    anypoint = _build_client()
    try:
        anypoint.authenticate()
    except Exception as e:
        raise kopf.TemporaryError(f"Anypoint auth failed: {e}", delay=30)

    # ── Ensure Flex Gateway ────────────────────────────────────────────────────
    gw_id, gw_public_url = _ensure_gateway(anypoint)

    # ── Fetch Exchange content (card/spec) ────────────────────────────────────
    a2a_card = a2a_meta = None
    oas_content = oas_filename = None

    if api_spec["apiType"] == "a2a":
        card_url = _agent_card_url(upstream_url)
        logger.info("[%s] Fetching A2A agent card from %s", name, card_url)
        a2a_card, _ = _fetch_spec_content(card_url)

        if a2a_card:
            card = json.loads(a2a_card.decode("utf-8"))
            card["version"] = str(card.get("version", "1.0.0")).lstrip("v")
            if card["version"].isdigit():
                card["version"] = f"{card['version']}.0.0"
            if "protocolVersion" not in card:
                card["protocolVersion"] = "0.3.0"
            a2a_card = json.dumps(card).encode("utf-8")
            a2a_meta = _build_a2a_metadata(api_spec["name"], exchange_asset_id, upstream_url)
            logger.info("[%s] Using discovered A2A agent card: %s", name, card_url)
        else:
            logger.warning("[%s] Agent Card not available yet, retrying [%s]", name, card_url)
            raise kopf.TemporaryError(
                f"A2A agent card not available yet at {card_url}",
                delay=30,
            )
    elif api_spec["apiType"] == "openapi":
        spec_url = spec.get("specification", {}).get("url") if spec.get("specification") else None
        if spec_url:
            oas_content, oas_filename = _fetch_spec_content(spec_url)
        if not oas_content:
            logger.warning("[%s] No OAS spec available — falling back to http-api Exchange type", name)
            exchange_type = "http-api"
            desired_state["exchangeType"] = exchange_type

    # ── Publish Exchange asset (content-aware) ────────────────────────────────
    exchange_content = a2a_card or oas_content or b""
    exchange_content_hash = hashlib.sha256(exchange_content).hexdigest()
    stored_content_hash = status.get("flexGatewayBind", {}).get("exchangeContentHash")
    asset_exists = anypoint.exchange_asset_exists(exchange_asset_id)

    if not asset_exists or exchange_content_hash != stored_content_hash:
        if asset_exists and exchange_content_hash != stored_content_hash:
            logger.info("[%s] Exchange content changed (hash %s → %s) — publishing new version",
                       name, (stored_content_hash or "none")[:8], exchange_content_hash[:8])
        exchange_version = anypoint.get_next_exchange_version(exchange_asset_id)
        try:
            status_url = anypoint.publish_exchange_asset(
                name=api_spec["name"],
                asset_id=exchange_asset_id,
                exchange_type=exchange_type,
                version=exchange_version,
                a2a_card=a2a_card,
                agent_metadata=a2a_meta,
                oas_content=oas_content,
                oas_filename=oas_filename,
            )
            anypoint.wait_for_exchange_publish(status_url)
            logger.info("[OK] Exchange asset published: %s v%s (%s)", exchange_asset_id, exchange_version, exchange_type)
        except Exception as e:
            raise kopf.TemporaryError(
                f"Exchange publish failed for {name}: {e}", delay=30
            )
    else:
        exchange_version = "1.0.0"
        logger.info("[SKIP] Exchange asset unchanged: %s (hash=%s)", exchange_asset_id, exchange_content_hash[:8])

    existing = anypoint.find_api_instance_by_label(name, asset_id=exchange_asset_id)
    if existing:
        api_id = existing["id"]
        logger.info("[SKIP] API instance exists: %s  id=%s", name, api_id)
    else:
        logger.info(
            "[%s] Creating API instance with endpoint_uri=%r endpoint_uri_endswith_slash=%s",
            name,
            upstream_url,
            upstream_url.endswith("/"),
        )
        api = anypoint.create_api_instance(
            spec_asset_id=exchange_asset_id,
            spec_version=exchange_version,
            endpoint_uri=upstream_url,
            label=name,
            proxy_path=name,
            gateway_url=gw_public_url,
            endpoint_type=endpoint_type,
        )
        api_id = api["id"]
        logger.info("[OK] API instance created: %s  id=%s", name, api_id)

    # ── Deploy to gateway ──────────────────────────────────────────────────────
    logger.info(
        "[%s] Deploying to gateway: api_id=%s gateway_id=%s gateway_name=%s "
        "exchangeAssetId=%s exchangeType=%s endpointType=%s upstreamUrl=%s apiPublicUrl=%s",
        name,
        api_id,
        gw_id,
        FLEX_GW_NAME,
        exchange_asset_id,
        exchange_type,
        endpoint_type,
        upstream_url,
        f"{gw_public_url}/{name}",
    )
    anypoint.deploy_to_gateway(api_id, gw_id, FLEX_GW_NAME)

    # ── Apply policies (template-driven) ──────────────────────────────────────    
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

    existing_api_status = dict(status.get("apiStatus", {}))
    existing_api_status["url"] = api_public_url

    existing_bind = status.get("flexGatewayBind", {})

    if (
        existing_bind.get("desiredState") == desired_state
        and existing_bind.get("apiPublicUrl") == api_public_url
        and status.get("apiStatus", {}).get("url") == api_public_url
    ):
        logger.info("[%s] Status already current, skipping status patch", name)
        return
    
    status_body = {
        "status": {
            "flexGatewayBind": {
                "apiInstanceId":   str(api_id),
                "gatewayId":       gw_id,
                "apiPublicUrl":    api_public_url,
                "upstreamUrl":     upstream_url,
                "policiesApplied": policies_applied,
                "templateRef":     template_ref,
                "templateDigest":  template_digest,
                "spec":            api_spec,
                "exchangeAssetId":     exchange_asset_id,
                "exchangeType":       exchange_type,
                "exchangeVersion":    exchange_version,
                "exchangeContentHash": exchange_content_hash,
                "endpointType":       endpoint_type,
                "desiredState":    desired_state,
            },
            "implementation": {"ready": True},
            "apiStatus": existing_api_status,
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
def delete_exposedapi(status, name, namespace, spec=None, **kwargs):
    api_instance_id = status.get("flexGatewayBind", {}).get("apiInstanceId")
    api_public_url = status.get("flexGatewayBind", {}).get("apiPublicUrl")
    template_ref = status.get("flexGatewayBind", {}).get("templateRef")

    logger.info(
        "[%s] Delete requested namespace=%s apiInstanceId=%s apiPublicUrl=%s templateRef=%s apiType=%s path=%s",
        name,
        namespace,
        api_instance_id or "<none>",
        api_public_url or "<none>",
        template_ref or "<none>",
        (spec or {}).get("apiType"),
        (spec or {}).get("path"),
    )
    if not api_instance_id:
        logger.info("[SKIP] %s — no apiInstanceId in status, nothing to clean up", name)
        return

    anypoint = _build_client()
    try:
        anypoint.authenticate()
        anypoint.delete_api_instance(int(api_instance_id))
        logger.info("[OK] Deleted API instance %s for %s", api_instance_id, name)
    except Exception as e:
        logger.exception("[%s] Delete failed for apiInstanceId=%s", name, api_instance_id)
        raise kopf.TemporaryError(f"Delete failed for {name}: {e}", delay=30)
