# MuleSoft Flex Gateway — ODA Canvas API Operator

A Kubernetes operator that watches `ExposedAPI` CRDs (`oda.tmforum.org/v1`) and automatically
configures a **Managed Flex Gateway in CloudHub 2.0** to host A2A agents, MCP servers, and
OpenAPI REST services. Built as the MuleSoft contribution to the TM Forum Project Foundation
AI-Native ODA Canvas.

---

## What It Does

When an ODA Component is deployed to the Canvas, the Component Operator creates `ExposedAPI`
custom resources. This operator watches those resources and — for each one — provisions the
following in Anypoint Platform:

1. **Publishes an Exchange asset** (`mcp`, `agent`, or `rest-api`) with the API's metadata and spec
2. **Creates an API instance** in API Manager with the correct endpoint type
3. **Deploys** the instance to the pre-provisioned Managed Flex Gateway
4. **Applies a policy set** driven by a K8s ConfigMap (falls back to built-in defaults)
5. **Writes `status.url`** back to the ExposedAPI CRD — the DependentAPI controller reads this to wire service-to-service URLs through the gateway

### Traffic Flow

```
External Consumer / Agent
  → Managed Flex Gateway (CloudHub 2.0 Private Space)
      → JWT validation, rate limiting, MCP/A2A policies enforced
          → Istio Ingress (ODA Canvas cluster external IP)
              → ODA Component K8s Service
```

### Supported API Types

| `spec.apiType` | Exchange type | Endpoint type | Policies applied |
|---|---|---|---|
| `mcp` | `mcp` | `mcp` | JWT Validation, Tracing, Header Injection, MCP Support, Agent Connection Telemetry |
| `a2a` | `agent` (+ A2A card) | `a2a` | JWT Validation, Tracing, Header Injection, A2A Agent Card, Agent Connection Telemetry |
| `openapi` | `rest-api` (+ OAS spec) | `http` | Rate Limiting (if enabled), CORS (if enabled), JWT Validation, Tracing, Header Injection |

---

## Directory Structure

```
oda-canvas-flexgateway-operator/
│
├── operator/
│   ├── apiOperatorFlexGateway.py   # kopf operator — CRD watch loop, Exchange publish,
│   │                               #   API instance create/deploy, policy application,
│   │                               #   status writeback, delete cleanup
│   ├── anypoint_client.py          # Anypoint Platform REST API client
│   │                               #   (auth, gateway, API Manager, Exchange, policies)
│   ├── policy_mapper.py            # Policy config builder — maps ExposedAPI spec fields
│   │                               #   to Anypoint policy payloads per asset ID
│   ├── requirements.txt            # Python 3.11 dependencies
│   └── Dockerfile                  # python:3.11-slim image
│
├── charts/
│   └── flexgateway-operator/       # Helm chart — deploy operator to ODA Canvas cluster
│       ├── Chart.yaml
│       ├── values.yaml             # All operator config + policy templates
│       └── templates/
│           ├── secret.yaml         # K8s Secret: ANYPOINT_CLIENT_ID/SECRET
│           ├── rbac.yaml           # ServiceAccount + ClusterRole (watches exposedapis)
│           ├── deployment.yaml     # Operator Deployment (env vars from secret + values)
│           └── policy-templates.yaml  # ConfigMap: which policies to apply per apiType
│
└── reference/
    └── accounts-api.yaml           # Sample OAS 3.0 spec (te-ai-des-accounts-api)
                                    #   used by the openapi ExposedAPI test manifest
```

### How the pieces connect

```
ExposedAPI CRD event
  → apiOperatorFlexGateway.py (kopf handler)
      → anypoint_client.py    (all Anypoint REST calls)
      → policy_mapper.py      (build config payload per policy asset ID)
      → K8s ConfigMap         (flexgateway-policy-templates — which policies to apply)
      → K8s status patch      (writes status.url back to ExposedAPI)
```

---

## Prerequisites

### Anypoint Platform
- Connected App with scopes: **Manage APIs**, **View APIs**, **View Organization**,
  **View Environment**, **Manage Flex Gateways**, **Read Applications**
- A **Managed Flex Gateway** pre-provisioned in a CloudHub 2.0 Private Space
- Note the `FLEX_GW_NAME` and `FLEX_GW_TARGET_ID` (Private Space target ID)

### Keycloak
- A running Keycloak realm with a JWKS endpoint
- The `aud` (audience) claim value expected in incoming JWTs

### Kubernetes
- ODA Canvas CRD installed: `exposedapis.oda.tmforum.org`
- `"a2a"` must be in the CRD enum for `spec.apiType` (patch if needed — see Testing section)

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANYPOINT_CLIENT_ID` | Yes | Connected App client ID (stored as K8s Secret) |
| `ANYPOINT_CLIENT_SECRET` | Yes | Connected App client secret (stored as K8s Secret) |
| `ANYPOINT_ORG_ID` | Yes | Anypoint organization ID |
| `ANYPOINT_ENV_ID` | Yes | Target environment ID |
| `ANYPOINT_HOST` | Yes | Control plane: `anypoint.mulesoft.com` (US) · `eu1.anypoint.mulesoft.com` (EU) · `ca1.anypoint.mulesoft.com` (Canada) · `jp1.anypoint.mulesoft.com` (Japan) |
| `FLEX_GW_TARGET_ID` | Yes | CloudHub 2.0 Private Space target ID |
| `FLEX_GW_NAME` | Yes | Name of the pre-provisioned Managed Flex Gateway |
| `KEYCLOAK_JWKS_URL` | Yes | Keycloak JWKS endpoint (e.g. `https://.../certs`) |
| `KEYCLOAK_AUDIENCE` | Yes | Expected JWT `aud` claim value |
| `OPERATOR_NAMESPACE` | No | Namespace where the policy templates ConfigMap lives (default: `operators`) |
| `LOGGING` | No | Log level (default: `INFO`) |
| `ISTIO_INGRESS_HOST` | No | Override Istio ingress discovery — set for local testing without Istio |

---

## Local Testing (kind cluster)

### 1. Cluster setup

```bash
# Install kind if needed
brew install kind

# Create local cluster
kind create cluster --name oda-canvas-test

# Install the ExposedAPI CRD from the ODA Canvas repo
kubectl apply -f /path/to/oda-canvas/charts/oda-crds/templates/oda-exposedapi-crd.yaml --context kind-oda-canvas-test

# Patch CRD to allow "a2a" apiType (not in all CRD versions)
kubectl get crd exposedapis.oda.tmforum.org -o json --context kind-oda-canvas-test \
  | python3 -c "
import json, sys
crd = json.load(sys.stdin)
for ver in crd['spec']['versions']:
    enum = ver['schema']['openAPIV3Schema']['properties']['spec']['properties']['apiType'].get('enum', [])
    if 'a2a' not in enum:
        enum.append('a2a')
        ver['schema']['openAPIV3Schema']['properties']['spec']['properties']['apiType']['enum'] = enum
print(json.dumps(crd))
" | kubectl apply -f - --context kind-oda-canvas-test

# Create required namespaces
kubectl create namespace components --context kind-oda-canvas-test
kubectl create namespace operators --context kind-oda-canvas-test
```

### 2. Operator setup

```bash
cd operator
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Run the operator

```bash
ANYPOINT_CLIENT_ID=<your-client-id> \
ANYPOINT_CLIENT_SECRET=<your-client-secret> \
ANYPOINT_ORG_ID=<your-org-id> \
ANYPOINT_ENV_ID=<your-env-id> \
ANYPOINT_HOST=anypoint.mulesoft.com \
FLEX_GW_TARGET_ID=<your-private-space-target-id> \
FLEX_GW_NAME=<your-gateway-name> \
KEYCLOAK_JWKS_URL=<your-jwks-url> \
KEYCLOAK_AUDIENCE=<your-audience> \
ISTIO_INGRESS_HOST=example.com \
kopf run --standalone apiOperatorFlexGateway.py
```

> `ISTIO_INGRESS_HOST=example.com` bypasses Istio discovery for local testing. In production, leave this unset and the operator discovers the real Istio ingress external IP automatically.

### 4. Apply test ExposedAPIs

Three test manifests are provided — apply any or all:

```bash
# MCP Server
kubectl apply -f - --context kind-oda-canvas-test <<EOF
apiVersion: oda.tmforum.org/v1
kind: ExposedAPI
metadata:
  name: pc-2-productcatalogmcp
  namespace: components
spec:
  name: productcatalogmcp
  apiType: mcp
  implementation: pc-2-prodcatmcp
  path: /pc-2-productcatalogmanagement/mcp
  port: 8080
EOF

# A2A Agent
kubectl apply -f - --context kind-oda-canvas-test <<EOF
apiVersion: oda.tmforum.org/v1
kind: ExposedAPI
metadata:
  name: pa-1-productagent-agentquery
  namespace: components
spec:
  name: productcatalogagent
  apiType: a2a
  implementation: pa-1-agent
  path: /pa-1-productagent/v1/agent
  port: 8000
EOF

# OpenAPI REST service (OAS spec fetched from reference/accounts-api.yaml in this repo)
kubectl apply -f - --context kind-oda-canvas-test <<EOF
apiVersion: oda.tmforum.org/v1
kind: ExposedAPI
metadata:
  name: te-accounts-api
  namespace: components
spec:
  name: te-ai-des-accounts-api
  apiType: openapi
  implementation: te-accounts-service
  path: /te-ai-des-accounts-api/v1
  port: 8081
  specification:
    url: "https://raw.githubusercontent.com/dcampuzano101/oda-canvas-flexgateway-operator/main/reference/accounts-api.yaml"
  rateLimit:
    enabled: true
    identifier: IP
    limit: "100"
    interval: pm
EOF
```

### 5. Verify provisioning

```bash
# Check status was written
kubectl get exposedapi <name> -n components \
  -o jsonpath='{.status}' --context kind-oda-canvas-test | python3 -m json.tool

# Key fields to confirm
kubectl get exposedapi <name> -n components \
  -o jsonpath='{.status.url}' --context kind-oda-canvas-test     # gateway public URL

kubectl get exposedapi <name> -n components \
  -o jsonpath='{.status.implementation.ready}' --context kind-oda-canvas-test  # true

# Then verify in Anypoint API Manager — the API instance should appear under
# "Agent and Tool Instances" with the correct endpoint type and policies
```

### 6. Test delete (cleanup)

```bash
kubectl delete exposedapi <name> -n components --context kind-oda-canvas-test
# Operator log: [OK] Deleted API instance <id> for <name>
# API instance is removed from Anypoint API Manager
```

---

## Policy Templates

The operator applies policies driven by a Kubernetes ConfigMap named `flexgateway-policy-templates`
in the `operators` namespace. If the ConfigMap is absent, the operator falls back to built-in
defaults (same policy set as the ConfigMap defaults in `charts/flexgateway-operator/values.yaml`).

### Apply the default ConfigMap

```bash
kubectl apply -f - --context kind-oda-canvas-test <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: flexgateway-policy-templates
  namespace: operators
data:
  mcp: |
    - assetId: jwt-validation
      minorVersion: "0.11"
    - assetId: tracing
      minorVersion: "1.1"
    - assetId: header-injection
      minorVersion: "1.3"
    - assetId: mcp-support
      minorVersion: "1.0"
    - assetId: agent-connection-telemetry
      minorVersion: "1.0"
  a2a: |
    - assetId: jwt-validation
      minorVersion: "0.11"
    - assetId: tracing
      minorVersion: "1.1"
    - assetId: header-injection
      minorVersion: "1.3"
    - assetId: a-two-a-agent-card
      minorVersion: "1.0"
    - assetId: agent-connection-telemetry
      minorVersion: "1.0"
  openapi: |
    - assetId: rate-limiting
      minorVersion: "1.4"
      condition: rateLimit.enabled
    - assetId: cors
      minorVersion: "1.0"
      condition: CORS.enabled
    - assetId: jwt-validation
      minorVersion: "0.11"
    - assetId: tracing
      minorVersion: "1.1"
    - assetId: header-injection
      minorVersion: "1.3"
EOF
```

### Verify the ConfigMap is being used

On the next ExposedAPI reconciliation the operator logs:
```
Loaded policy templates from ConfigMap operators/flexgateway-policy-templates
```
vs. without ConfigMap:
```
Policy templates ConfigMap not found — using built-in defaults
```

### Test ConfigMap-driven behavior

Edit the ConfigMap to remove a policy (e.g. remove `agent-connection-telemetry` from `mcp`),
save it, then delete and re-apply an MCP ExposedAPI. The removed policy will not be applied —
no operator restart needed.

Supported `assetId` values and their conditions:

| `assetId` | Config source | Condition field |
|---|---|---|
| `jwt-validation` | `KEYCLOAK_JWKS_URL` + `KEYCLOAK_AUDIENCE` env vars | — |
| `tracing` | `spec.name` + `api_id` | — |
| `header-injection` | `api_id` | — |
| `mcp-support` | (empty config) | — |
| `a-two-a-agent-card` | (hardcoded card path) | — |
| `agent-connection-telemetry` | (header expression) | — |
| `rate-limiting` | `spec.rateLimit.*` | `rateLimit.enabled` |
| `cors` | `spec.CORS.*` | `CORS.enabled` |

---

## Deploying via Helm (ODA Canvas cluster)

```bash
# Dry-run to validate templates render correctly
helm install flexgateway-operator charts/flexgateway-operator \
  --dry-run --debug \
  --set anypointSecret.clientId=<id> \
  --set anypointSecret.clientSecret=<secret> \
  --set operator.anypointOrgId=<org> \
  --set operator.anypointEnvId=<env> \
  --set operator.anypointHost=anypoint.mulesoft.com \
  --set operator.flexGwTargetId=<target> \
  --set operator.flexGwName=<gw-name> \
  --set operator.keycloakJwksUrl=<jwks-url> \
  --set operator.keycloakAudience=<audience> \
  --set image.repository=<your-registry>/flexgateway-operator \
  --namespace operators --create-namespace

# Install
helm install flexgateway-operator charts/flexgateway-operator \
  -f values-production.yaml \
  --namespace operators --create-namespace
```

The Helm chart deploys the operator Deployment, RBAC, credentials Secret, and the
`flexgateway-policy-templates` ConfigMap in a single install. Policies can be updated
post-install by editing the ConfigMap directly without a Helm upgrade.

---

## What Gets Provisioned Per ExposedAPI

| Resource | Location | Notes |
|---|---|---|
| Exchange asset | Anypoint Exchange | Named `metadata.name`; type matches `apiType` |
| API instance | Anypoint API Manager | `instanceLabel` = `metadata.name`; `endpoint.type` = `mcp`/`a2a`/`http` |
| OAS spec (openapi only) | Exchange asset | Fetched from `spec.specification.url` at provision time |
| Gateway deployment | Managed Flex Gateway | `type: HY` (hybrid) |
| Policy set | API instance | Driven by `flexgateway-policy-templates` ConfigMap |

### ExposedAPI Status Written

```yaml
status:
  url: https://<gateway-public-url>/<name>       # read by DependentAPI controller
  implementation:
    ready: true
  flexGatewayBind:
    apiInstanceId: "20865826"
    gatewayId: "e9180b69-..."
    apiPublicUrl: https://<gateway-public-url>/<name>
    policiesApplied: [jwt-validation, tracing, header-injection, mcp-support, ...]
    spec: { ... }                                # snapshot used for idempotency check
```

---

## Validation Status

| Phase | Description | Status |
|---|---|---|
| **Phase A** | Core Anypoint API logic validated without K8s — Exchange publish (mcp/agent/rest-api), API instance creation, gateway deployment, policy application for all three apiTypes | ✅ Complete |
| **Phase B** | kopf operator loop validated against local kind cluster — create, resume, update, delete, idempotency, status writeback, policy templates ConfigMap | ✅ Complete |
| **Phase C** | Deploy to ODA Canvas cluster via Helm chart; validate with Component Operator and real ExposedAPIs | ⏳ Pending Canvas cluster access |
