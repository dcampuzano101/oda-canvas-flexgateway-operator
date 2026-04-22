# MuleSoft Flex Gateway — ODA Canvas API Operator

A Kubernetes operator that watches `ExposedAPI` CRDs (`oda.tmforum.org/v1`) and automatically
configures a **Managed Flex Gateway in CloudHub 2.0** to host A2A agents and MCP servers. Built
as the MuleSoft contribution to the TM Forum Project Foundation AI-Native ODA Canvas.

---

## What It Does

When an ODA Component is deployed to the Canvas, the Component Operator creates `ExposedAPI`
custom resources. This operator watches those resources and — for each one — provisions the
following in Anypoint Platform:

1. **Publishes an Exchange asset** (type `mcp` or `agent`) with the API's metadata
2. **Creates an API instance** in API Manager with the correct endpoint type (`mcp` or `a2a`)
3. **Deploys** the instance to the pre-provisioned Managed Flex Gateway
4. **Applies a deterministic policy set** based on `apiType`
5. **Writes `status.url`** back to the ExposedAPI CRD — the DependentAPI controller reads
   this to wire service-to-service URLs through the gateway

### Traffic Flow

```
External Consumer / Agent
  → Managed Flex Gateway (CloudHub 2.0 Private Space)
      → JWT validation, rate limiting, MCP/A2A policies enforced
          → Istio Ingress (ODA Canvas cluster external IP)
              → ODA Component K8s Service
```

### Supported API Types

| `spec.apiType` | Exchange type | Endpoint type | Agentic policies applied |
|---|---|---|---|
| `mcp` | `mcp` | `mcp` | MCP Support, Agent Connection Telemetry |
| `a2a` | `agent` | `a2a` | A2A Agent Card, Agent Connection Telemetry |

All instances receive: **JWT Validation** (Keycloak JWKS), **Distributed Tracing**, **Header Injection**.

---

## Architecture

```
ODA Canvas (Kubernetes)              CloudHub 2.0 (MuleSoft)
┌─────────────────────────┐         ┌──────────────────────┐
│  Component Operator     │         │  Managed Flex Gateway│
│    ↓ creates            │         │  (pre-provisioned)   │
│  ExposedAPI CRD         │──────→  │                      │
│    ↓ watched by         │ configures via Anypoint APIs   │
│  apiOperatorFlexGateway │         └──────────────────────┘
│    ↓ writes             │
│  status.url             │         Anypoint Platform
└─────────────────────────┘         ┌──────────────────────┐
                                    │  API Manager         │
                                    │  Exchange            │
                                    │  Gateway Manager     │
                                    └──────────────────────┘
```

---

## Directory Structure

```
blueprint-mule-v2/
  operator/
    apiOperatorFlexGateway.py   # kopf operator — CRD watch loop + provisioning logic
    anypoint_client.py          # Anypoint Platform REST API client
    policy_mapper.py            # ExposedAPI spec → Anypoint policy payload mapper
    requirements.txt            # Python dependencies
    Dockerfile                  # python:3.11-slim
  charts/
    flexgateway-operator/       # Helm chart for deploying the operator to K8s
      Chart.yaml
      values.yaml               # All configurable values with comments
      templates/
        secret.yaml             # K8s Secret for Anypoint credentials
        rbac.yaml               # ServiceAccount + ClusterRole + ClusterRoleBinding
        deployment.yaml         # Operator Deployment
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
- The operator needs a ServiceAccount with permissions to watch `exposedapis` and patch their status

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
| `LOGGING` | No | Log level (default: `INFO`) |
| `ISTIO_INGRESS_HOST` | No | Override Istio ingress discovery — used for local testing without Istio |

---

## Running Locally (Phase B — kind cluster)

```bash
# 1. Create a local cluster
kind create cluster --name oda-canvas-test

# 2. Install the ExposedAPI CRD
kubectl apply -f /path/to/oda-canvas/charts/oda-crds/templates/oda-exposedapi-crd.yaml

# 3. Create namespace
kubectl create namespace components

# 4. Set up Python 3.11 venv
cd operator
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 5. Run the operator
ANYPOINT_CLIENT_ID=... \
ANYPOINT_CLIENT_SECRET=... \
ANYPOINT_ORG_ID=... \
ANYPOINT_ENV_ID=... \
ANYPOINT_HOST=anypoint.mulesoft.com \
FLEX_GW_TARGET_ID=... \
FLEX_GW_NAME=... \
KEYCLOAK_JWKS_URL=... \
KEYCLOAK_AUDIENCE=... \
ISTIO_INGRESS_HOST=<real-or-test-hostname> \
kopf run --standalone apiOperatorFlexGateway.py

# 6. Apply a test ExposedAPI
kubectl apply -f - <<EOF
apiVersion: oda.tmforum.org/v1
kind: ExposedAPI
metadata:
  name: my-mcp-server
  namespace: components
spec:
  name: My MCP Server
  apiType: mcp
  implementation: my-mcp-service
  path: /my-component/mcp
  port: 8080
EOF
```

---

## Deploying via Helm (Phase C — ODA Canvas cluster)

```bash
# Dry-run
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

---

## What Gets Provisioned Per ExposedAPI

| Resource | Location | Notes |
|---|---|---|
| Exchange asset | Anypoint Exchange | Named after `metadata.name`; type `mcp` or `agent` |
| API instance | Anypoint API Manager | `instanceLabel` = `metadata.name`; `endpoint.type` = `mcp` or `a2a` |
| Gateway deployment | Managed Flex Gateway | `type: HY` (hybrid) |
| JWT Validation policy | API instance | JWKS from Keycloak; injects `X-Agent-Scopes`, `X-Agent-Client-Id` headers |
| Distributed Tracing | API instance | OpenTelemetry spans with `mulesoft.api.instance.id` label |
| Header Injection | API instance | Injects `x-anypoint-api-instance-id` for telemetry correlation |
| MCP Support | API instance | MCP type only — handles streamable HTTP transport |
| A2A Agent Card | API instance | A2A type only — serves `/.well-known/agent-card.json` |
| Agent Connection Telemetry | API instance | MCP + A2A — tracks agent-to-tool/agent invocations |

### ExposedAPI Status Written

```yaml
status:
  url: https://<gateway-public-url>/<name>          # read by DependentAPI controller
  implementation:
    ready: true
  flexGatewayBind:
    apiInstanceId: "20865826"
    gatewayId: "e9180b69-..."
    apiPublicUrl: https://<gateway-public-url>/<name>
    policiesApplied: [jwt-validation, tracing, header-injection, mcp-support, agent-connection-telemetry]
    spec: { ... }                                    # snapshot for idempotency
```

---

## Validation Status

| Phase | Description | Status |
|---|---|---|
| **Phase A** | Core Anypoint API logic validated without K8s (Exchange publish, API instance, deploy, policies) | ✅ Complete |
| **Phase B** | kopf operator loop validated against local kind cluster (create, idempotency, delete, status writeback) | ✅ Complete |
| **Phase C** | Deploy to ODA Canvas cluster via Helm chart; validate with Component Operator and real ExposedAPIs | ⏳ Pending Canvas team access |
