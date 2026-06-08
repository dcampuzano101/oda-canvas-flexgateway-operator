"""
Anypoint Platform REST API client.

Ported from provision-customer-network-v2.sh and apply-security.sh.
Covers the subset needed by the Flex Gateway operator:
  - Authentication (Connected App client_credentials)
  - Gateway Manager (list, create, status)
  - API Manager (create instance, deploy to gateway, apply policy, delete)
  - Exchange (resolve policy version)
"""

import logging
import time
from typing import Optional

import requests
import yaml as _yaml
import json

logger = logging.getLogger(__name__)


class AnypointClient:
    """Thin wrapper around the Anypoint Platform REST APIs."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        org_id: str,
        env_id: str,
        host: str = "anypoint.mulesoft.com",
    ):
        self.host = host
        self.client_id = client_id
        self.client_secret = client_secret
        self.org_id = org_id
        self.env_id = env_id
        self._access_token: Optional[str] = None

    @property
    def _base(self) -> str:
        return f"https://{self.host}"

    @property
    def _headers(self) -> dict:
        if not self._access_token:
            raise RuntimeError("Not authenticated — call authenticate() first")
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
        }

    @property
    def _auth_header(self) -> dict:
        """Authorization only — use for multipart requests (Content-Type set by requests)."""
        if not self._access_token:
            raise RuntimeError("Not authenticated — call authenticate() first")
        return {"Authorization": f"Bearer {self._access_token}"}

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> str:
        """POST /accounts/api/v2/oauth2/token → access_token"""
        resp = requests.post(
            f"{self._base}/accounts/api/v2/oauth2/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
            },
        )
        resp.raise_for_status()
        self._access_token = resp.json()["access_token"]
        logger.info("Anypoint auth OK  org=%s  env=%s", self.org_id, self.env_id)
        return self._access_token

    # ------------------------------------------------------------------
    # Gateway Manager
    # ------------------------------------------------------------------

    def list_gateways(self) -> list[dict]:
        """GET /gatewaymanager/.../gateways → list of gateway objects."""
        resp = requests.get(
            f"{self._base}/gatewaymanager/api/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/gateways",
            headers=self._headers,
        )
        resp.raise_for_status()
        return resp.json().get("content", [])

    def get_gateway_versions(self) -> str:
        """Return the latest edge-channel gateway version string."""
        resp = requests.get(
            f"{self._base}/gatewaymanager/xapi/v1/gateway/versions",
            headers=self._headers,
        )
        resp.raise_for_status()
        return resp.json()["channels"]["edge"]["versions"][0]["displayName"]

    def get_domains(self, target_id: str) -> dict:
        """Resolve the wildcard domain and appUniqueId for a Private Space."""
        resp = requests.get(
            f"{self._base}/runtimefabric/api/organizations/{self.org_id}"
            f"/targets/{target_id}/environments/{self.env_id}"
            "/domains?sendAppUniqueId=true",
            headers=self._headers,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "domain": data["domains"][0],
            "appUniqueId": data["appUniqueId"],
        }

    def create_gateway(
        self,
        name: str,
        target_id: str,
        version: str,
        *,
        public_url: str = "",
        size: str = "small",
    ) -> dict:
        """POST /gatewaymanager/.../gateways → created gateway object."""
        body = {
            "name": name,
            "targetId": target_id,
            "releaseChannel": "edge",
            "runtimeVersion": version,
            "size": size,
            "configuration": {
                "ingress": {
                    "publicUrl": public_url,
                    "forwardSslSession": False,
                    "lastMileSecurity": False,
                },
                "logging": {"level": "info", "forwardLogs": True},
                "properties": {
                    "upstreamResponseTimeout": 60,
                    "connectionIdleTimeout": 60,
                },
                "tracing": {"enabled": True, "sampling": 100},
            },
        }
        resp = requests.post(
            f"{self._base}/gatewaymanager/api/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/gateways",
            headers=self._headers,
            json=body,
        )
        resp.raise_for_status()
        gw = resp.json()
        logger.info("Created gateway %s  id=%s", name, gw.get("id"))
        return gw

    def get_gateway_status(self, gateway_id: str) -> dict:
        """GET /gatewaymanager/xapi/.../gateways/{id} → running/ready status."""
        resp = requests.get(
            f"{self._base}/gatewaymanager/xapi/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/gateways/{gateway_id}",
            headers=self._headers,
        )
        resp.raise_for_status()
        return resp.json()

    def get_gateway_detail(self, gateway_id: str) -> dict:
        """GET /gatewaymanager/api/.../gateways/{id} → full gateway detail."""
        resp = requests.get(
            f"{self._base}/gatewaymanager/api/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/gateways/{gateway_id}",
            headers=self._headers,
        )
        resp.raise_for_status()
        return resp.json()

    def wait_for_gateway(
        self,
        gateway_id: str,
        *,
        timeout: int = 300,
        poll_interval: int = 5,
    ) -> dict:
        """Poll until gateway is running + ready, or raise on timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self.get_gateway_status(gateway_id)
            running = status.get("running")
            ready = status.get("ready")
            if running and ready:
                logger.info("Gateway %s is READY", gateway_id)
                return status
            logger.info(
                "Gateway %s  running=%s  ready=%s — waiting…",
                gateway_id, running, ready,
            )
            time.sleep(poll_interval)
        raise TimeoutError(
            f"Gateway {gateway_id} did not become ready within {timeout}s"
        )
    
    # ------------------------------------------------------------------
    # Secrets Manager / Upstream TLS
    # ------------------------------------------------------------------

    def _secrets_base(self) -> str:
        return (
            f"{self._base}/secrets-manager/api/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}"
        )

    def ensure_secret_group(self, name: str) -> dict:
        """Ensure Anypoint Secrets Manager secret group exists."""
        resp = requests.get(
            f"{self._secrets_base()}/secretGroups",
            headers=self._headers,
        )
        resp.raise_for_status()

        groups = resp.json()
        if isinstance(groups, dict):
            groups = groups.get("items") or groups.get("content") or groups.get("data") or []

        for group in groups:
            if group.get("name") == name:
                group_id = group.get("id") or group.get("meta", {}).get("id")
                logger.info("[SKIP] Secret group exists: %s id=%s", name, group_id)
                return {"id": group_id, "name": name, "raw": group}

        body = {
            "name": name,
            "downloadable": True,
        }

        resp = requests.post(
            f"{self._secrets_base()}/secretGroups/",
            headers=self._headers,
            json=body,
        )
        if not resp.ok:
            logger.error("ensure_secret_group create failed %s: %s", resp.status_code, resp.text)
        resp.raise_for_status()

        data = resp.json()
        group_id = data.get("id") or data.get("meta", {}).get("id")
        logger.info("Created secret group %s id=%s", name, group_id)
        return {"id": group_id, "name": name, "raw": data}

    def ensure_truststore(
        self,
        secret_group_id: str,
        *,
        name: str,
        cert_path: str,
        expiration_date: str = "2027-12-31",
    ) -> dict:
        """Ensure PEM truststore exists in a secret group."""
        url = f"{self._secrets_base()}/secretGroups/{secret_group_id}/truststores"

        resp = requests.get(url, headers=self._auth_header)
        resp.raise_for_status()

        truststores = resp.json()
        if isinstance(truststores, dict):
            truststores = truststores.get("items") or truststores.get("content") or truststores.get("data") or []

        for truststore in truststores:
            if truststore.get("name") == name:
                meta = truststore.get("meta", {})
                truststore_id = meta.get("id") or truststore.get("id")
                truststore_path = meta.get("path") or f"truststores/{truststore_id}"
                logger.info("[SKIP] Truststore exists: %s id=%s", name, truststore_id)
                return {
                    "id": truststore_id,
                    "path": truststore_path,
                    "name": name,
                    "raw": truststore,
                }

        with open(cert_path, "rb") as cert_file:
            files = {
                "type": (None, "PEM"),
                "expirationDate": (None, expiration_date),
                "name": (None, name),
                "trustStore": ("istio-cert.pem", cert_file, "application/x-x509-ca-cert"),
            }

            resp = requests.post(
                url,
                headers=self._auth_header,
                files=files,
            )

        if not resp.ok:
            logger.error("ensure_truststore create failed %s: %s", resp.status_code, resp.text)
        resp.raise_for_status()

        data = resp.json()
        created = data[0] if isinstance(data, list) and data else data
        meta = created.get("meta", {})
        truststore_id = meta.get("id") or created.get("id")
        truststore_path = meta.get("path") or f"truststores/{truststore_id}"

        logger.info("Created truststore %s id=%s path=%s", name, truststore_id, truststore_path)
        return {
            "id": truststore_id,
            "path": truststore_path,
            "name": name,
            "raw": created,
        }

    def ensure_tls_context(
        self,
        secret_group_id: str,
        *,
        name: str,
        mode: str,
        truststore_path: Optional[str] = None,
        expiration_date: str = "2027-12-31",
    ) -> dict:
        """Ensure Flex Gateway TLS context exists."""
        url = f"{self._secrets_base()}/secretGroups/{secret_group_id}/tlsContexts"

        resp = requests.get(url, headers=self._headers)
        resp.raise_for_status()

        contexts = resp.json()
        if isinstance(contexts, dict):
            contexts = contexts.get("items") or contexts.get("content") or contexts.get("data") or []

        for ctx in contexts:
            if ctx.get("name") == name:
                ctx_id = ctx.get("id") or ctx.get("meta", {}).get("id")
                logger.info("[SKIP] TLS context exists: %s id=%s", name, ctx_id)
                return {
                    "id": ctx_id,
                    "secretGroupId": secret_group_id,
                    "name": name,
                    "raw": ctx,
                }

        skip_validation = mode == "skip"

        body = {
            "name": name,
            "target": "FlexGateway",
            "expirationDate": expiration_date,
            "minTlsVersion": "TLSv1.2",
            "maxTlsVersion": "TLSv1.3",
            "cipherSuites": [
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ],
            "alpnProtocols": ["h2", "http/1.1"],
            "inboundSettings": {
                "enableClientCertValidation": False,
            },
            "outboundSettings": {
                "skipServerCertValidation": skip_validation,
            },
        }

        if mode == "cert":
            if not truststore_path:
                raise ValueError("truststore_path is required when mode='cert'")
            body["truststore"] = {"path": truststore_path}

        resp = requests.post(url, headers=self._headers, json=body)
        if not resp.ok:
            logger.error("ensure_tls_context create failed %s: %s", resp.status_code, resp.text)
        resp.raise_for_status()

        data = resp.json()
        ctx_id = data.get("id") or data.get("meta", {}).get("id")
        logger.info("Created TLS context %s id=%s mode=%s", name, ctx_id, mode)

        return {
            "id": ctx_id,
            "secretGroupId": secret_group_id,
            "name": name,
            "raw": data,
        }

    def setup_upstream_tls(
        self,
        *,
        mode: Optional[str],
        secret_group_name: str = "flexgateway-canvas-tls",
        cert_path: Optional[str] = None,
        truststore_name: str = "istio-ingress-cert",
        tls_context_name: str = "istio-outbound-tls",
        expiration_date: str = "2027-12-31",
    ) -> Optional[dict]:
        """
        Setup upstream TLS context for Flex Gateway.

        mode:
          None / "" = disabled
          "skip"   = create TLS context with skipServerCertValidation=true
          "cert"   = upload cert to truststore and create TLS context using it
        """
        if not mode:
            logger.info("Upstream TLS mode unset — no TLS context will be used")
            return None

        mode = mode.lower().strip()
        if mode not in {"skip", "cert"}:
            raise ValueError("UPSTREAM_TLS_MODE must be one of: skip, cert")

        group = self.ensure_secret_group(secret_group_name)
        secret_group_id = group["id"]

        truststore = None
        if mode == "cert":
            if not cert_path:
                raise ValueError("ISTIO_CERT_PATH is required when UPSTREAM_TLS_MODE=cert")
            truststore = self.ensure_truststore(
                secret_group_id,
                name=truststore_name,
                cert_path=cert_path,
                expiration_date=expiration_date,
            )

        tls_context = self.ensure_tls_context(
            secret_group_id,
            name=tls_context_name,
            mode=mode,
            truststore_path=truststore["path"] if truststore else None,
            expiration_date=expiration_date,
        )

        return {
            "secretGroupId": secret_group_id,
            "tlsContextId": tls_context["id"],
            "mode": mode,
            "secretGroupName": secret_group_name,
            "tlsContextName": tls_context_name,
            "truststorePath": truststore["path"] if truststore else None,
        }
    
    def configure_api_tls_contexts(
        self,
        api_id: int,
        *,
        outbound_tls: Optional[dict] = None,
        inbound_tls: Optional[dict] = None,
    ) -> dict:
        """POST /apimanager/.../apis/{id}/tls-contexts."""
        body = {}

        if inbound_tls:
            body["inbound"] = {
                "secretGroupId": inbound_tls["secretGroupId"],
                "tlsContextId": inbound_tls["tlsContextId"],
            }

        if outbound_tls:
            body["outbound"] = {
                "secretGroupId": outbound_tls["secretGroupId"],
                "tlsContextId": outbound_tls["tlsContextId"],
            }

        if not body:
            logger.info("[SKIP] No TLS context supplied for API %s", api_id)
            return {}

        url = (
            f"{self._base}/apimanager/api/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/apis/{api_id}/tls-contexts"
        )

        logger.info("Configuring TLS contexts for API %s body=%s", api_id, body)

        resp = requests.post(url, headers=self._headers, json=body)

        logger.info(
            "TLS context response: api_id=%s status=%s body=%s",
            api_id,
            resp.status_code,
            resp.text[:4000],
        )

        if not resp.ok:
            logger.error("configure_api_tls_contexts failed %s: %s", resp.status_code, resp.text)

        resp.raise_for_status()
        return resp.json() if resp.text else {}
    

    def get_api_tls_contexts(self, api_id):
        url = (
            f"{self._base}/apimanager/api/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/apis/{api_id}/tls-contexts"
        )

        resp = requests.get(url, headers=self._headers)

        logger.info(
            "GET TLS contexts api_id=%s status=%s body=%s",
            api_id,
            resp.status_code,
            resp.text,
        )

        return resp
    
    def get_api_instance(self, api_id: str) -> dict:
        """
        Get API Manager API instance details.
        """

        url = (
            f"{self._base}/apimanager/api/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/apis/{api_id}"
        )

        resp = requests.get(
            url,
            headers=self._headers,
        )

        logger.info(
            "GET API instance api_id=%s status=%s",
            api_id,
            resp.status_code,
        )

        if not resp.ok:
            logger.error(
                "get_api_instance failed %s: %s",
                resp.status_code,
                resp.text,
            )

        resp.raise_for_status()

        api = resp.json()

        logger.info(
            "API instance %s details:\n%s",
            api_id,
            json.dumps(api, indent=2),
        )

        return api
    
    def update_api_instance_upstream_tls(
        self,
        *,
        api_id: int | str,
        api_details: dict,
        upstream_url: str,
        tls_context: dict,
    ) -> dict:
        top_level_upstreams = api_details.get("upstreams", [])
        routing_upstreams = api_details.get("routing", [{}])[0].get("upstreams", [])

        if top_level_upstreams and top_level_upstreams[0].get("id"):
            upstream_id = top_level_upstreams[0]["id"]
        elif routing_upstreams and routing_upstreams[0].get("id"):
            upstream_id = routing_upstreams[0]["id"]
        else:
            raise ValueError(f"No upstream id found for API {api_id}")


        endpoint = dict(api_details.get("endpoint", {}))
        endpoint["tlsContexts"] = {"inbound": None}
        endpoint.pop("uri", None)

        existing_upstream_uri = None
        for upstream in api_details.get("upstreams", []):
            if upstream.get("id") == upstream_id:
                existing_upstream_uri = upstream.get("uri")
                break

        upstream_uri = existing_upstream_uri or endpoint.get("uri") or upstream_url

        deployment = api_details.get("deployment", {})

        deployment_body = {
            "environmentId": self.env_id,
            "type": "HY",
            "expectedStatus": "deployed",
            "overwrite": False,
            "targetId": deployment.get("targetId"),
            "targetName": deployment.get("targetName"),
            "gatewayVersion": deployment.get("gatewayVersion", "1.0.0"),
        }


        body = {
            "technology": api_details.get("technology", "flexGateway"),
            "approvalMethod": api_details.get("approvalMethod"),
            "providerId": api_details.get("providerId"),
            "endpointUri": api_details["endpointUri"],
            "endpoint": endpoint,
            "spec": {
                "assetId": api_details["assetId"],
                "groupId": api_details["groupId"],
                "version": api_details["assetVersion"],
            },
            "instanceLabel": api_details["instanceLabel"],
            "routing": api_details["routing"],
            "upstreams": [
                {
                    "id": upstream_id,
                    "label": None,
                    "uri": upstream_uri,
                    "tlsContext": {
                        "secretGroupId": tls_context["secretGroupId"],
                        "tlsContextId": tls_context["tlsContextId"],
                    },
                }
            ],
            "deployment": deployment_body,
        }

        logger.info(
            "Updating upstream TLS for API %s upstream_id=%s body=%s",
            api_id,
            upstream_id,
            json.dumps(body, indent=2),
        )

        resp = requests.patch(
            f"{self._base}/apimanager/xapi/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/apis/{api_id}?checkAutomatedPolicies=true",
            headers=self._headers,
            json=body,
        )

        logger.info(
            "Update upstream TLS response: api_id=%s status=%s body=%s",
            api_id,
            resp.status_code,
            resp.text,
        )

        resp.raise_for_status()
        return resp.json()
    # ------------------------------------------------------------------
    # API Manager
    # ------------------------------------------------------------------

    def create_api_instance(
        self,
        *,
        spec_group_id: Optional[str] = None,
        spec_asset_id: str,
        spec_version: str = "1.0.0",
        endpoint_uri: str,
        label: str,
        endpoint_type: str = "http",
        proxy_path: Optional[str] = None,
        gateway_url: Optional[str] = None,
        technology: str = "flexGateway",
    ) -> dict:
        """POST /apimanager/.../apis → created API instance."""
        group = spec_group_id or self.org_id
        proxy_uri = f"http://0.0.0.0:8081/{proxy_path or label}/"

        body: dict = {
            "spec": {
                "groupId": group,
                "assetId": spec_asset_id,
                "version": spec_version,
            },
            "endpoint": {
                "type": endpoint_type,
                "deploymentType": "HY",
                "uri": endpoint_uri,
                "proxyUri": proxy_uri,
                "isCloudHub": None,
            },
            "technology": technology,
            "instanceLabel": label,
        }

        if gateway_url:
            body["endpointUri"] = f"{gateway_url}/{proxy_path or label}/"

        resp = requests.post(
            f"{self._base}/apimanager/api/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/apis",
            headers=self._headers,
            json=body,
        )
        if not resp.ok:
            logger.error("create_api_instance failed %s: %s", resp.status_code, resp.text)
        resp.raise_for_status()
        api = resp.json()
        logger.info("Created API instance %s  id=%s", label, api.get("id"))
        return api

    def create_api_instance_xapi(
        self,
        *,
        spec_group_id: Optional[str] = None,
        spec_asset_id: str,
        spec_version: str = "1.0.0",
        endpoint_uri: str,
        label: str,
        endpoint_type: str = "http",
        proxy_path: Optional[str] = None,
        gateway_url: str,
        gateway_id: str,
        gateway_name: str,
        upstream_tls: Optional[dict] = None,
        technology: str = "flexGateway",
    ) -> dict:
        """
        POST /apimanager/xapi/.../apis

        Unified create + deploy API instance.
        Supports upstream TLS context.
        """
        group = spec_group_id or self.org_id
        path = proxy_path or label
        endpoint_uri = endpoint_uri.rstrip("/")
        proxy_uri = f"http://0.0.0.0:8081/{path}/"
        public_uri = f"{gateway_url.rstrip('/')}/{path}/"

        upstream: dict = {
            "uri": endpoint_uri,
        }

        if upstream_tls:
            upstream["tlsContext"] = {
                "secretGroupId": upstream_tls["secretGroupId"],
                "tlsContextId": upstream_tls["tlsContextId"],
            }

        body = {
            "technology": technology,
            "endpointUri": public_uri,
            "endpoint": {
                "deploymentType": "HY",
                "type": endpoint_type,
                "proxyUri": proxy_uri,
                "uri": endpoint_uri,
            },
            "spec": {
                "assetId": spec_asset_id,
                "groupId": group,
                "version": spec_version,
            },
            "instanceLabel": label,
            "upstreams": [upstream],
            "deployment": {
                "environmentId": self.env_id,
                "type": "HY",
                "expectedStatus": "deployed",
                "overwrite": False,
                "targetId": gateway_id,
                "targetName": gateway_name,
            },
        }

        url = (
            f"{self._base}/apimanager/xapi/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/apis"
        )

        logger.info(
            "Creating API instance via xapi: label=%s asset=%s version=%s "
            "endpointType=%s gateway=%s upstreamTls=%s url=%s",
            label,
            spec_asset_id,
            spec_version,
            endpoint_type,
            gateway_name,
            bool(upstream_tls),
            url,
        )

        logger.info(
            "create_api_instance_xapi request body: label=%s body=%s",
            label,
            json.dumps(body, indent=2),
        )
        resp = requests.post(url, headers=self._headers, json=body)

        logger.info(
            "create_api_instance_xapi response: label=%s status=%s headers=%s body=%s",
            label,
            resp.status_code,
            {
                "x-request-id": resp.headers.get("x-request-id"),
                "x-sfdc-request-id": resp.headers.get("x-sfdc-request-id"),
                "x-anypnt-trx-id": resp.headers.get("x-anypnt-trx-id"),
                "content-type": resp.headers.get("content-type"),
            },
            resp.text[:4000],
        )

        if not resp.ok:
            logger.error("create_api_instance_xapi failed %s: %s", resp.status_code, resp.text)

        resp.raise_for_status()
        api = resp.json()
        logger.info("Created/deployed API instance %s id=%s", label, api.get("id"))
        return api
    
    def deploy_to_gateway(
        self,
        api_id: int,
        gateway_id: str,
        gateway_name: str = "N/A",
    ) -> dict:
        """POST /proxies/xapi/.../apis/{id}/deployments → deploy API to gateway."""
        body = {
            "gatewayVersion": "N/A",
            "targetId": gateway_id,
            "targetName": gateway_name,
            "type": "HY",
            "environmentId": self.env_id,
        }
        url = (
            f"{self._base}/proxies/xapi/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/apis/{api_id}/deployments"
        )
        logger.info(
            "Deploying API to gateway: api_id=%s gateway_id=%s gateway_name=%s url=%s body=%s",
            api_id,
            gateway_id,
            gateway_name,
            url,
            body,
        )
        resp = requests.post(
            url,
            headers=self._headers,
            json=body,
        )
        logger.info(
            "Deploy response: api_id=%s status=%s headers=%s body=%s",
            api_id,
            resp.status_code,
            {
                "x-request-id": resp.headers.get("x-request-id"),
                "x-sfdc-request-id": resp.headers.get("x-sfdc-request-id"),
                "x-anypnt-trx-id": resp.headers.get("x-anypnt-trx-id"),
                "content-type": resp.headers.get("content-type"),
            },
            resp.text[:4000],
        )
        if resp.status_code == 400:
            logger.info("[SKIP] API %s already deployed to gateway (400)", api_id)
            return resp.json() if resp.text else {}
        if resp.status_code == 502:
            logger.error(
                "deploy_to_gateway returned 502. api_id=%s gateway_id=%s gateway_name=%s response=%s",
                api_id,
                gateway_id,
                gateway_name,
                resp.text[:4000],
            )
        if not resp.ok:
            logger.error("deploy_to_gateway failed %s: %s", resp.status_code, resp.text)
        resp.raise_for_status()
        logger.info("Deployed API %s to gateway %s", api_id, gateway_id)
        return resp.json()

    def list_api_instances(
        self,
        asset_id: Optional[str] = None,
    ) -> list[dict]:
        """
        GET /apimanager/.../apis → list of API instances.

        If asset_id is provided, filters by that Exchange asset.
        Returns a flat list of API instance dicts (extracted from the
        nested assets[].apis[] response structure).
        """
        path = (
            f"{self._base}/apimanager/api/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/apis"
        )
        if asset_id:
            path += f"?assetId={asset_id}"

        resp = requests.get(path, headers=self._headers)
        resp.raise_for_status()
        data = resp.json()
        instances = []
        for asset in data.get("assets", []):
            for api in asset.get("apis", []):
                instances.append(api)
        return instances

    def find_api_instance_by_label(
        self,
        label: str,
        asset_id: Optional[str] = None,
    ) -> Optional[dict]:
        """Find an existing API instance by its instanceLabel (idempotency check)."""
        instances = self.list_api_instances(asset_id=asset_id)
        for api in instances:
            if api.get("instanceLabel") == label:
                return api
        return None

    def apply_policy(
        self,
        api_id: int,
        policy_asset_id: str,
        policy_version: str,
        group_id: str,
        config: dict,
    ) -> dict:
        """
        POST /apimanager/.../apis/{id}/policies → apply a policy.

        Handles 409 (already applied) gracefully — logs and returns
        the response body without raising. Matches the idempotency
        pattern from the Mule apply-policy-subflow.
        """
        body = {
            "configurationData": config,
            "pointcutData": None,
            "groupId": group_id,
            "assetId": policy_asset_id,
            "assetVersion": policy_version,
        }
        resp = requests.post(
            f"{self._base}/apimanager/api/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/apis/{api_id}/policies",
            headers=self._headers,
            json=body,
        )

        if resp.status_code == 409:
            logger.info(
                "[SKIP] Policy %s already applied to API %s (409)",
                policy_asset_id, api_id,
            )
            return resp.json() if resp.text else {}

        if resp.status_code == 400:
            logger.warning(
                "[WARN] Policy %s on API %s returned 400: %s",
                policy_asset_id, api_id, resp.text,
            )
            return resp.json() if resp.text else {}

        resp.raise_for_status()
        result = resp.json()
        logger.info(
            "Applied policy %s v%s to API %s",
            policy_asset_id, policy_version, api_id,
        )
        return result

    def resolve_policy_version(
        self,
        group_id: str,
        asset_id: str,
        minor_version: str,
    ) -> str:
        """GET /exchange/.../minorVersions/{minor} → resolved patch version."""
        resp = requests.get(
            f"{self._base}/exchange/api/v2/assets/{group_id}/{asset_id}"
            f"/minorVersions/{minor_version}",
            headers=self._headers,
        )
        resp.raise_for_status()
        version = resp.json()["version"]
        logger.debug("Resolved %s/%s %s → %s", group_id, asset_id, minor_version, version)
        return version

    def delete_api_instance(self, api_id: int) -> None:
        """DELETE /apimanager/.../apis/{id}."""
        resp = requests.delete(
            f"{self._base}/apimanager/api/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/apis/{api_id}",
            headers=self._headers,
        )
        resp.raise_for_status()
        logger.info("Deleted API instance %s", api_id)

    # ------------------------------------------------------------------
    # Exchange
    # ------------------------------------------------------------------

    def exchange_asset_exists(self, asset_id: str, version: str = None) -> bool:
        """Return True if any version of this asset exists in Exchange."""
        if version:
            path = f"{self._base}/exchange/api/v2/assets/{self.org_id}/{asset_id}/{version}"
        else:
            path = f"{self._base}/exchange/api/v2/assets/{self.org_id}/{asset_id}"
        resp = requests.get(path, headers=self._headers)
        return resp.status_code == 200

    def get_next_exchange_version(self, asset_id: str) -> str:
        """
        Query Exchange for all versions of an asset and return the next
        available patch version. Handles soft-deleted versions by bumping
        past them if publish returns 409.
        """
        resp = requests.get(
            f"{self._base}/exchange/api/v2/assets/{self.org_id}/{asset_id}",
            headers=self._headers,
        )
        if resp.status_code == 404:
            return "1.0.0"

        resp.raise_for_status()
        versions = resp.json().get("versions", [])

        if not versions:
            return "1.0.0"

        max_patch = -1
        for v in versions:
            ver = v.get("version", "0.0.0")
            parts = ver.split(".")
            if len(parts) == 3 and parts[0] == "1" and parts[1] == "0":
                try:
                    max_patch = max(max_patch, int(parts[2]))
                except ValueError:
                    pass

        next_version = f"1.0.{max_patch + 1}" if max_patch >= 0 else "1.0.0"
        logger.info("Exchange version for %s: latest published=%s next=%s",
                    asset_id, f"1.0.{max_patch}" if max_patch >= 0 else "none", next_version)
        return next_version

    def publish_exchange_asset(
        self,
        name: str,
        asset_id: str,
        exchange_type: str,
        *,
        version: str = "1.0.0",
        api_version: Optional[str] = None,
        a2a_card: Optional[bytes] = None,
        agent_metadata: Optional[bytes] = None,
        oas_content: Optional[bytes] = None,
        oas_filename: Optional[str] = None,
    ) -> str:
        """
        POST multipart to Exchange to publish an asset.
        Returns the publicationStatusLink for polling.

        exchange_type: "mcp" | "agent" | "rest-api"
        a2a_card / agent_metadata: required bytes for exchange_type="agent"
        """
        url = (
            f"{self._base}/exchange/api/v2/organizations/{self.org_id}"
            f"/assets/{self.org_id}/{asset_id}/{version}"
        )
        # Always use multipart tuples — (None, value) forces multipart/form-data
        # even when there are no actual file attachments
        files = [
            ("name",   (None, name)),
            ("type",   (None, exchange_type)),
            ("status", (None, "published")),
        ]
        #if a2a_card and agent_metadata:
        #    files += [
        #        ("files.a2a-card.json",
        #         ("a2a-card.json", a2a_card, "application/json")),
        #        ("files.agent-metadata.json",
        #         ("agent-metadata.json", agent_metadata, "application/json")),
        #    ]
        if a2a_card and agent_metadata:
            files += [
                ("files.a2a-card.json",
                 ("a2a-card.json", a2a_card, "application/json")),
                ("files.agent-metadata.json",
                 ("agent-metadata.json", agent_metadata, "application/json")),
            ]
        if oas_content and oas_filename:
            ext = oas_filename.lower()
            classifier = "files.oas.yaml" if ext.endswith((".yaml", ".yml")) else "files.oas.json"
            mime = "application/yaml" if ext.endswith((".yaml", ".yml")) else "application/json"
            # Extract apiVersion from spec content; fall back to "v1"
            api_version = "1.0.0"
            try:
                parsed = _yaml.safe_load(oas_content)
                api_version = parsed.get("info", {}).get("version", "1.0.0")
            except Exception:
                pass
            files += [
                (classifier,              (oas_filename, oas_content, mime)),
                ("properties.mainFile",   (None, oas_filename)),
                ("properties.apiVersion", (None, api_version)),
            ]

        if exchange_type == "http-api":
            files.append((
                "properties.apiVersion",
                (None, api_version or "1.0.0"),
            ))
        resp = requests.post(url, headers=self._auth_header, files=files)

        # Handle soft-deleted version conflict — bump and retry once
        if resp.status_code == 409 and "deleted asset" in resp.text.lower():
            parts = version.split(".")
            if exchange_type == "http-api":
                bumped = f"{int(parts[0]) + 1}.0.0"
            else:
                bumped = f"{parts[0]}.{parts[1]}.{int(parts[2]) + 1}"
            logger.warning(
                "Exchange version %s is soft-deleted for %s — bumping to %s",
                version, asset_id, bumped,
            )
            bumped_url = (
                f"{self._base}/exchange/api/v2/organizations/{self.org_id}"
                f"/assets/{self.org_id}/{asset_id}/{bumped}"
            )
            # Update version in files list
            files = [(k, v) for k, v in files if k != "properties.apiVersion"]
            files.append(("properties.apiVersion", (None, bumped)))
            resp = requests.post(bumped_url, headers=self._auth_header, files=files)
            version = bumped

        if not resp.ok:
            logger.error("Exchange publish failed %s: %s", resp.status_code, resp.text)
        resp.raise_for_status()
        status_url = resp.json()["publicationStatusLink"]
        logger.info("Exchange publish submitted: %s v%s (%s)", asset_id, version, exchange_type)
        return status_url

    def wait_for_exchange_publish(
        self,
        status_url: str,
        *,
        timeout: int = 60,
        poll_interval: int = 3,
    ) -> None:
        """Poll publication status until completed, or raise on error/timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = requests.get(status_url, headers=self._auth_header)
            resp.raise_for_status()
            data = resp.json()
            status = data.get("status")
            if status == "completed":
                logger.info("Exchange publish completed")
                return
            if status == "error":
                errors = [
                    e
                    for step in data.get("steps", [])
                    for e in step.get("errors", [])
                ]
                raise RuntimeError(f"Exchange publish failed: {errors}")
            time.sleep(poll_interval)
        raise TimeoutError(f"Exchange publish did not complete within {timeout}s")
