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
        resp = requests.post(
            f"{self._base}/proxies/xapi/v1/organizations/{self.org_id}"
            f"/environments/{self.env_id}/apis/{api_id}/deployments",
            headers=self._headers,
            json=body,
        )
        if resp.status_code == 400:
            logger.info("[SKIP] API %s already deployed to gateway (400)", api_id)
            return resp.json() if resp.text else {}
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

    def exchange_asset_exists(self, asset_id: str, version: str = "1.0.0") -> bool:
        """Return True if the asset already exists in Exchange (idempotency check)."""
        resp = requests.get(
            f"{self._base}/exchange/api/v2/assets/{self.org_id}/{asset_id}/{version}",
            headers=self._headers,
        )
        return resp.status_code == 200

    def publish_exchange_asset(
        self,
        name: str,
        asset_id: str,
        exchange_type: str,
        *,
        version: str = "1.0.0",
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
                import yaml as _yaml
                parsed = _yaml.safe_load(oas_content)
                api_version = parsed.get("info", {}).get("version", "1.0.0")
            except Exception:
                pass
            files += [
                (classifier,              (oas_filename, oas_content, mime)),
                ("properties.mainFile",   (None, oas_filename)),
                ("properties.apiVersion", (None, str(api_version))),
            ]
        resp = requests.post(url, headers=self._auth_header, files=files)
        if not resp.ok:
            logger.error("Exchange publish failed %s: %s", resp.status_code, resp.text)
        resp.raise_for_status()
        status_url = resp.json()["publicationStatusLink"]
        logger.info("Exchange publish submitted: %s (%s)", asset_id, exchange_type)
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
