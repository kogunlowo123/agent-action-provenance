"""Typed client for agent-identity-fabric.

Endpoints (github.com/kogunlowo123/agent-identity-fabric):

* ``POST /oauth2/token``      RFC 7523 jwt-bearer grant (workload token in,
                              short-lived agent credential out)
* ``POST /oauth2/introspect`` RFC 7662 token status, including revocation and
                              suspension epochs
* ``POST /v1/authorize``      policy decision for the token's subject

Every transport failure or unexpected response raises
``UpstreamUnavailableError`` so callers fail closed.
"""

from __future__ import annotations

from typing import Any

import httpx
from agentic_core.domain.classification import DataClassification, Decision
from pydantic import BaseModel, ConfigDict, ValidationError

from agent_action_provenance.domain.errors import UnauthorizedError, UpstreamUnavailableError

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class Introspection(BaseModel):
    model_config = ConfigDict(frozen=True)

    active: bool
    sub: str | None = None
    scope: str | None = None
    exp: int | None = None
    jti: str | None = None
    act: dict[str, Any] | None = None

    @property
    def scopes(self) -> frozenset[str]:
        return frozenset((self.scope or "").split())

    def chain(self) -> tuple[str, ...]:
        """Delegation chain from the nested RFC 8693 ``act`` claim, nearest first."""
        out: list[str] = []
        node = self.act
        while isinstance(node, dict) and isinstance(node.get("sub"), str):
            out.append(node["sub"])
            node = node.get("act")
        return tuple(out)


class FabricDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Decision
    agent: str
    action: str
    resource: str
    matched_rules: tuple[str, ...]
    policy_version: str
    policy_digest: str
    reason: str
    delegation_chain: tuple[str, ...] = ()


class IssuedToken(BaseModel):
    model_config = ConfigDict(frozen=True)

    access_token: str
    token_type: str
    expires_in: int
    scope: str


class IdentityFabricClient:
    def __init__(self, base_url: str, *, client: httpx.AsyncClient) -> None:
        self._base = base_url.rstrip("/")
        self._client = client

    async def _post(
        self,
        path: str,
        *,
        data: dict[str, str] | None = None,
        json: Any = None,
        bearer: str | None = None,
    ) -> httpx.Response:
        headers = {"Authorization": f"Bearer {bearer}"} if bearer else None
        try:
            return await self._client.post(
                f"{self._base}{path}", data=data, json=json, headers=headers
            )
        except httpx.HTTPError as exc:
            raise UpstreamUnavailableError(f"identity fabric unreachable: {exc}") from exc

    async def introspect(self, token: str) -> Introspection:
        response = await self._post("/oauth2/introspect", data={"token": token})
        return self._parse(response, Introspection)

    async def authorize(
        self,
        token: str,
        *,
        action: str,
        resource_type: str,
        resource_id: str,
        classification: DataClassification,
        attributes: dict[str, Any],
        environment: dict[str, Any],
    ) -> FabricDecision:
        response = await self._post(
            "/v1/authorize",
            bearer=token,
            json={
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "resource_classification": int(classification),
                "resource_attributes": attributes,
                "environment": environment,
            },
        )
        if response.status_code == 401:
            raise UnauthorizedError("identity fabric rejected the credential")
        return self._parse(response, FabricDecision)

    async def token_jwt_bearer(
        self, *, client_id: str, assertion: str, scope: str | None = None
    ) -> IssuedToken:
        data = {"grant_type": JWT_BEARER, "client_id": client_id, "assertion": assertion}
        if scope:
            data["scope"] = scope
        response = await self._post("/oauth2/token", data=data)
        if response.status_code in (400, 401):
            raise UnauthorizedError("identity fabric refused to issue a credential")
        return self._parse(response, IssuedToken)

    @staticmethod
    def _parse[M: BaseModel](response: httpx.Response, model: type[M]) -> M:
        if response.status_code != 200:
            raise UpstreamUnavailableError(f"identity fabric returned HTTP {response.status_code}")
        try:
            return model.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise UpstreamUnavailableError("identity fabric returned an invalid body") from exc
