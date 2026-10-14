"""Caller authentication and authorization.

Agents (and the gateway acting for them) present agent credentials. When an
identity fabric URL is configured, credentials are introspected and every
request is authorized by the fabric's ``/v1/authorize``. Otherwise the
credential is verified locally against the fabric's JWKS and evaluated by a
local agentic-core PolicyEngine. There is no "allow all" mode: the service
refuses to start without one of the two.

Human auditors authenticate with the enterprise OIDC provider and carry
roles in their token.
"""

from __future__ import annotations

import fnmatch
from typing import Any, Protocol

from agentic_core.domain.classification import Decision, RiskLevel
from agentic_core.policy import PolicyEngine, PolicyRequest, Resource, Subject
from pydantic import BaseModel, ConfigDict, Field

from agent_action_provenance.domain.errors import ForbiddenError, UnauthorizedError
from agent_action_provenance.integrations.identity_fabric import IdentityFabricClient
from agent_action_provenance.security.jwks import KeyResolver, verify_jwt


class AgentPrincipal(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    scopes: frozenset[str]
    delegation_chain: tuple[str, ...] = ()
    claims: dict[str, Any] = Field(default_factory=dict, exclude=True, repr=False)


class AgentAuthorization(BaseModel):
    model_config = ConfigDict(frozen=True)

    principal: AgentPrincipal
    decision: Decision
    matched_rules: tuple[str, ...]
    policy_version: str
    policy_digest: str
    reason: str
    authorizer: str


class AgentAuthorizer(Protocol):
    async def authenticate(self, token: str) -> AgentPrincipal: ...

    async def decide(
        self,
        token: str,
        principal: AgentPrincipal,
        *,
        action: str,
        resource: Resource,
        environment: dict[str, Any],
    ) -> AgentAuthorization: ...


def _act_chain(act: Any) -> tuple[str, ...]:
    out: list[str] = []
    while isinstance(act, dict) and isinstance(act.get("sub"), str):
        out.append(act["sub"])
        act = act.get("act")
    return tuple(out)


class FabricAuthorizer:
    """Introspection and policy decisions delegated to agent-identity-fabric."""

    def __init__(self, client: IdentityFabricClient, *, fabric_url: str) -> None:
        self._client = client
        self._name = fabric_url.rstrip("/")

    async def authenticate(self, token: str) -> AgentPrincipal:
        status = await self._client.introspect(token)
        if not status.active or not status.sub:
            raise UnauthorizedError("credential is not active")
        return AgentPrincipal(
            subject=status.sub, scopes=status.scopes, delegation_chain=status.chain()
        )

    async def decide(
        self,
        token: str,
        principal: AgentPrincipal,
        *,
        action: str,
        resource: Resource,
        environment: dict[str, Any],
    ) -> AgentAuthorization:
        decision = await self._client.authorize(
            token,
            action=action,
            resource_type=resource.type,
            resource_id=resource.id,
            classification=resource.classification,
            attributes=resource.attributes,
            environment=environment,
        )
        if decision.agent != principal.subject:
            raise UnauthorizedError("authorization subject does not match the credential")
        return AgentAuthorization(
            principal=principal,
            decision=decision.decision,
            matched_rules=decision.matched_rules,
            policy_version=decision.policy_version,
            policy_digest=decision.policy_digest,
            reason=decision.reason,
            authorizer=self._name,
        )


class LocalPolicyAuthorizer:
    """Verifies agent credentials against the fabric JWKS; decides with local policy."""

    def __init__(
        self, resolver: KeyResolver, policy: PolicyEngine, *, issuer: str, audience: str
    ) -> None:
        self._resolver = resolver
        self._policy = policy
        self._issuer = issuer
        self._audience = audience

    async def authenticate(self, token: str) -> AgentPrincipal:
        claims = await verify_jwt(
            token, self._resolver, issuer=self._issuer, audience=self._audience
        )
        raw_scope = claims.get("scope", "")
        scopes = frozenset(raw_scope.split()) if isinstance(raw_scope, str) else frozenset()
        return AgentPrincipal(
            subject=str(claims["sub"]),
            scopes=scopes,
            delegation_chain=_act_chain(claims.get("act")),
            claims=claims,
        )

    async def decide(
        self,
        token: str,
        principal: AgentPrincipal,
        *,
        action: str,
        resource: Resource,
        environment: dict[str, Any],
    ) -> AgentAuthorization:
        raw_risk = principal.claims.get("risk", 1)
        risk = RiskLevel(max(1, min(4, raw_risk))) if isinstance(raw_risk, int) else RiskLevel.LOW
        subject = Subject(
            id=principal.subject,
            kind="agent",
            attributes={
                "scopes": sorted(principal.scopes),
                "action_in_scope": any(fnmatch.fnmatchcase(action, s) for s in principal.scopes),
                "delegated": bool(principal.delegation_chain),
                "delegation_depth": len(principal.delegation_chain),
                "risk": int(risk),
            },
        )
        result = self._policy.evaluate(
            PolicyRequest(
                subject=subject,
                action=action,
                resource=resource,
                risk=risk,
                environment=environment,
            )
        )
        return AgentAuthorization(
            principal=principal,
            decision=result.decision,
            matched_rules=result.matched_rules,
            policy_version=result.policy_version,
            policy_digest=result.policy_digest,
            reason=result.reason,
            authorizer="local-policy",
        )


class AuditorRole:
    AUDITOR = "provenance-auditor"  # read records, lineage, request exports
    APPROVER = "provenance-approver"  # approve exports that policy holds for sign-off


class AuditorPrincipal(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    roles: frozenset[str]


class AuditorAuthenticator:
    def __init__(
        self, resolver: KeyResolver, *, issuer: str, audience: str, roles_claim: str = "roles"
    ) -> None:
        self._resolver = resolver
        self._issuer = issuer
        self._audience = audience
        self._roles_claim = roles_claim

    async def authenticate(self, authorization: str | None) -> AuditorPrincipal:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise UnauthorizedError("bearer token required")
        claims = await verify_jwt(
            authorization[7:].strip(), self._resolver, issuer=self._issuer, audience=self._audience
        )
        raw = claims.get(self._roles_claim, [])
        roles = (
            frozenset(r for r in raw if isinstance(r, str))
            if isinstance(raw, list)
            else frozenset()
        )
        return AuditorPrincipal(subject=str(claims["sub"]), roles=roles)


def require_role(principal: AuditorPrincipal, *allowed: str) -> None:
    if not principal.roles.intersection(allowed):
        raise ForbiddenError(f"requires one of roles {sorted(allowed)}")
