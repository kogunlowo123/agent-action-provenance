"""Adapters: WORM archives, identity fabric client, JWKS, settings and container wiring."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import boto3
import httpx
import pytest
from agentic_core.domain.classification import DataClassification, Decision
from agentic_core.policy import Resource
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from agent_action_provenance.config import Settings
from agent_action_provenance.domain.errors import (
    ArchiveConflictError,
    UnauthorizedError,
    UpstreamUnavailableError,
)
from agent_action_provenance.infrastructure.archive import (
    FilesystemWormArchive,
    S3ObjectLockArchive,
    validate_key,
)
from agent_action_provenance.integrations.identity_fabric import IdentityFabricClient
from agent_action_provenance.runtime.container import build_container
from agent_action_provenance.security.authorization import (
    AuditorAuthenticator,
    FabricAuthorizer,
    require_role,
)
from agent_action_provenance.security.jwks import RemoteJwks, StaticJwks
from agent_action_provenance.security.keys import private_pem
from tests.conftest import (
    AGENT,
    AUDITOR_AUDIENCE,
    AUDITOR_ISSUER,
    FakeIdp,
    agent_token,
    submission,
)

RETAIN = datetime(2033, 1, 1, tzinfo=UTC)
FABRIC = "https://identity.corp.test"


class TestFilesystemArchive:
    async def test_write_once_and_idempotent(self, tmp_path: Path) -> None:
        archive = FilesystemWormArchive(tmp_path)
        first = await archive.put("batches/00000000000000000001.json", b"{}", retain_until=RETAIN)
        assert not first.already_present
        mode = await asyncio.to_thread(lambda: Path(first.location).stat().st_mode)
        assert not mode & stat.S_IWUSR
        again = await archive.put("batches/00000000000000000001.json", b"{}", retain_until=RETAIN)
        assert again.already_present
        assert again.sha256 == first.sha256
        with pytest.raises(ArchiveConflictError):
            await archive.put("batches/00000000000000000001.json", b"[]", retain_until=RETAIN)

    @pytest.mark.parametrize("key", ["../escape.json", "/abs.json", "Batches/x", "a/../../b", ""])
    def test_rejects_unsafe_keys(self, key: str) -> None:
        with pytest.raises(ValueError, match="invalid archive key"):
            validate_key(key)


class TestS3ObjectLockArchive:
    def _client(self) -> Any:
        return boto3.client(
            "s3", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test"
        )

    def test_mode_is_validated(self) -> None:
        with pytest.raises(ValueError, match="object lock mode"):
            S3ObjectLockArchive(self._client(), bucket="b", mode="NONE")

    async def test_put_with_object_lock_and_checksum(self) -> None:
        client = self._client()
        body = b'{"batch": 1}'
        checksum = base64.b64encode(hashlib.sha256(body).digest()).decode()
        with Stubber(client) as stub:
            stub.add_response(
                "put_object",
                {"ETag": '"etag"', "ChecksumSHA256": checksum},
                {
                    "Bucket": "audit-bucket",
                    "Key": "provenance/batches/x.json",
                    "Body": body,
                    "ContentType": "application/json",
                    "ChecksumSHA256": checksum,
                    "IfNoneMatch": "*",
                    "ObjectLockMode": "COMPLIANCE",
                    "ObjectLockRetainUntilDate": RETAIN,
                },
            )
            archive = S3ObjectLockArchive(client, bucket="audit-bucket", prefix="/provenance/")
            receipt = await archive.put("batches/x.json", body, retain_until=RETAIN)
        assert receipt.location == "s3://audit-bucket/provenance/batches/x.json"
        assert not receipt.already_present

    async def test_existing_identical_object_is_idempotent(self) -> None:
        client = self._client()
        body = b"same"
        checksum = base64.b64encode(hashlib.sha256(body).digest()).decode()
        with Stubber(client) as stub:
            stub.add_client_error("put_object", "PreconditionFailed", http_status_code=412)
            stub.add_response("head_object", {"ChecksumSHA256": checksum})
            receipt = await S3ObjectLockArchive(client, bucket="b").put(
                "k.json", body, retain_until=RETAIN
            )
        assert receipt.already_present
        assert receipt.location == "s3://b/k.json"

    async def test_existing_different_object_conflicts(self) -> None:
        client = self._client()
        with Stubber(client) as stub:
            stub.add_client_error("put_object", "PreconditionFailed", http_status_code=412)
            stub.add_response("head_object", {"ChecksumSHA256": "other"})
            with pytest.raises(ArchiveConflictError):
                await S3ObjectLockArchive(client, bucket="b").put(
                    "k.json", b"x", retain_until=RETAIN
                )

    async def test_other_errors_propagate(self) -> None:
        client = self._client()
        with Stubber(client) as stub:
            stub.add_client_error("put_object", "AccessDenied", http_status_code=403)
            with pytest.raises(ClientError):
                await S3ObjectLockArchive(client, bucket="b").put(
                    "k.json", b"x", retain_until=RETAIN
                )


def fabric_transport(handler_map: dict[str, Any]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        result = handler_map[request.url.path]
        return result(request) if callable(result) else result

    return httpx.MockTransport(handler)


DECISION = {
    "decision": "allow",
    "agent": AGENT,
    "action": "provenance:record:write",
    "resource": "agent-action:act-1",
    "matched_rules": ["allow-scoped-actions"],
    "policy_version": "2026.10.0",
    "policy_digest": "sha256:" + "c" * 64,
    "reason": "explicit allow",
    "delegation_chain": [],
}


class TestIdentityFabricClient:
    async def test_introspect_authorize_and_token(self) -> None:
        seen: dict[str, Any] = {}

        def authorize(request: httpx.Request) -> httpx.Response:
            seen["auth"] = request.headers["authorization"]
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json=DECISION)

        transport = fabric_transport(
            {
                "/oauth2/introspect": httpx.Response(
                    200,
                    json={
                        "active": True,
                        "sub": AGENT,
                        "scope": "a b",
                        "act": {
                            "sub": "spiffe://x/agent/a/b",
                            "act": {"sub": "spiffe://x/agent/a/c"},
                        },
                    },
                ),
                "/v1/authorize": authorize,
                "/oauth2/token": httpx.Response(
                    200,
                    json={
                        "access_token": "t",
                        "token_type": "Bearer",
                        "expires_in": 600,
                        "scope": "a",
                    },
                ),
            }
        )
        async with httpx.AsyncClient(transport=transport) as http:
            client = IdentityFabricClient(FABRIC + "/", client=http)
            status = await client.introspect("tok")
            assert status.scopes == {"a", "b"}
            assert status.chain() == ("spiffe://x/agent/a/b", "spiffe://x/agent/a/c")
            decision = await client.authorize(
                "tok",
                action="provenance:record:write",
                resource_type="agent-action",
                resource_id="act-1",
                classification=DataClassification.RESTRICTED,
                attributes={"own_action": True},
                environment={},
            )
            assert decision.decision is Decision.ALLOW
            assert seen["auth"] == "Bearer tok"
            assert seen["body"]["resource_classification"] == 3
            issued = await client.token_jwt_bearer(client_id=AGENT, assertion="w", scope="a")
            assert issued.expires_in == 600

    @pytest.mark.parametrize(
        ("response", "error"),
        [
            (httpx.Response(500), UpstreamUnavailableError),
            (httpx.Response(200, content=b"not json"), UpstreamUnavailableError),
            (httpx.Response(200, json={"unexpected": True}), UpstreamUnavailableError),
        ],
    )
    async def test_bad_responses_fail_closed(self, response: httpx.Response, error: type) -> None:
        transport = fabric_transport({"/oauth2/introspect": response})
        async with httpx.AsyncClient(transport=transport) as http:
            with pytest.raises(error):
                await IdentityFabricClient(FABRIC, client=http).introspect("tok")

    async def test_rejections_and_outage(self) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        transport = fabric_transport(
            {
                "/v1/authorize": httpx.Response(401, json={"error": "unauthorized"}),
                "/oauth2/token": httpx.Response(400, json={"error": "invalid_grant"}),
                "/oauth2/introspect": down,
            }
        )
        async with httpx.AsyncClient(transport=transport) as http:
            client = IdentityFabricClient(FABRIC, client=http)
            with pytest.raises(UnauthorizedError):
                await client.authorize(
                    "t",
                    action="a",
                    resource_type="r",
                    resource_id="*",
                    classification=DataClassification.PUBLIC,
                    attributes={},
                    environment={},
                )
            with pytest.raises(UnauthorizedError):
                await client.token_jwt_bearer(client_id=AGENT, assertion="w")
            with pytest.raises(UpstreamUnavailableError, match="unreachable"):
                await client.introspect("t")

    async def test_fabric_authorizer(self) -> None:
        transport = fabric_transport(
            {
                "/oauth2/introspect": httpx.Response(
                    200, json={"active": True, "sub": AGENT, "scope": "provenance:record:write"}
                ),
                "/v1/authorize": httpx.Response(200, json=DECISION),
            }
        )
        async with httpx.AsyncClient(transport=transport) as http:
            authorizer = FabricAuthorizer(
                IdentityFabricClient(FABRIC, client=http), fabric_url=FABRIC + "/"
            )
            principal = await authorizer.authenticate("tok")
            result = await authorizer.decide(
                "tok",
                principal,
                action="provenance:record:write",
                resource=Resource(type="agent-action"),
                environment={},
            )
            assert result.authorizer == FABRIC
            assert result.decision is Decision.ALLOW
            imposter = principal.model_copy(update={"subject": "spiffe://x/agent/a/z"})
            with pytest.raises(UnauthorizedError, match="does not match"):
                await authorizer.decide(
                    "tok", imposter, action="a", resource=Resource(type="r"), environment={}
                )

    async def test_inactive_credential(self) -> None:
        transport = fabric_transport(
            {"/oauth2/introspect": httpx.Response(200, json={"active": False})}
        )
        async with httpx.AsyncClient(transport=transport) as http:
            authorizer = FabricAuthorizer(
                IdentityFabricClient(FABRIC, client=http), fabric_url=FABRIC
            )
            with pytest.raises(UnauthorizedError, match="not active"):
                await authorizer.authenticate("tok")


class TestAuditorAuthentication:
    async def test_roles_and_rejections(self, auditor_idp: FakeIdp) -> None:
        auth = AuditorAuthenticator(
            StaticJwks(auditor_idp.jwks()), issuer=AUDITOR_ISSUER, audience=AUDITOR_AUDIENCE
        )
        token = auditor_idp.mint(
            sub="a@corp.test", aud=AUDITOR_AUDIENCE, roles=["provenance-auditor", 7]
        )
        who = await auth.authenticate(f"Bearer {token}")
        assert who.roles == {"provenance-auditor"}
        require_role(who, "provenance-auditor")
        odd = auditor_idp.mint(sub="a@corp.test", aud=AUDITOR_AUDIENCE, roles="admin")
        assert (await auth.authenticate(f"Bearer {odd}")).roles == frozenset()
        for header in (None, "Basic abc", "Bearer not-a-jwt"):
            with pytest.raises(UnauthorizedError):
                await auth.authenticate(header)

    async def test_remote_jwks_caches_and_fails_closed(self, auditor_idp: FakeIdp) -> None:
        calls = {"n": 0}

        def handler(_: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, json=auditor_idp.jwks())

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            jwks = RemoteJwks("https://login.corp.test/jwks", client=http)
            assert await jwks.key_for("idp-1") is not None
            assert await jwks.key_for("idp-1") is not None
            assert calls["n"] == 1
            with pytest.raises(UnauthorizedError, match="unknown signing key"):
                await jwks.key_for("other")


class TestSettings:
    def base(self, tmp_path: Path, **kw: Any) -> dict[str, Any]:
        values: dict[str, Any] = {
            "environment": "test",
            "public_url": "https://provenance.corp.test",
            "database_url": f"sqlite+aiosqlite:///{tmp_path / 'db.sqlite'}",
            "dev_ephemeral_keys": True,
            "agent_issuer": FABRIC,
            "agent_audience": "agent-platform",
            "agent_jwks_url": FABRIC + "/jwks",
            "auditor_issuer": AUDITOR_ISSUER,
            "auditor_audience": AUDITOR_AUDIENCE,
            "auditor_jwks_url": "https://login.corp.test/jwks",
        }
        values.update(kw)
        return values

    def test_fails_closed(self, tmp_path: Path) -> None:
        cases = [
            ({"environment": "production"}, "production"),
            ({"dev_ephemeral_keys": False}, "signing configuration incomplete"),
            ({"agent_jwks_url": None}, "PROVENANCE_FABRIC_URL"),
            ({"archive_backend": "s3"}, "ARCHIVE_BUCKET"),
        ]
        for change, message in cases:
            with pytest.raises(ValidationError, match=message):
                Settings(**self.base(tmp_path, **change))

    def test_derived_values(self, tmp_path: Path) -> None:
        s = Settings(**self.base(tmp_path, mcp_allowed_hosts=["provenance.internal:80"]))
        assert s.public_base == "https://provenance.corp.test"
        assert "provenance.corp.test" in s.mcp_hosts
        assert "provenance.internal:80" in s.mcp_hosts
        assert s.archive_retention == timedelta(days=2555)
        assert s.batch_max_wait == 0.05

    async def test_container_with_key_files_fabric_and_s3(
        self, tmp_path: Path, auditor_idp: FakeIdp
    ) -> None:
        log_key, audit_key = tmp_path / "log-2026-10.pem", tmp_path / "audit-2026-10.pem"
        log_key.write_bytes(private_pem(Ed25519PrivateKey.generate()))
        audit_key.write_bytes(private_pem(Ed25519PrivateKey.generate()))
        settings = Settings(
            **self.base(
                tmp_path,
                dev_ephemeral_keys=False,
                log_key_file=log_key,
                audit_key_file=audit_key,
                fabric_url=FABRIC,
                agent_jwks_url=None,
                archive_backend="s3",
                archive_bucket="bucket",
                audit_log_path=tmp_path / "audit.jsonl",
                access_policy_file=Path("policies/provenance-access.yaml"),
                export_policy_file=Path("policies/evidence-export.yaml"),
            )
        )
        s3 = boto3.client(
            "s3", region_name="us-east-1", aws_access_key_id="t", aws_secret_access_key="t"
        )
        container = await build_container(
            settings, s3_client=s3, auditor_resolver=StaticJwks(auditor_idp.jwks())
        )
        try:
            assert isinstance(container.service._authorizer, FabricAuthorizer)
            assert isinstance(container.service._archive, S3ObjectLockArchive)
            head = await container.service.latest_tree_head()
            assert head.tree_size == 0
        finally:
            await container.aclose()

    async def test_wrong_key_type_is_rejected(self, tmp_path: Path) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        from agent_action_provenance.security.keys import load_private_key, load_public_key

        pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        path = tmp_path / "ec.pem"
        path.write_bytes(pem)
        with pytest.raises(ValueError, match="not an Ed25519"):
            load_private_key(path)
        pub = (
            ec.generate_private_key(ec.SECP256R1())
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        with pytest.raises(ValueError, match="not Ed25519"):
            load_public_key(pub)


async def test_fabric_mode_end_to_end(
    tmp_path: Path, auditor_idp: FakeIdp, agent_idp: FakeIdp
) -> None:
    """Recording authorized by the identity fabric over HTTP (MockTransport)."""

    def authorize(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["action"] == "provenance:record:write"
        assert body["resource_attributes"]["own_action"] is True
        return httpx.Response(200, json=DECISION)

    transport = fabric_transport(
        {
            "/oauth2/introspect": httpx.Response(
                200, json={"active": True, "sub": AGENT, "scope": "provenance:record:write"}
            ),
            "/v1/authorize": authorize,
        }
    )
    settings = Settings(
        **TestSettings().base(
            tmp_path,
            fabric_url=FABRIC,
            agent_jwks_url=None,
            audit_log_path=tmp_path / "a.jsonl",
            archive_dir=tmp_path / "archive",
            export_policy_file=Path("policies/evidence-export.yaml"),
        )
    )
    http = httpx.AsyncClient(transport=transport)
    container = await build_container(
        settings, http=http, auditor_resolver=StaticJwks(auditor_idp.jwks())
    )
    try:
        receipt = await container.service.record(
            agent_token(agent_idp), submission(datetime.now(UTC))
        )
        assert receipt.leaf_index == 0
    finally:
        await container.aclose()
