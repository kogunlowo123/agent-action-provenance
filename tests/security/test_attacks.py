"""Adversarial tests mapped to docs/security/threat-model.md (T-numbers)."""

from __future__ import annotations

import base64
import json
import time

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, update

from agent_action_provenance.application.service import ProvenanceService
from agent_action_provenance.domain.log import SignedTreeHead
from agent_action_provenance.infrastructure.database import log_state, nodes, records, tree_heads
from agent_action_provenance.runtime.container import Container
from tests.conftest import (
    AGENT,
    AGENT_AUDIENCE,
    AGENT_ISSUER,
    FakeClock,
    FakeIdp,
    agent_token,
    auditor_headers,
    submission,
)

pytestmark = pytest.mark.security


async def seed(service: ProvenanceService, idp: FakeIdp, clock: FakeClock, n: int) -> list[str]:
    token = agent_token(idp)
    return [
        (await service.record(token, submission(clock.now(), f"act-sec{i:05d}"))).record_id
        for i in range(n)
    ]


class TestTamperEvidence:
    async def test_t1_edited_record_is_detected(
        self, container: Container, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        service = container.service
        ids = await seed(service, agent_idp, clock, 3)
        assert (await service.check_integrity()).ok
        stored = await service.ledger.get(ids[-1])
        assert stored is not None
        forged = json.loads(stored.leaf_bytes)
        forged["submission"]["action"]["status"] = "blocked"
        async with container.engine.begin() as conn:
            await conn.execute(
                update(records)
                .where(records.c.record_id == ids[-1])
                .values(document=json.dumps(forged, sort_keys=True, separators=(",", ":")))
            )
        report = await service.verify_record(ids[-1])
        assert not report.valid
        assert "leaf hash does not match record content" in report.problems
        integrity = await service.check_integrity()
        assert not integrity.ok
        assert any("does not match its leaf hash" in p for p in integrity.problems)
        assert container.metrics.integrity_checks.labels("failed")._value.get() == 1

    async def test_t2_rewritten_tree_node_is_detected(
        self, container: Container, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        await seed(container.service, agent_idp, clock, 4)
        async with container.engine.begin() as conn:
            await conn.execute(
                update(nodes)
                .where(nodes.c.level == 2)
                .where(nodes.c.idx == 0)
                .values(hash="ab" * 32)
            )
        report = await container.service.check_integrity()
        assert "stored tree does not reproduce the signed root" in report.problems

    async def test_t3_forged_tree_head_is_detected(
        self, container: Container, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        await seed(container.service, agent_idp, clock, 2)
        head = await container.service.latest_tree_head()
        forged = head.model_copy(update={"root_hash": "cd" * 32})
        async with container.engine.begin() as conn:
            await conn.execute(
                update(tree_heads)
                .where(tree_heads.c.tree_size == head.tree_size)
                .values(document=forged.model_dump_json())
            )
        report = await container.service.check_integrity()
        assert "latest tree head signature is invalid" in report.problems

    async def test_t4_rollback_is_detected(
        self, container: Container, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        service = container.service
        await seed(service, agent_idp, clock, 3)
        assert (await service.check_integrity()).ok
        token = agent_token(agent_idp)
        await service.record(token, submission(clock.now(), "act-rollback1"))
        assert (await service.check_integrity()).ok
        latest = await service.latest_tree_head()
        async with container.engine.begin() as conn:
            await conn.execute(delete(tree_heads).where(tree_heads.c.tree_size == latest.tree_size))
            await conn.execute(update(log_state).values(tree_size=latest.tree_size - 1))
        report = await service.check_integrity()
        assert not report.ok
        assert "rollback" in report.problems[0]

    async def test_t5_audit_chain_carries_no_credentials(
        self, container: Container, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        token = agent_token(agent_idp)
        await container.service.record(token, submission(clock.now()))
        text = container.settings.audit_log_path.read_text()
        assert token not in text
        assert token.split(".")[2] not in text


class TestCredentialAttacks:
    def _post(self, client: TestClient, clock: FakeClock, token: str) -> int:
        body = submission(clock.now()).model_dump(mode="json")
        return client.post(
            "/v1/records", json=body, headers={"Authorization": f"Bearer {token}"}
        ).status_code

    def test_t6_alg_none_and_garbage(self, client: TestClient, clock: FakeClock) -> None:
        unsigned = jwt.encode(
            {
                "sub": AGENT,
                "aud": AGENT_AUDIENCE,
                "iss": AGENT_ISSUER,
                "exp": int(time.time()) + 60,
                "iat": int(time.time()),
            },
            key=None,
            algorithm="none",
        )
        assert self._post(client, clock, unsigned) == 401
        assert self._post(client, clock, "not.a.token") == 401
        body = submission(clock.now()).model_dump(mode="json")
        assert client.post("/v1/records", json=body).status_code == 401
        assert (
            client.post("/v1/records", json=body, headers={"Authorization": "Bearer "}).status_code
            == 401
        )

    def test_t7_foreign_issuer_audience_and_expiry(
        self, client: TestClient, agent_idp: FakeIdp, auditor_idp: FakeIdp, clock: FakeClock
    ) -> None:
        impostor = FakeIdp(AGENT_ISSUER, kid=agent_idp.kid)  # same kid, different key
        assert self._post(client, clock, agent_token(impostor)) == 401
        wrong_aud = agent_idp.mint(sub=AGENT, aud="another-api", scope="provenance:record:write")
        assert self._post(client, clock, wrong_aud) == 401
        expired = agent_idp.mint(
            sub=AGENT, aud=AGENT_AUDIENCE, ttl=-120, scope="provenance:record:write"
        )
        assert self._post(client, clock, expired) == 401
        human = auditor_headers(auditor_idp, "provenance-auditor")["Authorization"][7:]
        assert self._post(client, clock, human) == 401

    def test_t8_payload_tampering(
        self, client: TestClient, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        token = agent_token(agent_idp, scope="fhir:read:*")
        head, payload, sig = token.split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
        claims["scope"] = "provenance:record:write"
        forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        assert self._post(client, clock, f"{head}.{forged}.{sig}") == 401

    def test_t9_agent_cannot_impersonate_or_read_as_auditor(
        self, client: TestClient, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        other = agent_token(agent_idp, "spiffe://agents.corp.test/agent/clinical/other")
        assert self._post(client, clock, other) == 403
        token = agent_token(agent_idp)
        assert (
            client.get("/v1/records", headers={"Authorization": f"Bearer {token}"}).status_code
            == 401
        )

    def test_t10_export_requires_role_and_second_person(
        self, client: TestClient, agent_idp: FakeIdp, auditor_idp: FakeIdp, clock: FakeClock
    ) -> None:
        body = submission(clock.now()).model_dump(mode="json")
        client.post(
            "/v1/records", json=body, headers={"Authorization": f"Bearer {agent_token(agent_idp)}"}
        )
        nobody = auditor_headers(auditor_idp, "viewer")
        denied = client.post(
            "/v1/exports", json={"agent_id": AGENT, "purpose": "curiosity"}, headers=nobody
        )
        assert denied.status_code == 403
        both = auditor_headers(auditor_idp, "provenance-auditor", "provenance-approver")
        export = client.post(
            "/v1/exports", json={"agent_id": AGENT, "purpose": "self review"}, headers=both
        ).json()
        assert export["status"] == "pending_approval"
        own = client.post(f"/v1/exports/{export['export_id']}/approve", headers=both)
        assert own.status_code == 403


class TestInputHardening:
    def test_t11_oversized_and_unknown_fields_rejected(
        self, client: TestClient, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        headers = {"Authorization": f"Bearer {agent_token(agent_idp)}"}
        body = submission(clock.now()).model_dump(mode="json")
        body["evidence"] = [
            dict(body["evidence"][0], digest="sha256:" + f"{i:064x}") for i in range(257)
        ]
        assert client.post("/v1/records", json=body, headers=headers).status_code == 422
        extra = submission(clock.now()).model_dump(mode="json") | {"admin": True}
        assert client.post("/v1/records", json=extra, headers=headers).status_code == 422
        assert client.get("/v1/log/entries", params={"start": 0, "end": 5000}).status_code == 422
        assert client.get("/v1/lineage/not-a-digest").status_code in (401, 422)

    def test_t12_mcp_rejects_dns_rebinding(self, client: TestClient) -> None:
        response = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"accept": "application/json, text/event-stream", "host": "attacker.test"},
        )
        assert response.status_code in (400, 403, 421)

    def test_t13_public_log_reveals_hashes_only(
        self, client: TestClient, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        body = submission(clock.now()).model_dump(mode="json")
        client.post(
            "/v1/records", json=body, headers={"Authorization": f"Bearer {agent_token(agent_idp)}"}
        )
        entry = client.get("/v1/log/entries", params={"start": 0, "end": 1}).json()["entries"][0]
        assert set(entry) == {"leaf_index", "leaf_hash", "record_id"}
        head = SignedTreeHead.model_validate(client.get("/v1/log/tree-head").json())
        assert head.tree_size == 1
