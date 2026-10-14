"""Full lifecycle over HTTP: agents record, monitors verify, auditors export and verify offline."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient

from agent_action_provenance import cli
from agent_action_provenance.domain import merkle
from agent_action_provenance.domain.log import (
    ConsistencyProof,
    InclusionProof,
    SignedTreeHead,
    verify_tree_head,
)
from agent_action_provenance.domain.verification import verify_consistency_proof
from agent_action_provenance.security.keys import load_public_key
from tests.conftest import (
    AGENT,
    FakeClock,
    FakeIdp,
    agent_token,
    auditor_headers,
    submission,
)

pytestmark = pytest.mark.e2e

MCP_HEADERS = {"accept": "application/json, text/event-stream"}


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def post_record(
    client: TestClient, idp: FakeIdp, clock: FakeClock, action_id: str
) -> dict[str, Any]:
    body = submission(clock.now(), action_id).model_dump(mode="json")
    response = client.post("/v1/records", json=body, headers=bearer(agent_token(idp)))
    assert response.status_code == 201, response.text
    return dict(response.json())


def log_key(client: TestClient) -> Ed25519PublicKey:
    return load_public_key(client.get("/v1/log/public-key").json()["public_key_pem"].encode())


def test_agent_records_and_monitor_verifies(
    client: TestClient, agent_idp: FakeIdp, clock: FakeClock
) -> None:
    key = log_key(client)
    genesis = SignedTreeHead.model_validate(client.get("/v1/log/tree-head").json())
    assert genesis.tree_size == 0
    assert verify_tree_head(genesis, key)

    receipt = post_record(client, agent_idp, clock, "act-e2e00001")
    head = SignedTreeHead.model_validate(receipt["tree_head"])
    proof = InclusionProof.model_validate(receipt["inclusion_proof"])
    assert verify_tree_head(head, key)
    assert merkle.verify_inclusion(
        bytes.fromhex(proof.leaf_hash),
        proof.leaf_index,
        proof.tree_size,
        [bytes.fromhex(p) for p in proof.audit_path],
        bytes.fromhex(head.root_hash),
    )

    for i in range(2, 6):
        post_record(client, agent_idp, clock, f"act-e2e0000{i}")
    latest = SignedTreeHead.model_validate(client.get("/v1/log/tree-head").json())
    consistency = ConsistencyProof.model_validate(
        client.get(
            "/v1/log/proof/consistency",
            params={"first": head.tree_size, "second": latest.tree_size},
        ).json()
    )
    assert verify_consistency_proof(consistency, head, latest) == []
    again = client.get("/v1/log/proof/inclusion", params={"leaf_index": 0}).json()
    assert again["tree_size"] == latest.tree_size
    entries = client.get("/v1/log/entries", params={"start": 0, "end": 10}).json()["entries"]
    assert [e["leaf_index"] for e in entries] == list(range(latest.tree_size))
    assert client.get("/v1/log/tree-head", params={"tree_size": head.tree_size}).json() == (
        head.model_dump(mode="json")
    )

    metrics = client.get("/metrics").text
    assert 'provenance_records_total{compliant="true",status="executed"} 5.0' in metrics
    response = client.get("/healthz")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-correlation-id"]


def test_auditor_review_export_and_offline_verification(
    client: TestClient,
    agent_idp: FakeIdp,
    auditor_idp: FakeIdp,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    receipt = post_record(client, agent_idp, clock, "act-aud00001")
    auditor = auditor_headers(auditor_idp, "provenance-auditor", sub="alice@corp.test")
    approver = auditor_headers(auditor_idp, "provenance-approver", sub="bob@corp.test")

    page = client.get("/v1/records", params={"agent_id": AGENT}, headers=auditor).json()
    assert [r["record_id"] for r in page["items"]] == [receipt["record_id"]]
    one = client.get(f"/v1/records/{receipt['record_id']}", headers=auditor).json()
    assert one["record"]["submission"]["action"]["name"] == "fhir:write:task"
    report = client.get(f"/v1/records/{receipt['record_id']}/verification", headers=auditor).json()
    assert report["valid"] is True
    output = one["record"]["submission"]["outputs"][0]["digest"]
    lineage = client.get(f"/v1/lineage/{output}", headers=auditor).json()
    assert lineage["records"][0]["record_id"] == receipt["record_id"]

    created = client.post(
        "/v1/exports", json={"agent_id": AGENT, "purpose": "HIPAA review"}, headers=auditor
    )
    assert created.status_code == 201, created.text
    export = created.json()
    assert export["status"] == "pending_approval"  # RESTRICTED evidence needs a second person
    blocked = client.get(f"/v1/exports/{export['export_id']}/bundle", headers=auditor)
    assert blocked.status_code == 403
    assert blocked.json()["error"] == "approval_required"
    assert client.get(f"/v1/exports/{export['export_id']}", headers=approver).json()["status"] == (
        "pending_approval"
    )
    approved = client.post(f"/v1/exports/{export['export_id']}/approve", headers=approver)
    assert approved.json()["status"] == "ready"
    bundle = client.get(f"/v1/exports/{export['export_id']}/bundle", headers=auditor)
    assert bundle.status_code == 200

    (tmp_path / "bundle.json").write_text(bundle.text)
    (tmp_path / "log.pem").write_text(client.get("/v1/log/public-key").json()["public_key_pem"])
    out = io.StringIO()
    code = cli.main(
        ["bundle", str(tmp_path / "bundle.json"), "--public-key", str(tmp_path / "log.pem")],
        stdout=out,
    )
    assert code == 0
    assert json.loads(out.getvalue())["valid"] is True


def test_auditor_endpoints_require_roles(client: TestClient, auditor_idp: FakeIdp) -> None:
    assert client.get("/v1/records").status_code == 401
    assert client.get("/v1/records").headers["www-authenticate"] == "Bearer"
    wrong = auditor_headers(auditor_idp, "provenance-approver")
    assert client.get("/v1/records", headers=wrong).status_code == 403
    assert (
        client.post(
            "/v1/exports/x/approve", headers=auditor_headers(auditor_idp, "provenance-auditor")
        ).status_code
        == 403
    )
    missing = client.get(
        "/v1/records/nope", headers=auditor_headers(auditor_idp, "provenance-auditor")
    )
    assert missing.status_code == 404
    assert missing.json()["error"] == "not_found"
    invalid = client.post(
        "/v1/exports",
        json={"purpose": "x"},
        headers=auditor_headers(auditor_idp, "provenance-auditor"),
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"] == "invalid_request"


def mcp_call(client: TestClient, token: str | None, name: str, arguments: dict[str, Any]) -> Any:
    headers = dict(MCP_HEADERS)
    if token:
        headers["authorization"] = f"Bearer {token}"
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()["result"]


def test_mcp_tools(client: TestClient, agent_idp: FakeIdp, clock: FakeClock) -> None:
    listing = client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers=MCP_HEADERS
    ).json()["result"]["tools"]
    tools = {t["name"]: t for t in listing}
    assert set(tools) == {
        "record_action",
        "get_tree_head",
        "get_inclusion_proof",
        "get_consistency_proof",
        "verify_record",
        "trace_lineage",
    }
    assert all("outputSchema" in t and "inputSchema" in t for t in listing)

    token = agent_token(agent_idp)
    body = submission(clock.now(), "act-mcp00001").model_dump(mode="json")
    receipt = mcp_call(client, token, "record_action", {"submission": body})
    assert not receipt["isError"], receipt
    record_id = receipt["structuredContent"]["record_id"]
    head = mcp_call(client, token, "get_tree_head", {})["structuredContent"]
    assert head["tree_size"] == 1
    assert mcp_call(client, token, "get_tree_head", {"tree_size": 1})["structuredContent"] == head
    proof = mcp_call(client, token, "get_inclusion_proof", {"leaf_index": 0})["structuredContent"]
    assert proof["tree_size"] == 1
    consistency = mcp_call(client, token, "get_consistency_proof", {"first": 0, "second": 1})
    assert consistency["structuredContent"]["proof"] == []
    verified = mcp_call(client, token, "verify_record", {"record_id": record_id})
    assert verified["structuredContent"]["valid"] is True
    lineage = mcp_call(
        client, token, "trace_lineage", {"digest": body["outputs"][0]["digest"], "max_depth": 2}
    )
    assert lineage["structuredContent"]["records"][0]["record_id"] == record_id

    denied = mcp_call(client, None, "get_tree_head", {})
    assert denied["isError"]
    assert "bearer" in denied["content"][0]["text"]
    no_scope = mcp_call(client, agent_token(agent_idp, scope="fhir:read:*"), "get_tree_head", {})
    assert no_scope["isError"]
    assert "denied" in no_scope["content"][0]["text"]


def a2a(client: TestClient, token: str | None, payload: Any) -> Any:
    headers = bearer(token) if token else {}
    return client.post("/a2a", json=payload, headers=headers)


def message(skill: str, data: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "messageId": "m1",
                "kind": "message",
                "parts": [{"kind": "data", "data": {"skill": skill, "input": data}}],
            }
        },
    }


def test_a2a_agent_card_and_message_send(
    client: TestClient, agent_idp: FakeIdp, clock: FakeClock
) -> None:
    card = client.get("/.well-known/agent-card.json").json()
    assert card["url"] == "https://provenance.corp.test/a2a"
    assert {
        "name",
        "description",
        "url",
        "version",
        "capabilities",
        "skills",
        "securitySchemes",
    } <= set(card)
    token = agent_token(agent_idp)
    body = submission(clock.now(), "act-a2a00001").model_dump(mode="json")
    task = a2a(client, token, message("record-action", body)).json()["result"]
    assert task["status"]["state"] == "completed"
    receipt = task["artifacts"][0]["parts"][0]["data"]
    assert receipt["leaf_index"] == 0

    verified = a2a(client, token, message("verify-record", {"record_id": receipt["record_id"]}))
    assert verified.json()["result"]["artifacts"][0]["parts"][0]["data"]["valid"] is True
    inc = a2a(client, token, message("inclusion-proof", {"leaf_index": 0})).json()["result"]
    assert inc["artifacts"][0]["parts"][0]["data"]["tree_size"] == 1
    con = a2a(client, token, message("consistency-proof", {"first": 1, "second": 1})).json()
    assert con["result"]["status"]["state"] == "completed"

    assert a2a(client, None, message("verify-record", {})).status_code == 401
    rejected = a2a(
        client, agent_token(agent_idp, scope="none"), message("inclusion-proof", {"leaf_index": 0})
    )
    assert rejected.json()["result"]["status"]["state"] == "rejected"
    failed = a2a(client, token, message("verify-record", {"record_id": "missing"}))
    assert failed.json()["result"]["status"]["state"] == "failed"
    invalid = a2a(client, token, message("inclusion-proof", {"leaf_index": "x"})).json()
    assert invalid["error"]["code"] == -32602
    unknown = a2a(client, token, message("delete-everything", {})).json()
    assert unknown["error"]["code"] == -32602
    method = a2a(client, token, {"jsonrpc": "2.0", "id": 2, "method": "tasks/get"}).json()
    assert method["error"]["code"] == -32601
    assert a2a(client, token, {"id": 3}).json()["error"]["code"] == -32600
    assert a2a(client, token, [1, 2]).json()["error"]["code"] == -32600
    no_message = a2a(
        client, token, {"jsonrpc": "2.0", "id": 4, "method": "message/send", "params": {}}
    ).json()
    assert no_message["error"]["code"] == -32602
    raw = client.post(
        "/a2a", content=b"{not json", headers={**bearer(token), "content-type": "application/json"}
    )
    assert raw.json()["error"]["code"] == -32700
    text_only = message("verify-record", {})
    text_only["params"]["message"]["parts"] = [{"kind": "text", "text": "hi"}]
    assert a2a(client, token, text_only).json()["error"]["code"] == -32602
    via_metadata = message("verify-record", {"record_id": receipt["record_id"]})
    part = via_metadata["params"]["message"]["parts"][0]["data"]
    part.pop("skill")
    via_metadata["params"]["message"]["metadata"] = {"skill": "verify-record"}
    assert a2a(client, token, via_metadata).json()["result"]["status"]["state"] == "completed"
