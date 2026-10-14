"""Load profile for a deployed provenance engine.

Run against a staging deployment, never production:

    PROVENANCE_LOAD_AGENT_TOKEN=<agent credential with provenance:record:write> \
    PROVENANCE_LOAD_AGENT_ID=<the credential's SPIFFE ID> \
    locust -f tests/performance/locustfile.py --host "$PROVENANCE_STAGING_URL" \
           --users 200 --spawn-rate 20 --run-time 10m --headless

Agents record far more often than monitors fetch proofs, so the mix weights
record submission over tree-head and proof reads.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta

from locust import HttpUser, between, task

TOKEN = os.environ.get("PROVENANCE_LOAD_AGENT_TOKEN", "")
AGENT_ID = os.environ.get("PROVENANCE_LOAD_AGENT_ID", "")


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _submission() -> dict[str, object]:
    now = datetime.now(UTC)
    action_id = f"load-{uuid.uuid4().hex}"
    evidence = {
        "uri": f"load://evidence/{action_id}",
        "digest": _digest(action_id + "-in"),
        "kind": "retrieval",
        "trust": 2,
        "classification": 1,
        "retrieved_at": (now - timedelta(seconds=2)).isoformat(),
    }
    return {
        "action_id": action_id,
        "agent_id": AGENT_ID,
        "action": {
            "name": "load:write:test",
            "target": "load://target",
            "risk": 1,
            "status": "executed",
            "started_at": (now - timedelta(seconds=1)).isoformat(),
            "ended_at": now.isoformat(),
        },
        "decision": {"summary": "load test action"},
        "evidence": [evidence],
        "outputs": [
            {
                "uri": f"load://output/{action_id}",
                "digest": _digest(action_id + "-out"),
                "classification": 1,
                "derived_from": [evidence["digest"]],
            }
        ],
    }


class AgentTraffic(HttpUser):
    wait_time = between(0.05, 0.25)

    @task(10)
    def record(self) -> None:
        self.client.post(
            "/v1/records",
            json=_submission(),
            headers={"Authorization": f"Bearer {TOKEN}"},
            name="/v1/records",
        )

    @task(3)
    def tree_head(self) -> None:
        self.client.get("/v1/log/tree-head", name="/v1/log/tree-head")

    @task(2)
    def inclusion(self) -> None:
        self.client.get(
            "/v1/log/proof/inclusion", params={"leaf_index": 0}, name="/v1/log/proof/inclusion"
        )
