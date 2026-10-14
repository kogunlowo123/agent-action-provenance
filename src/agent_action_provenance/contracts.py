"""Export published contracts: JSON Schemas for inputs/outputs and the OpenAPI document.

python -m agent_action_provenance.contracts            # rewrite schemas/ and docs/api/
python -m agent_action_provenance.contracts --check    # exit 1 if committed files are stale
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from agent_action_provenance.api.app import create_app
from agent_action_provenance.application.views import (
    ExportView,
    LineageGraph,
    RecordReceipt,
    VerificationReport,
)
from agent_action_provenance.domain.exports import ExportCriteria
from agent_action_provenance.domain.log import ConsistencyProof, InclusionProof, SignedTreeHead
from agent_action_provenance.domain.models import ActionSubmission, ProvenanceRecord
from agent_action_provenance.domain.verification import BundleVerification, EvidenceBundle

MODELS: dict[str, type[BaseModel]] = {
    "action-submission.request": ActionSubmission,
    "record-receipt.response": RecordReceipt,
    "provenance-record": ProvenanceRecord,
    "signed-tree-head": SignedTreeHead,
    "inclusion-proof": InclusionProof,
    "consistency-proof": ConsistencyProof,
    "export-criteria.request": ExportCriteria,
    "export.response": ExportView,
    "evidence-bundle": EvidenceBundle,
    "bundle-verification": BundleVerification,
    "verification-report.response": VerificationReport,
    "lineage-graph.response": LineageGraph,
}


async def _no_container() -> Any:  # pragma: no cover - never started
    raise RuntimeError("contract export does not start the application")


def documents() -> dict[str, dict[str, Any]]:
    docs: dict[str, dict[str, Any]] = {
        f"schemas/{name}.schema.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": (
                "https://github.com/kogunlowo123/agent-action-provenance/"
                f"schemas/{name}.schema.json"
            ),
            **model.model_json_schema(mode="validation"),
        }
        for name, model in MODELS.items()
    }
    app: FastAPI = create_app(_no_container)
    docs["docs/api/openapi.json"] = app.openapi()
    return docs


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None, root: Path | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    base = root or Path.cwd()
    stale: list[str] = []
    for relative, document in documents().items():
        path = base / relative
        content = render(document)
        if "--check" in args:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(relative)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    if stale:
        sys.stderr.write(
            "stale contracts (run python -m agent_action_provenance.contracts): "
            + ", ".join(stale)
            + "\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
