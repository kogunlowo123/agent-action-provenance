"""Record model validation, PROV documents, governance checks, signing and bundle verification."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from agentic_core.domain.classification import DataClassification, Decision, RiskLevel, TrustLevel
from agentic_core.domain.provenance import canonical_json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from agent_action_provenance.domain import governance, merkle, prov
from agent_action_provenance.domain.log import InclusionProof, verify_tree_head
from agent_action_provenance.domain.models import (
    ActionStatus,
    ApprovalRecord,
    EvidenceItem,
    EvidenceKind,
    OutputArtifact,
    ProvenanceRecord,
)
from agent_action_provenance.domain.verification import (
    BundleEntry,
    EvidenceBundle,
    verify_bundle,
    verify_consistency_proof,
    verify_inclusion_proof,
    verify_record_semantics,
)
from agent_action_provenance.security.keys import load_private_key, private_pem, public_pem
from agent_action_provenance.security.signing import TreeHeadSigner
from tests.conftest import AGENT, authorization, digest, submission

NOW = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)


def codes(**kw: Any) -> list[str]:
    return [f.code for f in governance.assess(submission(NOW, **kw)).findings]


def sealed(record_id: str = "r1", **kw: Any) -> ProvenanceRecord:
    s = submission(NOW, **kw)
    return ProvenanceRecord(
        record_id=record_id,
        recorded_at=NOW,
        recorded_by=AGENT,
        submission=s,
        submission_digest=s.digest(),
        prov=prov.build_document(record_id, s, recorded_by=AGENT, recorded_at=NOW),
        governance=governance.assess(s),
    )


class TestSubmissionValidation:
    def test_valid_submission(self) -> None:
        s = submission(NOW)
        assert s.max_classification is DataClassification.RESTRICTED
        assert s.digest().startswith("sha256:")
        assert s.digest() == submission(NOW).digest()

    @pytest.mark.parametrize(
        ("change", "message"),
        [
            ({"agent_id": "agent-without-spiffe"}, "spiffe"),
            ({"action_id": "short"}, "action_id"),
        ],
    )
    def test_rejects_bad_identifiers(self, change: dict[str, Any], message: str) -> None:
        data = submission(NOW).model_dump(mode="json") | change
        with pytest.raises(ValidationError, match=message):
            type(submission(NOW)).model_validate(data)

    def test_rejects_bad_digest_and_unknown_fields(self) -> None:
        data = submission(NOW).model_dump(mode="json")
        data["evidence"][0]["digest"] = "md5:abc"
        with pytest.raises(ValidationError, match="digest"):
            type(submission(NOW)).model_validate(data)
        data = submission(NOW).model_dump(mode="json") | {"injected": True}
        with pytest.raises(ValidationError, match="injected"):
            type(submission(NOW)).model_validate(data)

    def test_rejects_inverted_interval(self) -> None:
        data = submission(NOW).model_dump(mode="json")
        data["action"]["ended_at"] = (NOW - timedelta(hours=1)).isoformat()
        with pytest.raises(ValidationError, match="precedes"):
            type(submission(NOW)).model_validate(data)

    def test_rejects_duplicate_and_overlapping_artifacts(self) -> None:
        item = submission(NOW).evidence[0]
        with pytest.raises(ValidationError, match="evidence digests"):
            submission(NOW, evidence=(item, item))
        out = OutputArtifact(uri="x", digest=item.digest, classification=DataClassification.PUBLIC)
        with pytest.raises(ValidationError, match="both evidence and output"):
            submission(NOW, outputs=(out,))
        other = OutputArtifact(
            uri="y", digest=digest("y"), classification=DataClassification.PUBLIC
        )
        with pytest.raises(ValidationError, match="output digests"):
            submission(NOW, outputs=(other, other))

    def test_record_leaf_bytes_are_canonical(self) -> None:
        record = sealed()
        assert record.leaf_bytes() == canonical_json(record.model_dump(mode="json"))
        reparsed = ProvenanceRecord.model_validate_json(record.leaf_bytes())
        assert reparsed.leaf_bytes() == record.leaf_bytes()


class TestProvDocument:
    def test_maps_decision_evidence_authorization_and_outputs(self) -> None:
        doc = sealed().prov
        assert prov.validate_document(doc) == []
        agents = {a["aap:uri"]: a["prov:type"] for a in doc["agent"].values()}
        assert agents[AGENT] == "prov:SoftwareAgent"
        assert agents["nurse.jones@hospital.test"] == "prov:Person"
        assert {a["prov:type"] for a in doc["activity"].values()} == {
            "aap:Decision",
            "aap:Authorization",
            "aap:AgentAction",
            "aap:ProvenanceRecording",
        }
        plans = [e for e in doc["entity"].values() if e.get("prov:type") == "prov:Plan"]
        assert plans[0]["aap:policyName"] == "agent-authorization"
        associations = list(doc["wasAssociatedWith"].values())
        assert any("prov:plan" in a for a in associations)
        assert len(doc["actedOnBehalfOf"]) == 1

    def test_deterministic(self) -> None:
        assert canonical_json(sealed().prov) == canonical_json(sealed().prov)

    def test_approver_and_external_parents(self) -> None:
        approval = ApprovalRecord(
            approver="dr.smith@hospital.test",
            approved_at=NOW - timedelta(seconds=12),
            reference="CHG-1042",
        )
        external = digest("prior-report")
        outputs = (
            OutputArtifact(
                uri="out",
                digest=digest("out"),
                classification=DataClassification.RESTRICTED,
                derived_from=(external,),
            ),
        )
        evidence = (
            EvidenceItem(
                uri="e",
                digest=digest("e"),
                kind=EvidenceKind.TOOL_OUTPUT,
                trust=TrustLevel.VERIFIED,
                classification=DataClassification.INTERNAL,
                retrieved_at=NOW,
                derived_from=(external,),
            ),
        )
        s = submission(
            NOW,
            auth=authorization(NOW, decision=Decision.REQUIRE_APPROVAL, approval=approval),
            outputs=outputs,
            evidence=evidence,
            on_behalf_of=(
                "spiffe://agents.corp.test/agent/clinical/orchestrator",
                "service:care-portal",
            ),
        )
        doc = prov.build_document("r2", s, recorded_by=AGENT, recorded_at=NOW)
        assert prov.validate_document(doc) == []
        external_entity = doc["entity"][prov.entity_id(external)]
        assert external_entity["prov:type"] == "aap:ExternalEntity"
        types = {a["aap:uri"]: a["prov:type"] for a in doc["agent"].values()}
        assert types["dr.smith@hospital.test"] == "prov:Person"
        assert types["service:care-portal"] == "prov:SoftwareAgent"
        assert len(doc["actedOnBehalfOf"]) == 2

    def test_without_authorization_or_model(self) -> None:
        s = submission(NOW, auth=False, on_behalf_of=())
        data = s.model_dump(mode="json")
        data["decision"]["model"] = None
        data["action"]["tool"] = None
        bare = type(s).model_validate(data)
        doc = prov.build_document("r3", bare, recorded_by=AGENT, recorded_at=NOW)
        assert prov.validate_document(doc) == []
        assert "actedOnBehalfOf" not in doc

    def test_detects_constraint_violations(self) -> None:
        doc = sealed().prov
        assert prov.validate_document({"entity": {}}) == [
            "missing activity section",
            "missing agent section",
        ]
        broken = {**doc, "used": {"_:x": {"prov:activity": "aap:nope", "prov:entity": "aap:none"}}}
        assert any("not a declared activity" in p for p in prov.validate_document(broken))
        bad_plan = {
            **doc,
            "wasAssociatedWith": {
                "_:p": {
                    "prov:activity": next(iter(doc["activity"])),
                    "prov:agent": next(iter(doc["agent"])),
                    "prov:plan": "aap:ghost",
                }
            },
        }
        assert any("prov:plan" in p for p in prov.validate_document(bad_plan))
        entity = next(iter(doc["entity"]))
        acts = list(doc["activity"])
        twice = {
            **doc,
            "wasGeneratedBy": {
                "_:a": {"prov:entity": entity, "prov:activity": acts[0]},
                "_:b": {"prov:entity": entity, "prov:activity": acts[1]},
            },
        }
        assert any("more than one activity" in p for p in prov.validate_document(twice))
        e1, e2 = list(doc["entity"])[:2]
        cyclic = {
            **doc,
            "wasDerivedFrom": {
                "_:1": {"prov:generatedEntity": e1, "prov:usedEntity": e2},
                "_:2": {"prov:generatedEntity": e2, "prov:usedEntity": e1},
            },
        }
        assert any("cycle" in p for p in prov.validate_document(cyclic))
        times = {
            **doc,
            "activity": {
                **doc["activity"],
                "aap:t": {
                    "prov:startTime": NOW.isoformat(),
                    "prov:endTime": (NOW - timedelta(1)).isoformat(),
                },
                "aap:u": {"prov:startTime": "yesterday", "prov:endTime": "today"},
                "aap:v": "not-an-object",
            },
        }
        problems = prov.validate_document(times)
        assert any("ends before" in p for p in problems)
        assert any("invalid time" in p for p in problems)
        assert any("must be an object" in p for p in problems)
        shapes = {**doc, "used": ["list"], "wasGeneratedBy": {"_:z": "string"}}
        problems = prov.validate_document(shapes)
        assert "used must be an object" in problems
        assert "wasGeneratedBy _:z must be an object" in problems


class TestGovernance:
    def test_compliant_action(self) -> None:
        assert codes() == []

    def test_missing_and_denied_authorization(self) -> None:
        assert codes(auth=False) == ["authorization_missing"]
        assert codes(auth=False, status=ActionStatus.BLOCKED) == []
        assert codes(auth=authorization(NOW, decision=Decision.DENY)) == ["executed_despite_deny"]

    def test_approval_rules(self) -> None:
        held = authorization(NOW, decision=Decision.REQUIRE_APPROVAL)
        assert codes(auth=held) == ["approval_missing"]
        assert codes(auth=held, status=ActionStatus.PENDING_APPROVAL) == []
        late = ApprovalRecord(
            approver="dr.smith@hospital.test",
            approved_at=NOW + timedelta(minutes=2),
            reference="CHG-1",
        )
        assert codes(
            auth=authorization(NOW, decision=Decision.REQUIRE_APPROVAL, approval=late)
        ) == ["approval_after_execution"]
        selfish = ApprovalRecord(
            approver=AGENT, approved_at=NOW - timedelta(seconds=30), reference="CHG-2"
        )
        assert codes(auth=authorization(NOW, approval=selfish)) == ["self_approval"]
        principal = ApprovalRecord(
            approver="nurse.jones@hospital.test",
            approved_at=NOW - timedelta(seconds=30),
            reference="CHG-3",
        )
        assert codes(auth=authorization(NOW, approval=principal)) == ["self_approval"]

    def test_timing_and_blocked(self) -> None:
        assert codes(auth=authorization(NOW, decided_offset=60)) == [
            "authorization_after_execution"
        ]
        assert codes(status=ActionStatus.BLOCKED) == ["blocked_despite_allow"]
        late = (
            EvidenceItem(
                uri="e",
                digest=digest("late"),
                kind=EvidenceKind.DOCUMENT,
                trust=TrustLevel.VERIFIED,
                classification=DataClassification.INTERNAL,
                retrieved_at=NOW + timedelta(minutes=5),
            ),
        )
        assert codes(evidence=late, outputs=()) == ["evidence_after_action"]

    def test_high_risk_evidence_quality(self) -> None:
        assert codes(risk=RiskLevel.HIGH, evidence=(), outputs=()) == ["high_risk_without_evidence"]
        external = (
            EvidenceItem(
                uri="https://web",
                digest=digest("web"),
                kind=EvidenceKind.RETRIEVAL,
                trust=TrustLevel.EXTERNAL,
                classification=DataClassification.PUBLIC,
                retrieved_at=NOW,
            ),
        )
        assert codes(risk=RiskLevel.CRITICAL, evidence=external, outputs=()) == [
            "high_risk_on_untrusted_evidence"
        ]

    def test_classification_downgrade(self) -> None:
        evidence = submission(NOW).evidence
        leaked = (
            OutputArtifact(
                uri="email",
                digest=digest("email"),
                classification=DataClassification.INTERNAL,
                derived_from=(evidence[0].digest,),
            ),
        )
        assessment = governance.assess(submission(NOW, outputs=leaked))
        assert not assessment.compliant
        assert [f.code for f in assessment.findings] == ["classification_downgrade"]


class TestSigningAndVerification:
    def test_tree_head_signature(self) -> None:
        signer = TreeHeadSigner(Ed25519PrivateKey.generate())
        head = signer.sign(tree_size=3, root_hash=b"\x01" * 32, timestamp_ms=1)
        assert verify_tree_head(head, signer.public_key)
        assert signer.describe().log_id == head.log_id
        for change in (
            {"tree_size": 4},
            {"root_hash": "02" * 32},
            {"timestamp": 2},
            {"version": "other"},
            {"signature": "!!!"},
            {"signature": base64.b64encode(b"x" * 64).decode()},
        ):
            assert not verify_tree_head(head.model_copy(update=change), signer.public_key)
        assert not verify_tree_head(head, Ed25519PrivateKey.generate().public_key())

    def test_key_round_trip(self, tmp_path: Any) -> None:
        key = Ed25519PrivateKey.generate()
        path = tmp_path / "log.pem"
        path.write_bytes(private_pem(key))
        assert public_pem(load_private_key(path).public_key()) == public_pem(key.public_key())

    def _bundle(self, n: int = 3) -> tuple[EvidenceBundle, TreeHeadSigner]:
        signer = TreeHeadSigner(Ed25519PrivateKey.generate())
        records = [sealed(f"r{i}", action_id=f"act-{i:08d}") for i in range(n)]
        tree = merkle.MerkleTree()
        for r in records:
            tree.append(r.leaf_bytes())
        head = signer.sign(tree_size=n, root_hash=tree.root(), timestamp_ms=5)
        entries = tuple(
            BundleEntry(
                leaf_index=i,
                record=r.model_dump(mode="json"),
                inclusion_proof=InclusionProof(
                    leaf_index=i,
                    tree_size=n,
                    leaf_hash=merkle.leaf_hash(r.leaf_bytes()).hex(),
                    audit_path=tuple(p.hex() for p in tree.inclusion_proof(i)),
                ),
            )
            for i, r in enumerate(records)
        )
        bundle = EvidenceBundle(
            export_id="e1",
            generated_at=NOW,
            criteria={},
            log=signer.describe(),
            tree_head=head,
            entries=entries,
        )
        return bundle, signer

    def test_valid_bundle(self) -> None:
        bundle, signer = self._bundle()
        result = verify_bundle(bundle, signer.public_key)
        assert result.valid
        assert len(result.entries) == 3

    def test_bundle_tampering_is_detected(self) -> None:
        bundle, signer = self._bundle()
        key = signer.public_key
        entry = bundle.entries[1]

        def with_entry(**update: Any) -> EvidenceBundle:
            return bundle.model_copy(
                update={
                    "entries": (
                        bundle.entries[0],
                        entry.model_copy(update=update),
                        bundle.entries[2],
                    )
                }
            )

        edited = dict(entry.record)
        edited["recorded_by"] = "spiffe://agents.corp.test/agent/other/x"
        assert not verify_bundle(with_entry(record=edited), key).valid
        bad_path = entry.inclusion_proof.model_copy(update={"audit_path": ("zz",)})
        assert not verify_bundle(with_entry(inclusion_proof=bad_path), key).valid
        assert not verify_bundle(with_entry(leaf_index=0), key).valid
        assert not verify_bundle(with_entry(record={"record_id": 5}), key).valid
        assert not verify_bundle(bundle.model_copy(update={"format": "v0"}), key).valid
        other = TreeHeadSigner(Ed25519PrivateKey.generate())
        result = verify_bundle(bundle, other.public_key)
        assert not result.valid
        assert len(result.problems) == 2
        forged = bundle.model_copy(
            update={"tree_head": bundle.tree_head.model_copy(update={"root_hash": "00" * 32})}
        )
        assert not verify_bundle(forged, key).valid

    def test_semantic_tampering_with_consistent_hashes(self) -> None:
        """A record whose stored PROV/governance was edited is caught even before hashing."""
        record = sealed()
        doc = dict(record.prov)
        doc["agent"] = {**doc["agent"], "aap:agent-extra": {"prov:type": "prov:Person"}}
        problems = verify_record_semantics(record.model_copy(update={"prov": doc}))
        assert "PROV document is not derived from the submission" in problems
        quiet = record.model_copy(
            update={"governance": governance.assess(submission(NOW, auth=False))}
        )
        assert "governance assessment does not match the submission" in verify_record_semantics(
            quiet
        )
        wrong = record.model_copy(update={"submission_digest": "sha256:" + "0" * 64})
        assert "submission digest mismatch" in verify_record_semantics(wrong)

    def test_proof_helpers(self) -> None:
        bundle, _ = self._bundle(4)
        head = bundle.tree_head
        proof = bundle.entries[0].inclusion_proof
        assert verify_inclusion_proof(proof.model_copy(update={"tree_size": 3}), None, head)
        from agent_action_provenance.domain.log import ConsistencyProof

        bad = ConsistencyProof(first=1, second=4, proof=("zz",))
        older = head.model_copy(update={"tree_size": 1})
        assert verify_consistency_proof(bad, older, head) == ["consistency proof is not hex"]
        assert verify_consistency_proof(bad, head, head) == [
            "proof sizes do not match the tree heads"
        ]
