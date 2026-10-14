"""Provenance engine use cases.

Decision -> Evidence -> Authorization -> Audit Record: an agent submits what
it decided, the evidence it relied on and the authorization it acted under;
the engine derives a W3C PROV document, runs governance checks, seals the
record into the Merkle transparency log (group commit, signed tree head),
writes a signed agentic-core audit event and returns an inclusion proof.

Every state change and every authorization decision is in the audit chain;
an audit write failure fails the request.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from agentic_core.audit import AuditLog
from agentic_core.domain.classification import DataClassification, Decision
from agentic_core.domain.identifiers import new_id
from agentic_core.domain.provenance import canonical_json
from agentic_core.observability import correlation_id, get_logger
from agentic_core.policy import PolicyEngine, PolicyRequest, Resource, Subject

from agent_action_provenance.application.sequencer import BatchSequencer
from agent_action_provenance.application.views import (
    ExportView,
    IntegrityReport,
    LineageEdge,
    LineageGraph,
    LineageRecord,
    RecordReceipt,
    RecordView,
    VerificationReport,
)
from agent_action_provenance.domain import governance, merkle, prov
from agent_action_provenance.domain.errors import (
    ApprovalRequiredError,
    ConflictError,
    ForbiddenError,
    InvalidRecordError,
    LogIntegrityError,
    NotFoundError,
)
from agent_action_provenance.domain.exports import (
    ExportCriteria,
    ExportRequest,
    ExportStatus,
    PolicyOutcome,
)
from agent_action_provenance.domain.log import (
    ConsistencyProof,
    InclusionProof,
    LogEntry,
    LogPublicKey,
    SignedTreeHead,
    verify_tree_head,
)
from agent_action_provenance.domain.models import (
    ActionSubmission,
    ProvenanceRecord,
    sha256_digest,
)
from agent_action_provenance.domain.ports import Clock, Ledger, RecordFilter, StoredRecord
from agent_action_provenance.domain.verification import (
    BundleEntry,
    EvidenceBundle,
    verify_inclusion_proof,
    verify_record_semantics,
)
from agent_action_provenance.infrastructure.archive import EvidenceArchive
from agent_action_provenance.infrastructure.exports import SqlExportRepository
from agent_action_provenance.observability.metrics import ProvenanceMetrics
from agent_action_provenance.security.authorization import (
    AgentAuthorization,
    AgentAuthorizer,
    AgentPrincipal,
    AuditorPrincipal,
    AuditorRole,
    require_role,
)
from agent_action_provenance.security.signing import TreeHeadSigner

log = get_logger("agent_action_provenance.service")

RECORD_OWN = "provenance:record:write"
RECORD_DELEGATED = "provenance:record:delegate"
LOG_READ = "provenance:log:read"
EXPORT = "provenance:export"
MAX_ENTRIES_PAGE = 1000


class ProvenanceService:
    def __init__(
        self,
        *,
        ledger: Ledger,
        exports: SqlExportRepository,
        sequencer: BatchSequencer,
        signer: TreeHeadSigner,
        authorizer: AgentAuthorizer,
        export_policy: PolicyEngine,
        archive: EvidenceArchive,
        audit: AuditLog,
        metrics: ProvenanceMetrics,
        clock: Clock,
        export_max_records: int = 1000,
        archive_retention: timedelta = timedelta(days=2555),
    ) -> None:
        self._ledger = ledger
        self._exports = exports
        self._sequencer = sequencer
        self._signer = signer
        self._authorizer = authorizer
        self._export_policy = export_policy
        self._archive = archive
        self._audit = audit
        self._metrics = metrics
        self._clock = clock
        self._export_max = export_max_records
        self._retention = archive_retention
        self._seal = signer.sealer(clock.now)
        self._last_verified: SignedTreeHead | None = None

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    def seal(self, tree_size: int, root: bytes) -> SignedTreeHead:
        return self._seal(tree_size, root)

    def public_key(self) -> LogPublicKey:
        return self._signer.describe()

    # ------------------------------------------------------------- authorization

    async def authorize_agent(
        self,
        token: str,
        *,
        action: str,
        resource: Resource,
        principal: AgentPrincipal | None = None,
    ) -> AgentAuthorization:
        """Authenticate and authorize an agent; non-allow outcomes are audited and raised."""
        who = principal or await self._authorizer.authenticate(token)
        result = await self._authorizer.decide(
            token, who, action=action, resource=resource, environment={}
        )
        self._metrics.authz_decisions.labels(action, result.decision.value).inc()
        if result.decision is Decision.ALLOW:
            return result
        await self._record(
            who.subject,
            action,
            f"{resource.type}:{resource.id}",
            result.decision.value,
            {
                "rules": list(result.matched_rules),
                "policy_digest": result.policy_digest,
                "authorizer": result.authorizer,
                "reason": result.reason,
            },
        )
        if result.decision is Decision.REQUIRE_APPROVAL:
            raise ApprovalRequiredError(f"{action} requires human approval: {result.reason}")
        raise ForbiddenError(f"{action} denied: {result.reason}")

    async def authorize_log_read(self, token: str) -> AgentAuthorization:
        return await self.authorize_agent(
            token, action=LOG_READ, resource=Resource(type="transparency-log", id="*")
        )

    # ------------------------------------------------------------------ records

    async def record(self, token: str, submission: ActionSubmission) -> RecordReceipt:
        principal = await self._authorizer.authenticate(token)
        own = principal.subject == submission.agent_id
        await self.authorize_agent(
            token,
            principal=principal,
            action=RECORD_OWN if own else RECORD_DELEGATED,
            resource=Resource(
                type="agent-action",
                id=submission.action_id,
                classification=submission.max_classification,
                attributes={
                    "agent_id": submission.agent_id,
                    "own_action": own,
                    "action": submission.action.name,
                    "risk": int(submission.action.risk),
                },
            ),
        )

        existing = await self._ledger.find_action(submission.agent_id, submission.action_id)
        if existing is not None:
            return await self._duplicate(existing, submission)

        record_id = new_id()
        recorded_at = self._clock.now()
        document = prov.build_document(
            record_id, submission, recorded_by=principal.subject, recorded_at=recorded_at
        )
        problems = prov.validate_document(document)
        if problems:
            raise InvalidRecordError("; ".join(problems[:5]))
        assessment = governance.assess(submission)
        record = ProvenanceRecord(
            record_id=record_id,
            recorded_at=recorded_at,
            recorded_by=principal.subject,
            submission=submission,
            submission_digest=submission.digest(),
            prov=document,
            governance=assessment,
        )
        try:
            placement = await self._sequencer.submit(record)
        except ConflictError:
            # The same action was committed by a concurrent request (another
            # batch or replica): resolve it exactly like an idempotent retry.
            raced = await self._ledger.find_action(submission.agent_id, submission.action_id)
            if raced is None:
                raise
            return await self._duplicate(raced, submission)
        if placement.record_id != record_id:
            stored = await self._ledger.get(placement.record_id)
            if stored is None:  # pragma: no cover - the leader committed this record
                raise LogIntegrityError("deduplicated record is missing")
            return await self._duplicate(stored, submission)

        head = placement.batch.tree_head
        offset = placement.leaf_index - placement.batch.start
        leaf = placement.batch.leaf_hashes[offset]
        proof = InclusionProof(
            leaf_index=placement.leaf_index,
            tree_size=head.tree_size,
            leaf_hash=leaf,
            audit_path=placement.batch.audit_paths[offset],
        )
        self._metrics.records.labels(
            submission.action.status.value, str(assessment.compliant).lower()
        ).inc()
        for finding in assessment.findings:
            self._metrics.findings.labels(finding.code, finding.severity.value).inc()
        await self._record(
            principal.subject,
            "provenance.record",
            f"record:{record_id}",
            "success",
            {
                "agent_id": submission.agent_id,
                "action": submission.action.name,
                "record_digest": record.digest(),
                "leaf_index": placement.leaf_index,
                "tree_size": head.tree_size,
                "root_hash": head.root_hash,
                "compliant": assessment.compliant,
                "findings": [f.code for f in assessment.findings],
            },
        )
        return RecordReceipt(
            record_id=record_id,
            leaf_index=placement.leaf_index,
            leaf_hash=leaf,
            record_digest=record.digest(),
            submission_digest=record.submission_digest,
            duplicate=False,
            governance=assessment,
            tree_head=head,
            inclusion_proof=proof,
        )

    async def _duplicate(self, stored: StoredRecord, submission: ActionSubmission) -> RecordReceipt:
        if stored.record.submission_digest != submission.digest():
            raise ConflictError(
                f"action {submission.action_id} was already recorded with different content"
            )
        head = await self.latest_tree_head()
        return RecordReceipt(
            record_id=stored.record.record_id,
            leaf_index=stored.leaf_index,
            leaf_hash=stored.leaf_hash,
            record_digest=sha256_digest(stored.leaf_bytes),
            submission_digest=stored.record.submission_digest,
            duplicate=True,
            governance=stored.record.governance,
            tree_head=head,
            inclusion_proof=await self.inclusion_proof(stored.leaf_index, head.tree_size),
        )

    async def get_record(self, record_id: str) -> RecordView:
        stored = await self._ledger.get(record_id)
        if stored is None:
            raise NotFoundError(f"record {record_id} not found")
        return self._view(stored)

    @staticmethod
    def _view(stored: StoredRecord) -> RecordView:
        return RecordView(
            record_id=stored.record.record_id,
            leaf_index=stored.leaf_index,
            leaf_hash=stored.leaf_hash,
            record=json.loads(stored.leaf_bytes),
        )

    async def search(self, criteria: RecordFilter, *, limit: int, offset: int) -> list[RecordView]:
        return [
            self._view(s) for s in await self._ledger.search(criteria, limit=limit, offset=offset)
        ]

    # --------------------------------------------------------------------- log

    async def latest_tree_head(self) -> SignedTreeHead:
        head = await self._ledger.latest_tree_head()
        if head is None:
            return await self._ledger.ensure_genesis(self.seal)
        return head

    async def tree_head(self, tree_size: int) -> SignedTreeHead:
        head = await self._ledger.tree_head(tree_size)
        if head is None:
            raise NotFoundError(f"no signed tree head for size {tree_size}")
        return head

    async def _hashes(self, ranges: list[merkle.Range]) -> list[str]:
        needed = merkle.nodes_for(ranges)
        found = await self._ledger.nodes(needed)
        if needed - found.keys():
            raise LogIntegrityError("stored tree is missing nodes")
        return [h.hex() for h in merkle.assemble(ranges, found)]

    async def _current_size(self) -> int:
        return (await self.latest_tree_head()).tree_size

    async def inclusion_proof(
        self, leaf_index: int, tree_size: int | None = None
    ) -> InclusionProof:
        current = await self._current_size()
        size = current if tree_size is None else tree_size
        if size > current:
            raise NotFoundError(f"tree size {size} has not been signed yet")
        if not 0 <= leaf_index < size:
            raise NotFoundError(f"leaf {leaf_index} is not in a tree of size {size}")
        leaf = await self._ledger.leaf_hash(leaf_index)
        if leaf is None:
            raise LogIntegrityError(f"leaf {leaf_index} is missing")
        return InclusionProof(
            leaf_index=leaf_index,
            tree_size=size,
            leaf_hash=leaf.hex(),
            audit_path=tuple(await self._hashes(merkle.inclusion_ranges(leaf_index, size))),
        )

    async def consistency_proof(self, first: int, second: int) -> ConsistencyProof:
        if not 0 <= first <= second:
            raise InvalidRecordError("first must not exceed second")
        if second > await self._current_size():
            raise NotFoundError(f"tree size {second} has not been signed yet")
        return ConsistencyProof(
            first=first,
            second=second,
            proof=tuple(await self._hashes(merkle.consistency_ranges(first, second))),
        )

    async def entries(self, start: int, end: int) -> list[LogEntry]:
        if not 0 <= start < end or end - start > MAX_ENTRIES_PAGE:
            raise InvalidRecordError(f"request 1..{MAX_ENTRIES_PAGE} entries with start < end")
        return await self._ledger.entries(start, end)

    async def verify_record(self, record_id: str) -> VerificationReport:
        stored = await self._ledger.get(record_id)
        if stored is None:
            raise NotFoundError(f"record {record_id} not found")
        head = await self.latest_tree_head()
        problems: list[str] = []
        if not verify_tree_head(head, self._signer.public_key):
            problems.append("latest tree head signature is invalid")
        proof = await self.inclusion_proof(stored.leaf_index, head.tree_size)
        problems += verify_inclusion_proof(proof, stored.leaf_bytes, head)
        problems += verify_record_semantics(stored.record)
        return VerificationReport(
            record_id=record_id,
            leaf_index=stored.leaf_index,
            tree_size=head.tree_size,
            root_hash=head.root_hash,
            valid=not problems,
            problems=tuple(problems),
        )

    # ----------------------------------------------------------------- lineage

    async def lineage(
        self, digest: str, *, max_depth: int = 8, max_records: int = 500
    ) -> LineageGraph:
        frontier = {digest}
        seen_entities = {digest}
        record_ids: dict[str, None] = {}
        edges: dict[tuple[str, str, str], None] = {}
        truncated = False
        depth = 0
        while frontier and depth < max_depth:
            depth += 1
            next_frontier: set[str] = set()
            producers = await self._ledger.generators(frontier)
            for entity, rid in producers:
                edges[(entity, rid, "wasGeneratedBy")] = None
                record_ids[rid] = None
            for child, parent, _rid in await self._ledger.derivations(frontier):
                edges[(child, parent, "wasDerivedFrom")] = None
                next_frontier.add(parent)
            for rid, used in await self._ledger.inputs({r for _, r in producers}):
                edges[(rid, used, "used")] = None
                next_frontier.add(used)
            if len(record_ids) > max_records:
                truncated = True
                break
            frontier = next_frontier - seen_entities
            seen_entities |= frontier
        else:
            truncated = bool(frontier)
        stored = await self._ledger.search(
            RecordFilter(record_ids=tuple(record_ids)), limit=max_records + 1
        )
        return LineageGraph(
            root=digest,
            depth=depth,
            truncated=truncated,
            records=tuple(
                LineageRecord(
                    record_id=s.record.record_id,
                    leaf_index=s.leaf_index,
                    agent_id=s.record.submission.agent_id,
                    action=s.record.submission.action.name,
                    status=s.record.submission.action.status.value,
                    compliant=s.record.governance.compliant,
                    recorded_at=s.record.recorded_at,
                )
                for s in stored[:max_records]
            ),
            edges=tuple(LineageEdge(source=a, target=b, relation=r) for a, b, r in edges),
        )

    # ----------------------------------------------------------------- exports

    async def request_export(
        self, auditor: AuditorPrincipal, criteria: ExportCriteria
    ) -> ExportView:
        selected = await self._ledger.search(
            RecordFilter(
                agent_id=criteria.agent_id,
                correlation_id=criteria.correlation_id,
                action=criteria.action,
                compliant=criteria.compliant,
                since=criteria.since,
                until=criteria.until,
                record_ids=criteria.record_ids,
            ),
            limit=self._export_max + 1,
        )
        if not selected:
            raise NotFoundError("no records match the export criteria")
        if len(selected) > self._export_max:
            raise InvalidRecordError(
                f"export would exceed {self._export_max} records; narrow the criteria"
            )
        max_cls = max(s.record.submission.max_classification for s in selected)
        non_compliant = sum(1 for s in selected if not s.record.governance.compliant)
        decision = self._export_policy.evaluate(
            PolicyRequest(
                subject=Subject(id=auditor.subject, kind="user", roles=auditor.roles),
                action=EXPORT,
                resource=Resource(
                    type="evidence-bundle",
                    classification=max_cls,
                    attributes={"record_count": len(selected), "non_compliant": non_compliant},
                ),
                environment={"purpose": criteria.purpose},
            )
        )
        self._metrics.exports.labels(decision.decision.value).inc()
        export_id = new_id()
        await self._record(
            auditor.subject,
            "export.request",
            f"export:{export_id}",
            decision.decision.value,
            {
                "records": len(selected),
                "max_classification": int(max_cls),
                "rules": list(decision.matched_rules),
                "policy_digest": decision.policy_digest,
                "purpose": criteria.purpose,
            },
        )
        if decision.decision is Decision.DENY:
            raise ForbiddenError(f"export denied: {decision.reason}")
        request = ExportRequest(
            export_id=export_id,
            status=(
                ExportStatus.READY
                if decision.decision is Decision.ALLOW
                else ExportStatus.PENDING_APPROVAL
            ),
            criteria=criteria,
            requested_by=auditor.subject,
            created_at=self._clock.now(),
            record_ids=tuple(s.record.record_id for s in selected),
            max_classification=DataClassification(max_cls),
            policy=PolicyOutcome(
                decision=decision.decision,
                matched_rules=decision.matched_rules,
                policy_version=decision.policy_version,
                policy_digest=decision.policy_digest,
                reason=decision.reason,
            ),
        )
        await self._exports.add(request)
        return ExportView.of(request)

    async def _export(self, export_id: str) -> ExportRequest:
        request = await self._exports.get(export_id)
        if request is None:
            raise NotFoundError(f"export {export_id} not found")
        return request

    async def get_export(self, auditor: AuditorPrincipal, export_id: str) -> ExportView:
        require_role(auditor, AuditorRole.AUDITOR, AuditorRole.APPROVER)
        return ExportView.of(await self._export(export_id))

    async def approve_export(self, approver: AuditorPrincipal, export_id: str) -> ExportView:
        require_role(approver, AuditorRole.APPROVER)
        request = await self._export(export_id)
        if request.status is not ExportStatus.PENDING_APPROVAL:
            raise ConflictError(f"export {export_id} is {request.status.value}")
        if approver.subject == request.requested_by:
            await self._record(
                approver.subject,
                "export.approve",
                f"export:{export_id}",
                "denied",
                {"reason": "self-approval"},
            )
            raise ForbiddenError("the requester cannot approve their own export")
        approved = request.model_copy(
            update={
                "status": ExportStatus.READY,
                "approved_by": approver.subject,
                "approved_at": self._clock.now(),
            }
        )
        await self._exports.transition(approved, ExportStatus.PENDING_APPROVAL)
        self._metrics.exports.labels("approved").inc()
        await self._record(
            approver.subject,
            "export.approve",
            f"export:{export_id}",
            "success",
            {"requested_by": request.requested_by, "records": len(request.record_ids)},
        )
        return ExportView.of(approved)

    async def export_bundle(self, auditor: AuditorPrincipal, export_id: str) -> EvidenceBundle:
        require_role(auditor, AuditorRole.AUDITOR)
        request = await self._export(export_id)
        if auditor.subject != request.requested_by:
            raise ForbiddenError("only the requesting auditor may download the bundle")
        if request.status is not ExportStatus.READY:
            raise ApprovalRequiredError(f"export {export_id} is awaiting approval")
        head = await self.latest_tree_head()
        stored = await self._ledger.search(
            RecordFilter(record_ids=request.record_ids), limit=len(request.record_ids)
        )
        entries = [
            BundleEntry(
                leaf_index=s.leaf_index,
                record=json.loads(s.leaf_bytes),
                inclusion_proof=await self.inclusion_proof(s.leaf_index, head.tree_size),
            )
            for s in stored
        ]
        await self._record(
            auditor.subject,
            "export.download",
            f"export:{export_id}",
            "success",
            {"records": len(entries), "tree_size": head.tree_size, "root_hash": head.root_hash},
        )
        return EvidenceBundle(
            export_id=export_id,
            generated_at=self._clock.now(),
            criteria=request.criteria.model_dump(mode="json"),
            log=self.public_key(),
            tree_head=head,
            entries=tuple(entries),
        )

    # -------------------------------------------------------------- integrity

    async def check_integrity(self) -> IntegrityReport:
        """Self-monitor: re-derive the signed root and prove append-only growth."""
        problems: list[str] = []
        head = await self.latest_tree_head()
        previous = self._last_verified
        if not verify_tree_head(head, self._signer.public_key):
            problems.append("latest tree head signature is invalid")
        if head.tree_size != await self._ledger.tree_size():
            problems.append("log size differs from the latest signed tree head")
        if head.tree_size:
            try:
                needed = merkle.perfect_subtrees(0, head.tree_size)
                found = await self._ledger.nodes(needed)
                root = merkle.range_hash(0, head.tree_size, found)
            except KeyError:
                problems.append("stored tree is missing nodes")
            else:
                if root.hex() != head.root_hash:
                    problems.append("stored tree does not reproduce the signed root")
            batch_start = await self._ledger.batch_start(head.tree_size)
            problems += await self._check_leaves(batch_start or 0, head.tree_size)
        if previous is not None and head.tree_size < previous.tree_size:
            problems.append(
                f"log shrank from {previous.tree_size} to {head.tree_size} leaves (rollback)"
            )
        if previous is not None and not problems:
            try:
                proof = await self.consistency_proof(previous.tree_size, head.tree_size)
                if not merkle.verify_consistency(
                    previous.tree_size,
                    head.tree_size,
                    bytes.fromhex(previous.root_hash),
                    bytes.fromhex(head.root_hash),
                    [bytes.fromhex(p) for p in proof.proof],
                ):
                    problems.append("log is not an append-only extension of the last verified head")
            except (LogIntegrityError, NotFoundError) as exc:
                problems.append(str(exc))
        ok = not problems
        self._metrics.integrity_checks.labels("ok" if ok else "failed").inc()
        if ok:
            self._last_verified = head
        else:
            log.error("log_integrity_failure", problems=problems, tree_size=head.tree_size)
            await self._record(
                "agent-action-provenance",
                "log.integrity",
                "transparency-log",
                "failure",
                {"problems": problems, "tree_size": head.tree_size},
            )
        return IntegrityReport(
            ok=ok,
            tree_size=head.tree_size,
            checked_from=previous.tree_size if previous else 0,
            problems=tuple(problems),
        )

    async def _check_leaves(self, start: int, end: int) -> list[str]:
        problems: list[str] = []
        stored = {e.leaf_index: e.leaf_hash for e in await self._ledger.entries(start, end)}
        for index, document in await self._ledger.leaves_between(start, end):
            if merkle.leaf_hash(document).hex() != stored.get(index):
                problems.append(f"record at leaf {index} does not match its leaf hash")
        return problems

    # ------------------------------------------------------------------ archive

    async def archive_pending(self, limit: int = 50) -> int:
        """Copy sealed batches to WORM storage. Returns the number archived."""
        pending = await self._ledger.pending_archive(limit)
        archived = 0
        try:
            for item in pending:
                head = item.tree_head
                rows = await self._ledger.leaves_between(item.batch_start, head.tree_size)
                body = canonical_json(
                    {
                        "format": "aap-batch/v1",
                        "log": self.public_key().model_dump(mode="json"),
                        "tree_head": head.model_dump(mode="json"),
                        "entries": [
                            {"leaf_index": index, "record": json.loads(document)}
                            for index, document in rows
                        ],
                    }
                )
                key = f"batches/{head.tree_size:020d}.json"
                receipt = await self._archive.put(
                    key, body, retain_until=self._clock.now() + self._retention
                )
                await self._ledger.mark_archived(head.tree_size, key, self._clock.now())
                await self._record(
                    "agent-action-provenance",
                    "archive.put",
                    receipt.location,
                    "success",
                    {
                        "tree_size": head.tree_size,
                        "root_hash": head.root_hash,
                        "sha256": receipt.sha256,
                        "already_present": receipt.already_present,
                    },
                )
                archived += 1
        except Exception:
            self._metrics.archive_failures.inc()
            raise
        finally:
            self._metrics.archive_backlog.set(len(await self._ledger.pending_archive(1000)))
        return archived

    # ---------------------------------------------------------------------- audit

    async def audit_tool_call(self, subject: str, tool: str, channel: str = "mcp") -> None:
        """Audit a read-only tool invocation made through MCP or A2A."""
        await self._record(subject, f"{channel}.{tool}", channel, "success", {})

    async def _record(
        self, actor: str, action: str, resource: str, outcome: str, details: dict[str, Any]
    ) -> None:
        await self._audit.record(
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            correlation_id=correlation_id(),
            details=details,
        )
