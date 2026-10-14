"""Deterministic governance checks over a submitted action.

The engine never refuses to *record* an action because of these findings:
evidence of a violation is exactly what must be preserved. Findings are
sealed into the record (and therefore into the Merkle leaf), counted in
metrics, and alerted on.
"""

from __future__ import annotations

from datetime import timedelta

from agentic_core.domain.classification import Decision, RiskLevel, TrustLevel

from agent_action_provenance.domain.models import (
    ActionStatus,
    ActionSubmission,
    GovernanceAssessment,
    GovernanceFinding,
    Severity,
)

# Tolerated clock skew between the agent, the authorizer and the recorder.
CLOCK_SKEW = timedelta(seconds=30)


Findings = list[GovernanceFinding]


def _add(findings: Findings, code: str, severity: Severity, detail: str) -> None:
    findings.append(GovernanceFinding(code=code, severity=severity, detail=detail))


def _authorization(s: ActionSubmission, findings: Findings) -> None:
    auth = s.authorization
    executed = s.action.status is ActionStatus.EXECUTED
    if auth is None:
        if executed:
            _add(
                findings,
                "authorization_missing",
                Severity.VIOLATION,
                "action executed without a recorded authorization decision",
            )
        return
    if executed and auth.decision is Decision.DENY:
        _add(
            findings,
            "executed_despite_deny",
            Severity.VIOLATION,
            f"policy {auth.policy_name}@{auth.policy_version} denied the action",
        )
    if executed and auth.decision is Decision.REQUIRE_APPROVAL and auth.approval is None:
        _add(
            findings,
            "approval_missing",
            Severity.VIOLATION,
            "policy required human approval but none is recorded",
        )
    if auth.decided_at > s.action.started_at + CLOCK_SKEW:
        _add(
            findings,
            "authorization_after_execution",
            Severity.VIOLATION,
            "authorization decision is timestamped after the action started",
        )
    if s.action.status is ActionStatus.BLOCKED and auth.decision is Decision.ALLOW:
        _add(
            findings,
            "blocked_despite_allow",
            Severity.INFO,
            "action was blocked although policy allowed it",
        )


def _approval(s: ActionSubmission, findings: Findings) -> None:
    approval = s.authorization.approval if s.authorization else None
    if approval is None:
        return
    if approval.approver == s.agent_id or approval.approver in s.on_behalf_of[:1]:
        _add(
            findings,
            "self_approval",
            Severity.VIOLATION,
            "approval was granted by the acting agent or its immediate principal",
        )
    if approval.approved_at > s.action.started_at + CLOCK_SKEW:
        _add(
            findings,
            "approval_after_execution",
            Severity.VIOLATION,
            "approval is timestamped after the action started",
        )


def _evidence(s: ActionSubmission, findings: Findings) -> None:
    for item in s.evidence:
        if item.retrieved_at > s.action.ended_at + CLOCK_SKEW:
            _add(
                findings,
                "evidence_after_action",
                Severity.WARNING,
                f"evidence {item.digest[:19]} was retrieved after the action ended",
            )
    if s.action.risk < RiskLevel.HIGH or s.action.status is not ActionStatus.EXECUTED:
        return
    if not s.evidence:
        _add(findings, "high_risk_without_evidence", Severity.WARNING, "no evidence recorded")
    elif all(e.trust is TrustLevel.EXTERNAL for e in s.evidence):
        _add(
            findings,
            "high_risk_on_untrusted_evidence",
            Severity.WARNING,
            "every evidence item has EXTERNAL trust",
        )


def _classification(s: ActionSubmission, findings: Findings) -> None:
    evidence_cls = {e.digest: e.classification for e in s.evidence}
    for output in s.outputs:
        sources = [evidence_cls[d] for d in output.derived_from if d in evidence_cls]
        if sources and output.classification < max(sources):
            _add(
                findings,
                "classification_downgrade",
                Severity.VIOLATION,
                f"output {output.digest[:19]} is labelled below the data it derives from",
            )


def assess(submission: ActionSubmission) -> GovernanceAssessment:
    findings: Findings = []
    for check in (_authorization, _approval, _evidence, _classification):
        check(submission, findings)
    compliant = not any(f.severity is Severity.VIOLATION for f in findings)
    return GovernanceAssessment(compliant=compliant, findings=tuple(findings))
