"""W3C PROV-JSON documents for agent actions, and PROV constraint checks.

Serialization follows the PROV-JSON member submission
(https://www.w3.org/submissions/prov-json/): top-level ``prefix`` plus one
object per element/relation kind keyed by qualified name. The mapping of an
agent action onto PROV-DM is:

    decide     (activity)  used evidence, generated the decision entity,
                           wasAssociatedWith the acting agent
    authorize  (activity)  used the decision, wasAssociatedWith the authorizer
                           under the policy (prov:Plan) and any approver,
                           generated the authorization entity
    act        (activity)  used the decision (and authorization),
                           wasInformedBy decide/authorize, generated outputs
    outputs    (entities)  wasDerivedFrom their declared sources,
                           wasAttributedTo the acting agent
    agent      actedOnBehalfOf each principal in the delegation chain

Identifiers are deterministic so the same submission always produces the
same document, which keeps the Merkle leaf reproducible.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime
from typing import Any

from agentic_core.domain.identifiers import AgentId

from agent_action_provenance.domain.models import ActionSubmission

PROV_NS = "http://www.w3.org/ns/prov#"
AAP_NS = "https://github.com/kogunlowo123/agent-action-provenance/ns#"
XSD_NS = "http://www.w3.org/2001/XMLSchema#"

ELEMENT_KINDS = ("entity", "activity", "agent")

# relation kind -> (role -> required element kind)
RELATIONS: dict[str, dict[str, str]] = {
    "used": {"prov:activity": "activity", "prov:entity": "entity"},
    "wasGeneratedBy": {"prov:entity": "entity", "prov:activity": "activity"},
    "wasAssociatedWith": {"prov:activity": "activity", "prov:agent": "agent"},
    "wasAttributedTo": {"prov:entity": "entity", "prov:agent": "agent"},
    "wasDerivedFrom": {"prov:generatedEntity": "entity", "prov:usedEntity": "entity"},
    "wasInformedBy": {"prov:informed": "activity", "prov:informant": "activity"},
    "actedOnBehalfOf": {"prov:delegate": "agent", "prov:responsible": "agent"},
}
OPTIONAL_REFERENCES = {"prov:plan": "entity", "prov:activity": "activity"}


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:24]


def entity_id(digest: str) -> str:
    return f"aap:entity-{digest.removeprefix('sha256:')}"


def agent_qname(uri: str) -> str:
    return f"aap:agent-{_h(uri)}"


def _time(value: datetime) -> str:
    return value.isoformat()


class _Builder:
    def __init__(self) -> None:
        self.doc: dict[str, Any] = {
            "prefix": {"prov": PROV_NS, "aap": AAP_NS, "xsd": XSD_NS},
            "entity": {},
            "activity": {},
            "agent": {},
        }
        self._counters: dict[str, int] = defaultdict(int)

    def agent(self, uri: str, *, software: bool) -> str:
        qname = agent_qname(uri)
        self.doc["agent"].setdefault(
            qname,
            {
                "prov:type": "prov:SoftwareAgent" if software else "prov:Person",
                "aap:uri": uri,
            },
        )
        return qname

    def entity(self, qname: str, attributes: dict[str, Any]) -> str:
        self.doc["entity"].setdefault(qname, attributes)
        return qname

    def relation(self, kind: str, **roles: str) -> None:
        self._counters[kind] += 1
        body = {f"prov:{k}": v for k, v in roles.items()}
        self.doc.setdefault(kind, {})[f"_:{kind}{self._counters[kind]}"] = body


def _is_software(principal: str) -> bool:
    try:
        AgentId.parse(principal)
    except ValueError:
        return principal.startswith(("spiffe://", "service:"))
    return True


def build_document(
    record_id: str, submission: ActionSubmission, *, recorded_by: str, recorded_at: datetime
) -> dict[str, Any]:
    b = _Builder()
    s = submission
    actor = b.agent(s.agent_id, software=True)

    decide = f"aap:decide-{record_id}"
    act = f"aap:act-{record_id}"
    b.doc["activity"][decide] = {
        "prov:type": "aap:Decision",
        "prov:endTime": _time(s.action.started_at),
    }
    b.doc["activity"][act] = {
        "prov:type": "aap:AgentAction",
        "prov:startTime": _time(s.action.started_at),
        "prov:endTime": _time(s.action.ended_at),
        "aap:action": s.action.name,
        "aap:target": s.action.target,
        "aap:status": s.action.status.value,
        "aap:risk": int(s.action.risk),
        **({"aap:tool": s.action.tool} if s.action.tool else {}),
    }
    b.relation("wasAssociatedWith", activity=decide, agent=actor)
    b.relation("wasAssociatedWith", activity=act, agent=actor)

    decision = b.entity(
        f"aap:decision-{record_id}",
        {
            "prov:type": "aap:DecisionRecord",
            "aap:summary": s.decision.summary,
            **({"aap:model": s.decision.model.model} if s.decision.model else {}),
        },
    )
    b.relation("wasGeneratedBy", entity=decision, activity=decide)
    b.relation("used", activity=act, entity=decision)
    b.relation("wasInformedBy", informed=act, informant=decide)

    known: set[str] = set()
    for item in s.evidence:
        qname = b.entity(
            entity_id(item.digest),
            {
                "prov:type": f"aap:{item.kind.value}",
                "aap:uri": item.uri,
                "aap:digest": item.digest,
                "aap:trust": int(item.trust),
                "aap:classification": int(item.classification),
            },
        )
        known.add(item.digest)
        b.relation("used", activity=decide, entity=qname)
    for output in s.outputs:
        known.add(output.digest)

    if s.authorization is not None:
        auth = s.authorization
        authorize = f"aap:authorize-{record_id}"
        b.doc["activity"][authorize] = {
            "prov:type": "aap:Authorization",
            "prov:endTime": _time(auth.decided_at),
            "aap:decision": auth.decision.value,
        }
        authorizer = b.agent(auth.authorizer, software=True)
        policy = b.entity(
            f"aap:policy-{auth.policy_digest.removeprefix('sha256:')}",
            {
                "prov:type": "prov:Plan",
                "aap:policyName": auth.policy_name,
                "aap:policyVersion": auth.policy_version,
                "aap:digest": auth.policy_digest,
            },
        )
        b.relation("wasAssociatedWith", activity=authorize, agent=authorizer, plan=policy)
        b.relation("used", activity=authorize, entity=decision)
        grant = b.entity(
            f"aap:authorization-{record_id}",
            {
                "prov:type": "aap:AuthorizationDecision",
                "aap:decision": auth.decision.value,
                "aap:matchedRules": list(auth.matched_rules),
            },
        )
        b.relation("wasGeneratedBy", entity=grant, activity=authorize)
        b.relation("used", activity=act, entity=grant)
        b.relation("wasInformedBy", informed=authorize, informant=decide)
        b.relation("wasInformedBy", informed=act, informant=authorize)
        if auth.approval is not None:
            approver = b.agent(
                auth.approval.approver, software=_is_software(auth.approval.approver)
            )
            b.relation("wasAssociatedWith", activity=authorize, agent=approver)

    for output in s.outputs:
        qname = b.entity(
            entity_id(output.digest),
            {
                "prov:type": "aap:Output",
                "aap:uri": output.uri,
                "aap:digest": output.digest,
                "aap:classification": int(output.classification),
            },
        )
        b.relation("wasGeneratedBy", entity=qname, activity=act)
        b.relation("wasAttributedTo", entity=qname, agent=actor)

    derived = [(e.digest, e.derived_from) for e in s.evidence]
    derived += [(o.digest, o.derived_from) for o in s.outputs]
    for child, parents in derived:
        for parent in parents:
            if parent not in known:
                b.entity(
                    entity_id(parent), {"prov:type": "aap:ExternalEntity", "aap:digest": parent}
                )
            b.relation(
                "wasDerivedFrom", generatedEntity=entity_id(child), usedEntity=entity_id(parent)
            )

    delegate = actor
    for principal in s.on_behalf_of:
        responsible = b.agent(principal, software=_is_software(principal))
        b.relation("actedOnBehalfOf", delegate=delegate, responsible=responsible, activity=act)
        delegate = responsible

    recorder = b.agent(recorded_by, software=True)
    b.doc["activity"][f"aap:record-{record_id}"] = {
        "prov:type": "aap:ProvenanceRecording",
        "prov:startTime": _time(recorded_at),
    }
    b.relation("wasAssociatedWith", activity=f"aap:record-{record_id}", agent=recorder)
    b.relation("wasInformedBy", informed=f"aap:record-{record_id}", informant=act)
    return b.doc


def _references(
    kind: str, rel_id: str, body: dict[str, Any], declared: dict[str, set[str]]
) -> list[str]:
    roles = RELATIONS[kind]
    problems = [
        f"{kind} {rel_id}: {role} {body.get(role)!r} is not a declared {element_kind}"
        for role, element_kind in roles.items()
        if body.get(role) not in declared[element_kind]
    ]
    problems += [
        f"{kind} {rel_id}: {role} {body[role]!r} is not declared"
        for role, element_kind in OPTIONAL_REFERENCES.items()
        if role not in roles and role in body and body[role] not in declared[element_kind]
    ]
    return problems


def _relations(
    doc: dict[str, Any], declared: dict[str, set[str]]
) -> tuple[list[str], dict[str, set[str]], dict[str, set[str]]]:
    problems: list[str] = []
    generated_by: dict[str, set[str]] = defaultdict(set)
    derivations: dict[str, set[str]] = defaultdict(set)
    for kind in RELATIONS:
        section = doc.get(kind, {})
        if not isinstance(section, dict):
            problems.append(f"{kind} must be an object")
            continue
        for rel_id, body in section.items():
            if not isinstance(body, dict):
                problems.append(f"{kind} {rel_id} must be an object")
                continue
            problems += _references(kind, rel_id, body, declared)
            if kind == "wasGeneratedBy":
                generated_by[str(body.get("prov:entity"))].add(str(body.get("prov:activity")))
            elif kind == "wasDerivedFrom":
                derivations[str(body.get("prov:generatedEntity"))].add(
                    str(body.get("prov:usedEntity"))
                )
    return problems, generated_by, derivations


def _intervals(activities: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for activity_id, attrs in activities.items():
        if not isinstance(attrs, dict):
            problems.append(f"activity {activity_id} must be an object")
            continue
        start, end = attrs.get("prov:startTime"), attrs.get("prov:endTime")
        if not (isinstance(start, str) and isinstance(end, str)):
            continue
        try:
            if datetime.fromisoformat(end) < datetime.fromisoformat(start):
                problems.append(f"activity {activity_id} ends before it starts")
        except ValueError:
            problems.append(f"activity {activity_id} has an invalid time")
    return problems


def validate_document(doc: dict[str, Any]) -> list[str]:
    """Check referential integrity and the PROV-CONSTRAINTS this model relies on.

    * every relation references declared elements of the right kind
    * unique generation: an entity is generated by at most one activity
    * derivation is acyclic (no entity derives, transitively, from itself)
    * an activity does not end before it starts
    """
    missing = [f"missing {k} section" for k in ELEMENT_KINDS if not isinstance(doc.get(k), dict)]
    if missing:
        return missing
    declared = {kind: set(doc[kind]) for kind in ELEMENT_KINDS}
    problems, generated_by, derivations = _relations(doc, declared)
    problems += [
        f"entity {entity} is generated by more than one activity"
        for entity, activities in generated_by.items()
        if len(activities) > 1
    ]
    problems += _cycles(derivations)
    problems += _intervals(doc["activity"])
    return problems


def _cycles(edges: dict[str, set[str]]) -> list[str]:
    white, grey, black = 0, 1, 2
    color: dict[str, int] = defaultdict(int)
    found: list[str] = []
    for root in list(edges):
        if color[root] != white:
            continue
        stack: list[tuple[str, list[str]]] = [(root, sorted(edges.get(root, ())))]
        color[root] = grey
        while stack:
            node, pending = stack[-1]
            if not pending:
                color[node] = black
                stack.pop()
                continue
            child = pending.pop()
            if color[child] == grey:
                found.append(f"derivation cycle through {child}")
            elif color[child] == white:
                color[child] = grey
                stack.append((child, sorted(edges.get(child, ()))))
    return found
