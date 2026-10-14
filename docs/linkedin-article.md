When an AI agent changes a record, who can prove what it did, and why?

We kept hitting the same gap: agents act on real systems, but the evidence of their actions lives in logs the platform team can edit.

Why it matters: auditors ask three questions. What did the agent decide, from which evidence? Was it authorized, and was approval given first? Can the record itself be trusted?

The flow we built:
Decision → Evidence → Authorization → PROV record → Merkle log → Signed tree head → WORM archive → Monitors

How it works:
1. The agent, or the gateway in front of it, submits its decision, evidence digests and the policy decision it acted under.
2. We turn that into a W3C PROV document: who acted, for whom, what it used, what it produced.
3. Governance checks run on every record: executed despite a deny, missing approval, self-approval, outputs labelled below their inputs. Violations are sealed into the record, never refused.
4. Records are batched into an RFC 6962 Merkle tree in PostgreSQL. One signature covers each batch, and every caller gets an inclusion proof back.
5. Consistency proofs let anyone check that the log only grew.
6. Sealed batches go to S3 Object Lock in compliance mode.
7. Auditors export evidence bundles and verify them offline against a public key they pinned themselves.

Best practices: authorize every caller through the identity fabric and fail closed; store digests, never evidence content; require a second person for sensitive exports; run monitors outside the platform's trust boundary.

Tradeoffs: one ordered log means one write lock, and batching adds tens of milliseconds. Retention locks are cheap to set and impossible to undo. Proofs only help if someone checks them, so monitoring is part of the design.

Value: an investigation starts from evidence anyone can verify, not from whoever had database access.

As agents take on regulated work, provenance becomes as basic as authentication.

Question: should agent actions without a verifiable record be blocked outright, or recorded and flagged?

Code: github.com/kogunlowo123/agent-action-provenance

#AI #ArtificialIntelligence #GenerativeAI #AgenticAI #LLMOps #EnterpriseAI #AISecurity #RAG #MachineLearning #DataScience #CloudComputing #Kubernetes #MLOps #DigitalTransformation #Innovation #Provenance #AuditTrail #Compliance
