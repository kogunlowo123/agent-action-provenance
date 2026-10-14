# Compliance control mapping

The evidence column names the artifact an auditor can inspect. Mappings show
where the engine supports a control; the controls themselves belong to the
operating organization's program.

| Control objective | HIPAA Security Rule | SOC 2 (TSC 2017) | ISO/IEC 27001:2022 | NIST SP 800-53 r5 | NIST AI RMF 1.0 | 21 CFR Part 11 / GxP | Evidence |
|---|---|---|---|---|---|---|---|
| Audit trail of agent activity | 164.312(b) | CC7.2 | 8.15 | AU-2, AU-3, AU-12 | MEASURE 2.8 | 11.10(e) | Sealed records, `GET /v1/records`, PROV documents |
| Audit record integrity | 164.312(c)(1), (c)(2) | CC7.2 | 8.15 | AU-9, AU-9(3), SI-7 | MEASURE 2.8 | 11.10(c), 11.10(e) | Signed tree heads, inclusion/consistency proofs, integrity-check metrics |
| Non-repudiation | 164.312(c)(2) | CC7.2 | 8.15 | AU-10 | GOVERN 1.4 | 11.50, 11.70 | `recorded_by`, approver in PROV, signed audit chain |
| Protection of records from deletion | 164.316(b)(2)(i) | A1.2 | 5.33 | AU-11, AU-9(2) | — | 11.10(c) | S3 Object Lock COMPLIANCE, retention variables |
| Time-stamped, sequenced records | 164.312(b) | CC7.2 | 8.17 | AU-8 | — | 11.10(e) | Tree-head timestamps, leaf index ordering, PROV times |
| Authorization of actions | 164.308(a)(4) | CC6.1, CC6.3 | 5.15, 8.2 | AC-3, AC-6 | MANAGE 2.4 | 11.10(d), 11.10(g) | `AuthorizationRecord` in every record, `authorization_missing` and `executed_despite_deny` findings |
| Human oversight of high-risk actions | — | CC5.2 | 5.2 | CA-7 | GOVERN 3.2, MANAGE 2.4 | 11.10(g) | `approval_missing`, `self_approval`, `approval_after_execution` findings |
| Data lineage | 164.312(c)(1) | PI1.2 | 5.12 | SI-7, PT-2 | MAP 2.3, MEASURE 2.9 | ALCOA+ (attributable, original) | `wasDerivedFrom`, `GET /v1/lineage/{digest}` |
| Data classification handling | 164.312(a)(1) | C1.1 | 5.12, 5.13 | AC-16 | MAP 4.1 | — | `classification_downgrade` finding, export classification policy |
| Controlled disclosure to auditors | 164.308(a)(3) | CC6.1 | 5.15, 5.34 | AC-21 | GOVERN 6.1 | 11.10(d) | Export requests, two-person approval, audit events |
| Change control of rules | 164.308(a)(8) | CC8.1 | 8.32 | CM-3 | GOVERN 1.4 | 11.10(k) | Git history, CODEOWNERS, policy digest in audit, `RECORD_SCHEMA_VERSION` |
| Monitoring and response | 164.308(a)(6) | CC7.3 | 5.24 | IR-4, SI-4 | MANAGE 4.1 | — | Alert rules, incident runbook |
| Availability and recovery | 164.308(a)(7) | A1.2, A1.3 | 8.13, 8.14 | CP-9, CP-10 | — | 11.10(c) | Multi-AZ PostgreSQL, PITR, DR runbook, archive rebuild procedure |

## GxP and computerized system validation

- **21 CFR Part 11 / EU Annex 11:** records are attributable (`recorded_by`,
  agent, delegation chain, approver), contemporaneous (sealed with a signed
  timestamp), original (exact bytes hashed), enduring (WORM) and available
  (export with offline verification), meeting ALCOA+ for agent-generated
  actions.
- **FDA CSA (Computer Software Assurance):** the engine is a high-assurance
  record-keeping function. Assurance evidence: the CI run for the deployed tag
  (unit, security, chaos, e2e and PostgreSQL integration suites with the
  coverage gate) serves as OQ evidence for the requirements in
  `docs/architecture/acceptance-criteria.md`; IQ is the Helm release with the
  digest-pinned image and its SBOM and provenance attestation; PQ is the
  monitoring SLOs.

## HITRUST

HITRUST CSF requirements for audit logging (09.aa), protection of log
information (09.ac) and monitoring (09.ab) map to the rows above; the engine
provides the technical controls and evidence, not the certification.
