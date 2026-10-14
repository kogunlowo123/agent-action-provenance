"""Service metrics exposed on /metrics in Prometheus text format."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram


class ProvenanceMetrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        r = self.registry
        self.requests = Histogram(
            "provenance_http_request_duration_seconds",
            "HTTP request latency",
            ["method", "route", "status"],
            registry=r,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
        )
        self.records = Counter(
            "provenance_records_total",
            "Action records sealed into the log",
            ["status", "compliant"],
            registry=r,
        )
        self.findings = Counter(
            "provenance_governance_findings_total",
            "Governance findings by code and severity",
            ["code", "severity"],
            registry=r,
        )
        self.batch_size = Histogram(
            "provenance_batch_size",
            "Records per sealed batch",
            registry=r,
            buckets=(1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024),
        )
        self.seal_seconds = Histogram(
            "provenance_batch_seal_seconds",
            "Time to append a batch and sign its tree head",
            registry=r,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
        )
        self.batch_failures = Counter(
            "provenance_batch_failures_total", "Batches that failed to commit", registry=r
        )
        self.tree_size = Gauge(
            "provenance_log_tree_size", "Leaves in the latest signed tree head", registry=r
        )
        self.archive_backlog = Gauge(
            "provenance_archive_backlog", "Sealed batches not yet in WORM storage", registry=r
        )
        self.archive_failures = Counter(
            "provenance_archive_failures_total", "Failed WORM archive writes", registry=r
        )
        self.integrity_checks = Counter(
            "provenance_integrity_checks_total",
            "Self-monitoring checks of the signed log",
            ["result"],
            registry=r,
        )
        self.authz_decisions = Counter(
            "provenance_authorization_decisions_total",
            "Caller authorization decisions",
            ["action", "decision"],
            registry=r,
        )
        self.exports = Counter(
            "provenance_exports_total", "Auditor export requests", ["status"], registry=r
        )
