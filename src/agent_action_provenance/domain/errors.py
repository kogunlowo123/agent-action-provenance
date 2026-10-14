"""Domain errors mapped to HTTP status codes by the API layer."""

from __future__ import annotations


class ProvenanceError(Exception):
    code = "invalid_request"
    status = 400

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(ProvenanceError):
    code = "not_found"
    status = 404


class ConflictError(ProvenanceError):
    code = "conflict"
    status = 409


class InvalidRecordError(ProvenanceError):
    """The submission is well-formed JSON but violates provenance constraints."""

    code = "invalid_record"
    status = 422


class UnauthorizedError(ProvenanceError):
    code = "unauthorized"
    status = 401


class ForbiddenError(ProvenanceError):
    code = "forbidden"
    status = 403


class ApprovalRequiredError(ProvenanceError):
    """Policy requires a human sign-off before the operation may proceed."""

    code = "approval_required"
    status = 403


class UpstreamUnavailableError(ProvenanceError):
    """A dependency needed to make a safe decision is unreachable (fail closed)."""

    code = "temporarily_unavailable"
    status = 503


class LogIntegrityError(ProvenanceError):
    """Stored log state does not match a signed tree head or a proof failed."""

    code = "log_integrity"
    status = 500


class ArchiveConflictError(ProvenanceError):
    """A WORM object already exists with different content."""

    code = "archive_conflict"
    status = 409
