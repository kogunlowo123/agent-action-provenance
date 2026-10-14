"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from agentic_core.observability import bind_correlation_id, get_logger
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from agent_action_provenance import __version__
from agent_action_provenance.api.a2a import router as a2a_router
from agent_action_provenance.api.mcp import build_mcp, mcp_http_app
from agent_action_provenance.api.routes import router
from agent_action_provenance.domain.errors import ProvenanceError
from agent_action_provenance.runtime.container import Container

ContainerFactory = Callable[[], Awaitable[Container]]
Sleep = Callable[[float], Awaitable[None]]

log = get_logger("agent_action_provenance.api")

DEFAULT_MCP_HOSTS = ["127.0.0.1:*", "localhost:*"]


async def archive_forever(container: Container, interval_s: float) -> None:
    """Ship sealed batches to WORM storage when a batch seals, and on a timer."""
    while True:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(container.archive_due.wait(), interval_s)
        container.archive_due.clear()
        try:
            await container.service.archive_pending()
        except Exception:
            log.exception("archive_failed")


async def monitor_forever(
    container: Container, interval_s: float, sleep: Sleep = asyncio.sleep
) -> None:
    """Continuously re-verify the signed log against stored state."""
    while True:
        try:
            await container.service.check_integrity()
        except Exception:
            log.exception("integrity_check_failed")
        await sleep(interval_s)


def create_app(factory: ContainerFactory, *, mcp_allowed_hosts: list[str] | None = None) -> FastAPI:
    mcp_server = build_mcp(lambda: app.state.container)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        container = await factory()
        app.state.container = container
        settings = container.settings
        tasks = [
            asyncio.create_task(archive_forever(container, settings.archive_interval_s)),
            asyncio.create_task(monitor_forever(container, settings.monitor_interval_s)),
        ]
        log.info("startup", version=__version__)
        try:
            async with mcp_server.session_manager.run():
                yield
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            await container.aclose()

    app = FastAPI(
        title="Agent Action Provenance",
        version=__version__,
        description=(
            "Provenance engine for AI agent actions: W3C PROV records, signed evidence chain, "
            "RFC 6962 transparency log (append, inclusion proof, consistency proof), auditor "
            "evidence export and WORM archival."
        ),
        lifespan=lifespan,
    )
    app.include_router(router)
    app.include_router(a2a_router)
    for route in mcp_http_app(mcp_server, mcp_allowed_hosts or DEFAULT_MCP_HOSTS).routes:
        app.router.routes.append(route)

    @app.middleware("http")
    async def correlation_and_metrics(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-correlation-id")
        cid = incoming if incoming and len(incoming) <= 64 and incoming.isprintable() else None
        started = time.perf_counter()
        with bind_correlation_id(cid) as bound:
            response = await call_next(request)
        response.headers["X-Correlation-ID"] = bound
        response.headers["X-Content-Type-Options"] = "nosniff"
        route = request.scope.get("route")
        path = getattr(route, "path", "unmatched")
        container: Container | None = getattr(request.app.state, "container", None)
        if container is not None:
            container.metrics.requests.labels(
                request.method, path, str(response.status_code)
            ).observe(time.perf_counter() - started)
        return response

    @app.exception_handler(ProvenanceError)
    async def provenance_error(_: Request, exc: ProvenanceError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        return JSONResponse(
            status_code=exc.status,
            content={"error": exc.code, "error_description": exc.message},
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_request",
                "error_description": "request failed validation",
                "details": [
                    {"loc": list(e.get("loc", ())), "msg": str(e.get("msg", ""))}
                    for e in exc.errors()
                ],
            },
        )

    return app
