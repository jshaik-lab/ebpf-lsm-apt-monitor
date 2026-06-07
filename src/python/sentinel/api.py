"""FastAPI status and health API — exposes /health /status /decisions endpoints."""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(title="SENTINEL", version="1.0.0", docs_url="/docs")

_start_time: float = time.time()
_agent_ref: Optional[Any] = None


def register_agent(agent: Any) -> None:
    """Called by SentinelAgent at startup to wire in stats callbacks."""
    global _agent_ref
    _agent_ref = agent


@app.get("/health")
async def health() -> Dict:
    return {
        "status": "ok",
        "uptime_s": round(time.time() - _start_time),
        "mode": _agent_ref.config.mode if _agent_ref else "starting",
        "version": "1.0.0",
    }


@app.get("/status")
async def status() -> Dict:
    if _agent_ref is None:
        return {"error": "agent not yet initialized"}
    return _agent_ref.get_stats()


@app.get("/decisions")
async def decisions(limit: int = 100) -> List[Dict]:
    if _agent_ref is None:
        return []
    return _agent_ref.get_recent_decisions(limit)


@app.get("/ready")
async def ready() -> JSONResponse:
    """Kubernetes-style readiness probe."""
    if _agent_ref is None or not _agent_ref.is_running:
        return JSONResponse({"ready": False}, status_code=503)
    return JSONResponse({"ready": True})
