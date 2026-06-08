"""Provenance metadata for paper-grade evaluation results.

Every evaluation script must embed `make_meta()` in its output JSON so reviewers
can verify the result was produced on the intended platform with the intended
backend and no mock fallbacks. See docs/CLAUDE_VPS_OPERATOR_PROMPT.md.
"""
from __future__ import annotations

import os
import platform
import socket
import subprocess
import time
from typing import Any

_FALLBACK_COUNT = 0


def record_ollama_fallback() -> None:
    global _FALLBACK_COUNT
    _FALLBACK_COUNT += 1


def get_ollama_fallback_count() -> int:
    return _FALLBACK_COUNT


def _git_sha() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, timeout=5
        )
        return out.decode().strip()
    except Exception:
        return os.environ.get("SENTINEL_GIT_SHA", "unknown")


def _cpu_brief() -> str:
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or platform.machine()


def _ram_gb() -> float:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return round(int(line.split()[1]) / 1024 / 1024, 1)
    except Exception:
        pass
    return 0.0


def make_meta(
    *,
    backend: str | None = None,
    model_full: str | None = None,
    model_draft: str | None = None,
    timeout_seconds: int | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a provenance-meta dict for embedding in evaluation result JSONs.

    Honours SENTINEL_EVAL_PLATFORM env var as a human-readable platform label.
    All values are derived dynamically — no hardcoded host strings.
    """
    meta: dict[str, Any] = {
        "platform": os.environ.get(
            "SENTINEL_EVAL_PLATFORM",
            f"{platform.system()} {platform.release()} ({socket.gethostname()})",
        ),
        "system":      platform.system(),
        "kernel":      platform.release(),
        "machine":     platform.machine(),
        "hostname":    socket.gethostname(),
        "cpu":         _cpu_brief(),
        "ram_gb":      _ram_gb(),
        "python":      platform.python_version(),
        "backend":     backend
            or os.environ.get("SENTINEL__LLM__BACKEND", "unknown"),
        "model_full":  model_full
            or os.environ.get("SENTINEL__LLM__FULL_MODEL", "unknown"),
        "model_draft": model_draft
            or os.environ.get("SENTINEL__LLM__DRAFT_MODEL", "unknown"),
        "timeout_seconds": timeout_seconds
            or int(os.environ.get("SENTINEL__LLM__TIMEOUT_SECONDS", "0") or 0),
        "git_sha":     _git_sha(),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ollama_fallback_to_mock_count": get_ollama_fallback_count(),
    }
    if extra:
        meta.update(extra)
    return meta
