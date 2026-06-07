"""Shared test fixtures."""
import pytest

from sentinel.config import (
    SentinelConfig,
)
from sentinel.enforcement import CWAEEngine
from sentinel.ipg import IPGBuilder
from sentinel.models import KernelEvent, SyscallType


@pytest.fixture
def cfg() -> SentinelConfig:
    return SentinelConfig.defaults()


@pytest.fixture
def ipg() -> IPGBuilder:
    return IPGBuilder()


@pytest.fixture
def attack_window() -> list[KernelEvent]:
    """Credential dump + C2 scenario (T1003 + T1071)."""
    def e(ms, pid, comm, sc, res):
        return KernelEvent(
            ts_ns=ms * 1_000_000, pid=pid, ppid=pid - 1, uid=1000,
            comm=comm, sc_type=int(sc), resource=res,
        )
    E = SyscallType
    return [
        e(0,   1234, "bash", E.EXEC,    "/bin/bash"),
        e(2,   1234, "bash", E.EXEC,    "/usr/bin/cat"),
        e(3,   1234, "cat",  E.FILE_R,  "/etc/shadow"),
        e(4,   1234, "cat",  E.FILE_R,  "/etc/passwd"),
        e(90,  1234, "bash", E.NET_CON, "104.21.43.12:4444"),
        e(95,  1234, "bash", E.EXEC,    "/tmp/sh"),
    ]


@pytest.fixture
def benign_window() -> list[KernelEvent]:
    """Normal nginx web-server trace."""
    def e(ms, pid, comm, sc, res):
        return KernelEvent(
            ts_ns=ms * 1_000_000, pid=pid, ppid=pid - 1, uid=33,
            comm=comm, sc_type=int(sc), resource=res,
        )
    E = SyscallType
    return [
        e(0, 8000, "nginx", E.NET_LIS, "0.0.0.0:80"),
        e(1, 8000, "nginx", E.FILE_R,  "/var/www/html/index.html"),
        e(2, 8000, "nginx", E.FILE_R,  "/var/www/html/style.css"),
        e(3, 8000, "nginx", E.FILE_W,  "/var/log/nginx/access.log"),
        e(4, 8000, "nginx", E.NET_LIS, "0.0.0.0:443"),
        e(5, 8000, "nginx", E.FILE_R,  "/var/www/html/app.js"),
    ]


@pytest.fixture
def cwae(tmp_path) -> CWAEEngine:
    return CWAEEngine(
        audit_log_path=str(tmp_path / "audit.jsonl"),
        incident_log_path=str(tmp_path / "incidents.jsonl"),
        dry_run=True,
    )
