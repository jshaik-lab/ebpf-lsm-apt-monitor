"""AgentPipeline — wires the three agents into a running async system.

Architecture:
  EventSource ──(KernelEvent)──▶ DetectorAgent
                                      │
                              (DetectionSignal)
                                      │
                                      ▼
                               AnalyzerAgent ──▶ (runs N concurrent tasks)
                                      │
                              (AnalysisResult)
                                      │
                                      ▼
                                AuditorAgent ──▶ audit.jsonl + CWAEEngine

The pipeline exposes a single push_event(event) coroutine as its public API.
Internally it starts three asyncio Tasks and connects them via bounded queues.

Queue depths are bounded to provide back-pressure:
  detector→analyzer: max 500  (burst buffer for LLM latency)
  analyzer→auditor:  max 200  (auditor is fast — flush-or-drop semantics)
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Callable, Optional

import structlog

from sentinel.agents.auditor  import AuditorAgent
from sentinel.agents.analyzer import AnalyzerAgent
from sentinel.agents.detector import DetectorAgent
from sentinel.config import SentinelConfig
from sentinel.enforcement import CWAEEngine
from sentinel.llm import make_classifier
from sentinel.llm.base import DualTierClassifier
from sentinel.models import KernelEvent

logger = structlog.get_logger(__name__)

# PCABP bloom-filter paths searched at pipeline startup (first hit wins).
_PCABP_CANDIDATES = (
    "src/python/sentinel/pcabp/nginx_callsites_x86_64_gcp.pkl",
    "src/python/sentinel/pcabp/nginx_callsites_x86_64_ionos.pkl",
    "src/python/sentinel/pcabp/nginx_callsites.pkl",
)


def _load_call_site_map() -> "Optional[object]":
    try:
        from sentinel.pcabp.call_site_map import ValidCallSiteMap
    except ImportError:
        return None
    root = Path(__file__).resolve()
    for parent in root.parents:
        if (parent / "config" / "sentinel.yaml").is_file():
            root = parent
            break
    else:
        root = Path(__file__).resolve().parents[4]
    for rel in _PCABP_CANDIDATES:
        p = root / rel
        if p.is_file():
            logger.info("pcabp_call_site_map_loaded", path=str(p))
            return ValidCallSiteMap.load(str(p))
    return None


def _load_behavioral_encoder() -> "Optional[object]":
    try:
        from sentinel.pcabp.behavioral_encoder import BehavioralEncoder
        return BehavioralEncoder()
    except Exception:
        return None


def _load_egte(config: SentinelConfig) -> "Optional[object]":
    if not config.egte.enabled:
        return None
    try:
        from sentinel.egte import EGTEEngine, TierCalibrator
        cal = TierCalibrator(alpha=config.egte.alpha)
        return EGTEEngine(
            calibrator=cal,
            cove_hal_threshold=config.egte.cove_hal_threshold,
        )
    except Exception as exc:
        logger.warning("egte_load_failed", error=str(exc))
        return None


class AgentPipeline:
    """Manages lifecycle of all three agents."""

    def __init__(
        self,
        detector:  DetectorAgent,
        analyzer:  AnalyzerAgent,
        auditor:   AuditorAgent,
        det_queue: asyncio.Queue,
        ana_queue: asyncio.Queue,
    ):
        self._detector  = detector
        self._analyzer  = analyzer
        self._auditor   = auditor
        self._det_queue = det_queue
        self._ana_queue = ana_queue
        self._tasks: list[asyncio.Task] = []

    @classmethod
    def from_config(
        cls,
        config:           SentinelConfig,
        classifier:       Optional[DualTierClassifier] = None,
        enforce_map_fd:   int = -1,
        xdp_fd:           int = -1,
        on_audit_entry:   Optional[Callable[[dict], None]] = None,
    ) -> "AgentPipeline":
        det_queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        ana_queue: asyncio.Queue = asyncio.Queue(maxsize=200)

        clf = classifier or make_classifier(config.llm)
        cwae = CWAEEngine(
            enforce_map_fd=enforce_map_fd,
            xdp_quarantine_fd=xdp_fd,
            audit_log_path=config.enforcement.audit_log,
            incident_log_path=config.enforcement.incident_log,
            dry_run=config.enforcement.dry_run,
        )

        csm = _load_call_site_map()
        encoder = _load_behavioral_encoder() if csm is not None else None

        detector = DetectorAgent(
            out_queue=det_queue,
            window_size=config.processing.syscall_window_size,
            entropy_low=config.processing.entropy.low_threshold,
            entropy_high=config.processing.entropy.high_threshold,
            entropy_window=config.processing.entropy.window_size,
            call_site_map=csm,
        )
        analyzer = AnalyzerAgent(
            in_queue=det_queue,
            out_queue=ana_queue,
            classifier=clf,
            max_concurrent_llm=config.processing.max_concurrent_llm,
            call_site_map=csm,
            behavioral_encoder=encoder,
        )
        auditor = AuditorAgent(
            in_queue=ana_queue,
            cwae=cwae,
            audit_log_path=config.enforcement.audit_log,
            incident_path=config.enforcement.incident_log,
            flag_pid_cb=detector.flag_pid,
            on_audit_entry=on_audit_entry,
            egte=_load_egte(config),
        )
        return cls(detector, analyzer, auditor, det_queue, ana_queue)

    async def __aenter__(self) -> "AgentPipeline":
        self._tasks = [
            asyncio.create_task(self._analyzer.run(), name="analyzer"),
            asyncio.create_task(self._auditor.run(),  name="auditor"),
        ]
        logger.info("agent_pipeline_started", tasks=[t.get_name() for t in self._tasks])
        return self

    async def __aexit__(self, *_) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("agent_pipeline_stopped")

    async def push_event(self, event: KernelEvent) -> None:
        """Public entry point — call for every kernel event."""
        await self._detector.handle(event)

    def stats(self) -> dict:
        return {
            "detector":  self._detector.stats,
            "analyzer":  self._analyzer.stats,
            "auditor":   self._auditor.stats,
            "classifier": getattr(self._analyzer._clf, "stats", {}),
            "queue_depths": {
                "detector_out": self._det_queue.qsize(),
                "analyzer_out": self._ana_queue.qsize(),
            },
        }
