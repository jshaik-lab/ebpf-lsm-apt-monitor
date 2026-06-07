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
from typing import Optional

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

        detector = DetectorAgent(
            out_queue=det_queue,
            window_size=config.processing.syscall_window_size,
            entropy_low=config.processing.entropy.low_threshold,
            entropy_high=config.processing.entropy.high_threshold,
            entropy_window=config.processing.entropy.window_size,
        )
        analyzer = AnalyzerAgent(
            in_queue=det_queue,
            out_queue=ana_queue,
            classifier=clf,
            max_concurrent_llm=config.processing.max_concurrent_llm,
        )
        auditor = AuditorAgent(
            in_queue=ana_queue,
            cwae=cwae,
            audit_log_path=config.enforcement.audit_log,
            incident_path=config.enforcement.incident_log,
            flag_pid_cb=detector.flag_pid,
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
            "queue_depths": {
                "detector_out": self._det_queue.qsize(),
                "analyzer_out": self._ana_queue.qsize(),
            },
        }
