"""Three-agent zero-trust pipeline (Core Novelty 3 — Agentic Pipeline).

Agent separation of concerns:
  DetectorAgent  — fast gate: entropy + hard-triggers → DetectionSignal
  AnalyzerAgent  — reasoning: IPG + semantic + dual-tier LLM → AnalysisResult
  AuditorAgent   — verification + enforcement: EvidenceLinker + CWAE → EnforcementRecord

Each agent communicates via typed asyncio.Queue channels, enabling:
  1. Independent unit testing per agent
  2. Parallel execution of multiple Analyzer instances
  3. Clean audit trail: each stage's output is archived separately
  4. Future scaling: replace AsyncQueue with Redis Streams (Section VII-A)

Usage:
    pipeline = AgentPipeline.from_config(config)
    async with pipeline:
        await pipeline.push_event(kernel_event)
"""
from sentinel.agents.detector  import DetectorAgent,  DetectionSignal
from sentinel.agents.analyzer  import AnalyzerAgent,  AnalysisResult
from sentinel.agents.auditor   import AuditorAgent
from sentinel.agents.pipeline  import AgentPipeline

__all__ = [
    "DetectorAgent",  "DetectionSignal",
    "AnalyzerAgent",  "AnalysisResult",
    "AuditorAgent",
    "AgentPipeline",
]
