"""PCABP — Program-Counter-Aware Behavioral Provenance.

Solves the Nginx Mimicry problem: syscalls issued by heap/stack-injected
shellcode vs. the same syscalls issued by the nginx binary's own .text section
are behaviourally identical at the syscall-sequence level but distinguishable
by WHERE in the address space the CALL instruction originated.

Pipeline (integrated into the main SENTINEL stages):

  Stage 1 (DetectorAgent): ValidCallSiteMap.check(event.ip)
    → static_violation=True if IP not in nginx .text call-site bloom filter
    → triggers "pcabp_static_violation" immediately (bypasses entropy gate)

  Stage 2 (AnalyzerAgent): BehavioralEncoder.score(window)
    → ai_divergence ∈ [0, 1]: embedding distance from in-binary centroid

  Stage 3 (CWAEEngine): consensus scoring
    → pcabp_score = 0.4 * static_violation + 0.6 * ai_divergence
    → effective_confidence = max(llm_confidence, pcabp_score)
    → enforcement tier derived from effective_confidence (Algorithm 3)

BehavioralEncoder (PyTorch) is imported lazily so bloom-filter rebuild and
static-only paths work without torch installed.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from sentinel.pcabp.call_site_map import ValidCallSiteMap

__all__ = ["ValidCallSiteMap", "BehavioralEncoder", "PCAPBScore"]

if TYPE_CHECKING:
    from sentinel.pcabp.behavioral_encoder import BehavioralEncoder, PCAPBScore


def __getattr__(name: str):
    if name in ("BehavioralEncoder", "PCAPBScore"):
        from sentinel.pcabp.behavioral_encoder import BehavioralEncoder, PCAPBScore
        return BehavioralEncoder if name == "BehavioralEncoder" else PCAPBScore
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
