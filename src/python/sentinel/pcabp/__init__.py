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
"""
from sentinel.pcabp.call_site_map import ValidCallSiteMap
from sentinel.pcabp.behavioral_encoder import BehavioralEncoder, PCAPBScore

__all__ = ["ValidCallSiteMap", "BehavioralEncoder", "PCAPBScore"]
