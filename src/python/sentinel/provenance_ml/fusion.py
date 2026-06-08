"""Score Fusion Engine (Algorithm 4) for SENTINEL Option A."""
from __future__ import annotations


def fuse_scores(
    graph_score: float,
    llm_label: str,
    llm_conf: float,
    ltl_severity: float,
    pcabp_score: float = 0.0,
    cove_cap: float | None = None,
) -> tuple[str, float]:
    """Fuse scores from multiple detection axes (Algorithm 4).
    
    Combines:
      - graph_score (deterministic/GBDT)
      - llm_label / llm_conf (LLM explanation/attribution)
      - ltl_severity (safety monitor floors)
      - pcabp_score (stack tracing stack violation/behavioral divergence)
      - cove_cap (CoVe grounding limits)
      
    Returns (fused_label, fused_confidence).
    """
    effective = max(graph_score, pcabp_score)

    # 1. safety axiom floor from LTL SymbolicGuardian
    if ltl_severity >= 0.7:
        effective = max(effective, ltl_severity)

    # 2. LLM consensus escalation
    if llm_label == "MALICIOUS":
        effective = max(effective, llm_conf)

    # 3. CoVe grounding cap
    if cove_cap is not None:
        effective = min(effective, cove_cap)

    label = "MALICIOUS" if effective >= 0.50 else "BENIGN"
    return label, effective
