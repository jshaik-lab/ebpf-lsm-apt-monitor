from typing import Annotated, Any, Dict, List, TypedDict, Optional
import operator

class KernelEventDict(TypedDict):
    """Dictionary representation of a KernelEvent for the state."""
    ts_ns: int
    pid: int
    ppid: int
    uid: int
    comm: str
    sc_type: int
    resource: str
    flags: int
    net_port: int
    net_ip4: int

class ThreatDecisionDict(TypedDict):
    """Dictionary representation of a threat decision."""
    label: str
    confidence: float
    reasoning: str
    mitre_ttps: List[str]

class SentinelState(TypedDict):
    """LangGraph state for the SENTINEL agentic pipeline."""
    pid: int
    comm: str
    
    # Detector phase
    raw_events: List[KernelEventDict]
    ipg_text: str
    semantic_insights: List[str]
    
    # Analyzer phase
    analyzer_decision: Optional[ThreatDecisionDict]
    
    # Auditor phase
    auditor_report: Optional[str]
    is_verified: bool
    final_decision: Optional[ThreatDecisionDict]
