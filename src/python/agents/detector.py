import logging
from typing import List, Dict

# Assumes ipg_encoder is in the parent directory
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipg_encoder import IPGBuilder, KernelEvent, SyscallType, ResourceType
from agents.state import SentinelState

logger = logging.getLogger("sentinel.detector")

class DetectorAgent:
    """
    Detector Agent (Tier 1):
    Ingests raw eBPF events, constructs the Intent Provenance Graph (IPG),
    and extracts basic semantic insights (e.g., suspicious paths, credential access).
    """
    def __init__(self):
        self.ipg_builder = IPGBuilder()

    def _generate_semantic_insights(self, ipg_text: str, events: List[KernelEvent]) -> List[str]:
        insights = []
        t = ipg_text.lower()
        
        # High-level security mappings
        if any(p in t for p in ["/etc/shadow", "/etc/passwd", ".ssh", "id_rsa"]):
            insights.append("Credential Access: Attempted read of sensitive system files.")
            
        if any(p in t for p in ["/tmp/", "/dev/shm", "/var/tmp"]):
            if "execve" in t:
                insights.append("Execution: Suspicious execution from world-writable temporary directory.")
                
        if t.count("connect") > 0:
            if "execve" in t:
                insights.append("C2/Lateral Movement: Process made network connection and executed a command.")
                
        if "setuid" in t:
            insights.append("Privilege Escalation: Process attempted to change user identity (setuid).")
            
        if "ptrace" in t:
            insights.append("Defense Evasion/Process Injection: Process used ptrace on another process.")
            
        return insights

    def run(self, state: SentinelState) -> SentinelState:
        logger.debug(f"DetectorAgent analyzing {len(state['raw_events'])} events for PID {state['pid']}")
        
        # Convert dicts back to KernelEvent objects
        events = [KernelEvent(**e) for e in state["raw_events"]]
        
        # Build IPG
        G = self.ipg_builder.build(events)
        ipg_text = self.ipg_builder.serialize(G)
        
        # Generate Insights
        insights = self._generate_semantic_insights(ipg_text, events)
        
        # Update State
        state["ipg_text"] = ipg_text
        state["semantic_insights"] = insights
        
        return state
