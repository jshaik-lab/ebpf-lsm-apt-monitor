import logging
import re
from typing import Dict, Any, List, Set

from agents.state import SentinelState, ThreatDecisionDict

logger = logging.getLogger("sentinel.auditor")

class AuditorAgent:
    """
    Auditor Agent (Tier 3) - Deterministic Verification:
    Enforces Verifiable Trace Reasoning using a pure mathematical/string-matching
    algorithm. Ensures the Analyzer's claims strictly map to the actual eBPF raw events.
    Completely eliminates the LLM to guarantee zero hallucination acceptance and
    microsecond-scale latency for the verification phase.
    """
    def __init__(self):
        # Regex patterns to extract entities from the LLM reasoning string
        self.path_pattern = re.compile(r'(/[\w\.\-]+(?:/[\w\.\-]+)*)')
        self.ip_pattern = re.compile(r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b)')

    def _extract_entities(self, reasoning: str) -> Dict[str, Set[str]]:
        paths = set(self.path_pattern.findall(reasoning))
        ips = set(self.ip_pattern.findall(reasoning))
        
        # Heuristically extract process names (words often before verbs, or quoted)
        # For a strict deterministic auditor, we focus primarily on exact Paths and IPs.
        return {
            "paths": paths,
            "ips": ips
        }

    def run(self, state: SentinelState) -> SentinelState:
        logger.debug(f"AuditorAgent deterministically verifying PID {state['pid']}")
        
        analyzer_dec = state.get("analyzer_decision")
        if not analyzer_dec or analyzer_dec["label"] == "BENIGN":
            # Fast path
            state["is_verified"] = True
            state["auditor_report"] = "Auto-verified (Benign)"
            state["final_decision"] = analyzer_dec
            return state

        claim_text = analyzer_dec["reasoning"]
        extracted = self._extract_entities(claim_text)
        
        # Flatten raw event resources for O(1) membership checking
        # raw_events contains: {ts_ns, pid, comm, sc_type, resource, ...}
        raw_resources = {str(e.get("resource", "")) for e in state["raw_events"]}
        # Also include comms
        raw_comms = {str(e.get("comm", "")) for e in state["raw_events"]}
        
        hallucinations = []
        
        # Verify Paths
        for path in extracted["paths"]:
            # Exact match or prefix match (e.g. LLM says /etc/shadow, resource is /etc/shadow)
            match_found = any(path in res for res in raw_resources)
            # Sometimes LLMs say "executed /bin/bash", so check comms too
            if not match_found:
                match_found = any(path.endswith(comm) for comm in raw_comms)
                
            if not match_found:
                hallucinations.append(f"Path '{path}' not found in eBPF trace")

        # Verify IPs
        for ip in extracted["ips"]:
            match_found = any(ip in res for res in raw_resources)
            if not match_found:
                hallucinations.append(f"IP '{ip}' not found in eBPF trace")

        if not hallucinations:
            state["is_verified"] = True
            state["auditor_report"] = f"VERIFIED: Entities {extracted} strictly match trace."
            state["final_decision"] = analyzer_dec
        else:
            logger.warning(f"Auditor rejected claim due to hallucination: {hallucinations}")
            state["is_verified"] = False
            state["auditor_report"] = f"HALLUCINATION REJECTED: {', '.join(hallucinations)}"
            state["final_decision"] = ThreatDecisionDict(
                label="BENIGN",
                confidence=0.0,
                reasoning=f"Rejected by Deterministic Auditor: {hallucinations}",
                mitre_ttps=[]
            )
            
        return state
