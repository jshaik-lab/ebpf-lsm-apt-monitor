import logging
from langgraph.graph import StateGraph, END
from typing import TypedDict, Dict, Any, List

from agents.state import SentinelState, KernelEventDict
from agents.detector import DetectorAgent
from agents.analyzer import AnalyzerAgent
from agents.auditor import AuditorAgent

logger = logging.getLogger("sentinel.pipeline")

class SentinelPipeline:
    """
    Assembles the Detector, Analyzer, and Auditor into a LangGraph state machine.
    """
    def __init__(self, ollama_url: str = "http://localhost:11434/api/generate", model_name: str = "llama3.1"):
        self.detector = DetectorAgent()
        self.analyzer = AnalyzerAgent(model_name=model_name, url=ollama_url)
        self.auditor = AuditorAgent(model_name=model_name, url=ollama_url)
        
        # Build graph
        workflow = StateGraph(SentinelState)
        
        workflow.add_node("detector", self.detector.run)
        workflow.add_node("analyzer", self.analyzer.run)
        workflow.add_node("auditor", self.auditor.run)
        
        workflow.set_entry_point("detector")
        
        # Detector -> Analyzer -> Auditor -> END
        workflow.add_edge("detector", "analyzer")
        workflow.add_edge("analyzer", "auditor")
        workflow.add_edge("auditor", END)
        
        self.app = workflow.compile()

    def invoke(self, pid: int, comm: str, raw_events: List[Dict[str, Any]]) -> SentinelState:
        """Runs the agentic pipeline on a window of kernel events."""
        initial_state = SentinelState(
            pid=pid,
            comm=comm,
            raw_events=raw_events,
            ipg_text="",
            semantic_insights=[],
            analyzer_decision=None,
            auditor_report=None,
            is_verified=False,
            final_decision=None
        )
        
        logger.debug(f"Invoking pipeline for PID {pid}")
        try:
            result = self.app.invoke(initial_state)
            return result
        except Exception as e:
            logger.error(f"Pipeline execution failed: {e}")
            raise
