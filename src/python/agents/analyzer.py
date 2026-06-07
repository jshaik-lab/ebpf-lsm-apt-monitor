import json
import logging
import requests
from typing import Dict, Any

from agents.state import SentinelState, ThreatDecisionDict

logger = logging.getLogger("sentinel.analyzer")

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.1" # Target model on the Hetzner server

SYSTEM_PROMPT = """You are an expert kernel security analyst with deep knowledge of Linux syscall semantics and advanced persistent threats.
You are given a Behavioral Graph (Intent Provenance Graph) of recent kernel actions and some semantic insights extracted by a detector.

Task:
1. Classify the behavior as BENIGN or MALICIOUS.
2. Assign a confidence score (0.0 to 1.0).
3. Provide a brief reasoning.
4. List applicable MITRE ATT&CK TTP IDs.

Output valid JSON strictly adhering to this format:
{"label": "BENIGN" | "MALICIOUS", "confidence": 0.95, "reasoning": "...", "mitre_ttps": ["T1003", ...]}
"""

class AnalyzerAgent:
    """
    Analyzer Agent (Tier 2):
    Ingests the IPG and semantic insights. Uses a local Ollama model to
    perform deep reasoning and assign a threat classification.
    """
    def __init__(self, model_name: str = MODEL_NAME, url: str = OLLAMA_URL):
        self.model_name = model_name
        self.url = url

    def run(self, state: SentinelState) -> SentinelState:
        logger.debug(f"AnalyzerAgent inspecting PID {state['pid']}")
        
        prompt = f"Graph:\n{state['ipg_text']}\n\nSemantic Insights:\n"
        prompt += "\n".join(f"- {s}" for s in state['semantic_insights']) if state['semantic_insights'] else "- None"
        
        payload = {
            "model": self.model_name,
            "system": SYSTEM_PROMPT,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.0,
                "top_p": 0.9
            }
        }
        
        try:
            resp = requests.post(self.url, json=payload, timeout=60)
            resp.raise_for_status()
            result = resp.json()["response"]
            data = json.loads(result)
            
            state["analyzer_decision"] = ThreatDecisionDict(
                label=data.get("label", "BENIGN"),
                confidence=float(data.get("confidence", 0.0)),
                reasoning=data.get("reasoning", "Parse fallback"),
                mitre_ttps=data.get("mitre_ttps", [])
            )
        except Exception as e:
            logger.error(f"AnalyzerAgent Ollama inference failed: {e}")
            # Fallback
            state["analyzer_decision"] = ThreatDecisionDict(
                label="BENIGN", confidence=0.0,
                reasoning=f"Inference error: {e}", mitre_ttps=[]
            )
            
        return state
