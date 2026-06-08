"""Ollama HTTP backend — async, with structured JSON output and retry logic."""
from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Dict, List

import httpx
import structlog

from sentinel.llm.base import BaseClassifier
from sentinel.models import ThreatDecision

logger = structlog.get_logger(__name__)

SYSTEM_PROMPT = """You are an expert kernel security analyst with deep knowledge
of Linux syscall semantics, MITRE ATT&CK tactics, and advanced persistent threats.

You will receive an Intent Provenance Graph (IPG) in YAML format describing the
recent system-call behaviour of one or more processes on a Linux host.
- Each node is a (process comm, resource-type) pair: EXEC, FILE, NET, MEM, SYS, LLM.
- Each directed edge is a system call with a time delta (dt_ms).
- Edges marked sensitive:true access security-critical files (/etc/shadow, SSH keys, etc.).
- The res: field contains the file path or ip:port involved.
- Edges with syscall:tls_read carry an intent: field with intercepted LLM API plaintext.
- The meta: block may contain additional behavioral signals — these fields ONLY appear
  when positive (they are omitted entirely when neutral/zero). Their presence raises
  suspicion; their absence means the signal was not detected but is NOT exonerating.
  Always reason from the raw syscall pattern in Steps 1-4 first:
    outbound_ext: N    (if present) N connect edges to non-RFC-1918 routable IPs detected.
                       On a server daemon (nginx, apache) this is a HIGH suspicion signal —
                       legitimate reverse-proxies use RFC-1918 upstreams only.
    exec_after_net: true  (if present) execve edge followed a connect edge — strengthens
                          web-shell dropper hypothesis (T1190→T1105→T1059).
    unusual_comm: true    (if present) non-standard process name detected (possible T1036).
- Edges marked anomaly: ext_outbound are connect syscalls to routable external IPs.
  For server processes (nginx, apache) this is a HIGH supplemental suspicion signal.

Reason step-by-step before deciding:
  Step 1 — identify each process and its resource interactions.
  Step 2 — trace causal chains: which edges precede which?
  Step 3 — match edge patterns to MITRE ATT&CK techniques.
  Step 4 — weigh whether the combined pattern is benign or malicious.
  Step 5 — assign a calibrated confidence (avoid defaulting to extremes).

Respond ONLY with valid JSON matching this exact schema (no markdown, no prose):
{
  "chain_of_thought": "<steps 1-4 in 3-5 sentences>",
  "label": "BENIGN"|"MALICIOUS",
  "confidence": 0.0-1.0,
  "reasoning": "<one sentence citing specific edges and why they are/are not malicious>",
  "mitre_ttps": [...],
  "evidence_refs": [
    {
      "event_desc": "<exact syscall + resource from the graph, e.g. 'openat(R) /etc/shadow'>",
      "supports": "<TTP ID or BENIGN>",
      "confidence_contribution": 0.0
    }
  ]
}
CRITICAL: evidence_refs must ONLY cite edges that ACTUALLY APPEAR in the graph above.
Do not invent resources or syscalls not present in the IPG. Each evidence_ref
confidence_contribution should sum to approximately the overall confidence."""

FEW_SHOT_EXAMPLES: List[Dict[str, Any]] = [
    {
        "graph": (
            "# Intent Provenance Graph -- SENTINEL v1.0\n"
            "meta: {nodes: 3, edges: 4, outbound_ext: 1, exec_after_net: true}\n"
            "nodes:\n"
            "  - {id: n0, comm: bash, rtype: EXEC}\n"
            "  - {id: n1, comm: cat,  rtype: FILE}\n"
            "  - {id: n2, comm: bash, rtype: NET}\n"
            "edges:\n"
            "  - {src: n0, dst: n1, syscall: openat(R), dt_ms: 1.0, res: /etc/shadow, sensitive: true}\n"
            "  - {src: n1, dst: n1, syscall: openat(R), dt_ms: 1.0, res: /etc/passwd, sensitive: true}\n"
            "  - {src: n1, dst: n2, syscall: connect,   dt_ms: 86.0, res: 93.184.216.34:4444, anomaly: ext_outbound}\n"
            "  - {src: n2, dst: n0, syscall: execve,    dt_ms: 3.0,  res: /tmp/sh, sensitive: true}\n"
            "procs: [bash, cat]"
        ),
        "decision": {
            "chain_of_thought": "Step 1: bash and cat interact with /etc/shadow and /etc/passwd (sensitive credential files). Step 2: cat reads credentials, then bash connects outbound to 93.184.216.34:4444 (external routable IP, anomaly: ext_outbound — outbound_ext:1 in meta confirms), then executes /tmp/sh (world-writable temp dir). Step 3: openat(R) on /etc/shadow matches T1003; connect to external :4444 matches T1071 C2; execve from /tmp matches T1059 staged payload. Step 4: the causal chain credential-access → C2 → execution is a textbook APT kill-chain.",
            "label": "MALICIOUS",
            "confidence": 0.97,
            "reasoning": "bash reads /etc/shadow and /etc/passwd (T1003), connects to external 93.184.216.34:4444 (T1071 C2, ext_outbound), then executes /tmp/sh (T1059) — a complete credential-dump-to-C2 kill-chain.",
            "mitre_ttps": ["T1003", "T1071", "T1059"],
        },
    },
    {
        "graph": (
            "# Intent Provenance Graph -- SENTINEL v1.0\n"
            "meta: {nodes: 2, edges: 3}\n"
            "nodes:\n"
            "  - {id: n0, comm: nginx, rtype: NET}\n"
            "  - {id: n1, comm: nginx, rtype: FILE}\n"
            "edges:\n"
            "  - {src: n0, dst: n1, syscall: openat(R), dt_ms: 0.5, res: /var/www/html/index.html}\n"
            "  - {src: n0, dst: n0, syscall: listen,    dt_ms: 1.0}\n"
            "  - {src: n1, dst: n1, syscall: openat(W), dt_ms: 0.3, res: /var/log/nginx/access.log}\n"
            "procs: [nginx]"
        ),
        "decision": {
            "chain_of_thought": "Step 1: only nginx processes appear; all file access is under /var/www/html (web root) and /var/log/nginx. Step 2: the edge sequence is listen → serve static file → write access log — a deterministic web-serving loop. Step 3: no sensitive files, no suspicious ports, no execve from temp dirs. Step 4: all edges are consistent with normal nginx operation.",
            "label": "BENIGN",
            "confidence": 0.04,
            "reasoning": "nginx reads only from web-root and writes to its own access log — normal web-server behaviour with no suspicious edges.",
            "mitre_ttps": [],
            "evidence_refs": [
                {"event_desc": "openat(R) /var/www/html/index.html", "supports": "BENIGN", "confidence_contribution": 0.04},
            ],
        },
    },
]


class OllamaClassifier(BaseClassifier):
    """Sends IPG text to Ollama and parses the structured JSON response."""

    def __init__(
        self,
        base_url:         str,
        model:            str,
        timeout:          int = 30,
        max_retries:      int = 3,
        tier:             str = "ollama",
        extra_context:    str = "",
        extra_examples:   List[Dict[str, Any]] | None = None,
    ):
        self._url          = base_url.rstrip("/")
        self._model        = model
        self._timeout      = timeout
        self._retries      = max_retries
        self._tier         = tier
        # Allow callers (e.g. evaluate_darpa_tc.py) to inject domain context
        self._system_prompt = (extra_context + "\n\n" + SYSTEM_PROMPT).strip() \
            if extra_context else SYSTEM_PROMPT
        self._examples     = list(FEW_SHOT_EXAMPLES) + (extra_examples or [])

    @property
    def tier_name(self) -> str:
        return self._tier

    async def classify(self, ipg_text: str) -> ThreatDecision:
        payload = {
            "model": self._model,
            "messages": self._build_messages(ipg_text),
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.0, "top_p": 0.9},
        }
        t0 = time.perf_counter()

        for attempt in range(self._retries):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(f"{self._url}/api/chat", json=payload)
                    resp.raise_for_status()
                    raw  = resp.json()["message"]["content"]
                    data = json.loads(raw)
                    latency_ms = (time.perf_counter() - t0) * 1000
                    logger.debug("ollama_inference", model=self._model, latency_ms=round(latency_ms, 1))
                    decision = ThreatDecision(
                        label=data.get("label", "BENIGN"),
                        confidence=float(data.get("confidence", 0.0)),
                        reasoning=data.get("reasoning", ""),
                        mitre_ttps=data.get("mitre_ttps", []),
                        chain_of_thought=data.get("chain_of_thought", ""),
                        model_used=self._model,
                        latency_ms=latency_ms,
                    )
                    # Attach structured evidence refs (Core Novelty 1)
                    decision.evidence_refs = data.get("evidence_refs", [])
                    return decision
            except Exception as exc:
                wait = 2 ** attempt
                logger.warning(
                    "ollama_retry",
                    model=self._model,
                    attempt=attempt + 1,
                    max_retries=self._retries,
                    error=str(exc),
                    retry_in_s=wait,
                )
                if attempt < self._retries - 1:
                    await asyncio.sleep(wait)

        logger.error("ollama_classify_failed", model=self._model, attempts=self._retries)
        allow_mock = os.environ.get("SENTINEL__LLM__ALLOW_MOCK_FALLBACK", "").lower() in (
            "1", "true", "yes",
        )
        if not allow_mock:
            raise RuntimeError(
                f"Ollama classify failed after {self._retries} attempts "
                f"(model={self._model}); mock fallback is disabled for paper evals. "
                "Set SENTINEL__LLM__ALLOW_MOCK_FALLBACK=1 only for local dev."
            )
        from sentinel.llm.mock import MockClassifier
        from sentinel.provenance import record_ollama_fallback
        record_ollama_fallback()
        return await MockClassifier(tier=f"mock/{self._tier}").classify(ipg_text)

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp  = await client.get(f"{self._url}/api/tags")
                models = [m["name"] for m in resp.json().get("models", [])]
                return any(self._model in m for m in models)
        except Exception:
            return False

    def _build_messages(self, ipg_text: str) -> List[Dict]:
        messages: List[Dict] = [{"role": "system", "content": self._system_prompt}]
        for ex in self._examples:
            messages.append({"role": "user",      "content": f"Graph:\n{ex['graph']}"})
            messages.append({"role": "assistant", "content": json.dumps(ex["decision"])})
        messages.append({"role": "user", "content": f"Graph:\n{ipg_text}"})
        return messages
