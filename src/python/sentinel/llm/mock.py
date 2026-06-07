"""Heuristic mock classifier — multi-signal scoring, no LLM required.

Used when Ollama is unavailable or for unit tests. Approximates real LLM
behaviour well enough to test the full enforcement pipeline.
"""
from __future__ import annotations

import logging

from sentinel.llm.base import BaseClassifier
from sentinel.models import ThreatDecision

logger = logging.getLogger(__name__)


class MockClassifier(BaseClassifier):

    def __init__(self, tier: str = "mock"):
        self._tier = tier

    @property
    def tier_name(self) -> str:
        return self._tier

    async def classify(self, ipg_text: str) -> ThreatDecision:
        t = ipg_text.lower()
        score = 0.0
        ttps: list[str] = []

        # Credential access (checks YAML res: fields and sensitive: true annotation)
        if any(p in t for p in ["/etc/shadow", "/etc/passwd", "/.ssh/",
                                  ".aws/credentials", "id_rsa", "ssl/private",
                                  "sensitive: true"]):
            score += 0.55
            ttps.append("T1003")

        # Execution from suspicious paths
        if any(p in t for p in ["/tmp/", "/dev/shm", ".hidden"]):
            score += 0.45
            ttps.append("T1059")

        # C2 / unusual outbound port (res: field carries raw ip:port in YAML)
        if any(p in t for p in [":4444", ":4443", ":1337", ":8888",
                                  ":9999", ":31337", "185.", "93.184", "104."]):
            score += 0.50
            ttps.append("T1071")

        # Multi-hop lateral movement
        if t.count("connect") >= 2:
            score += 0.25
            ttps.append("T1210")

        # Download + execute
        if "openat(w)" in t and "execve" in t and "rtype: net" in t:
            score += 0.45
            ttps.append("T1105")

        # Privilege escalation
        if "setuid" in t:
            score += 0.65
            ttps.append("T1068")

        # Process injection
        if "ptrace" in t:
            score += 0.70
            ttps.append("T1055")

        # Defense evasion
        if any(p in t for p in ["/var/log/", "auth.log", "cron.d", "crontab"]):
            score += 0.40
            ttps.append("T1562")

        # Data exfiltration
        if t.count("openat(r)") >= 2 and "connect" in t and "sensitive: true" in t:
            score += 0.45
            ttps.append("T1041")

        # Benign dampening
        if any(p in t for p in ["nginx", "postgres", "sshd", "apache", "systemd"]):
            if not any(p in t for p in ["/tmp/", "setuid", "ptrace",
                                         "sensitive: true", ":4444"]):
                score -= 0.30
        if any(p in t for p in ["apt", "dpkg", "yum", "pip"]):
            score -= 0.20

        score = max(0.0, min(score, 0.99))
        label = "MALICIOUS" if score >= 0.30 else "BENIGN"
        confidence = score if label == "MALICIOUS" else round(min(1.0 - score, 0.08), 2)
        ttps = list(dict.fromkeys(ttps))[:4]

        return ThreatDecision(
            label=label,
            confidence=round(confidence, 2),
            reasoning=(
                f"Mock[{self._tier}]: {len(ttps)} attack signal(s) detected."
                if ttps else
                f"Mock[{self._tier}]: behaviour matches known-benign pattern."
            ),
            mitre_ttps=ttps,
            model_used=f"mock/{self._tier}",
        )
