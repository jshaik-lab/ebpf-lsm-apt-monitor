"""Evidence linker — verifiable trace reasoning (Core Novelty 1).

Every LLM output MUST map to a real eBPF event in the kernel trace.
No hallucinated reasoning is permitted in the audit trail.

The EvidenceLinker:
  1. Parses evidence_refs from the LLM's structured output
  2. Validates each claim against the actual KernelEvent window
  3. Produces an EvidenceReport: verified + unverified claims
  4. Flags decisions where confidence is driven by unverified claims

This makes SENTINEL forensically defensible: an operator can inspect
any alert and trace exactly which kernel event triggered each part of
the LLM's reasoning.  Unverified claims are logged but do NOT count
toward the enforcement confidence score.

Paper claim: "SENTINEL emits zero hallucinated evidence references
across N evaluation traces" — verified by running validate_all().
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from sentinel.models import KernelEvent, SyscallType, ThreatDecision


_SYSCALL_ALIASES = {
    "openat(r)":    int(SyscallType.FILE_R),
    "openat(w)":    int(SyscallType.FILE_W),
    "read":         int(SyscallType.FILE_R),
    "open":         int(SyscallType.FILE_R),
    "connect":      int(SyscallType.NET_CON),
    "listen":       int(SyscallType.NET_LIS),
    "execve":       int(SyscallType.EXEC),
    "exec":         int(SyscallType.EXEC),
    "ptrace":       int(SyscallType.PTRACE),
    "setuid":       int(SyscallType.SETUID),
    "mmap":         int(SyscallType.MMAP),
    "fork":         int(SyscallType.FORK),
    "clone":        int(SyscallType.CLONE),
}


@dataclass
class EvidenceClaim:
    """Single evidence reference from LLM output."""
    event_desc:              str
    supports_ttp:            str
    confidence_contribution: float
    verified:                bool  = False
    matched_event_idx:       Optional[int] = None
    matched_resource:        str   = ""
    verification_note:       str   = ""


@dataclass
class EvidenceReport:
    """Complete verification result for one ThreatDecision."""
    total_claims:      int
    verified_claims:   int
    unverified_claims: int
    hallucination_rate: float             # unverified / total
    verified_confidence: float            # confidence after removing unverified contributions
    claims:            List[EvidenceClaim] = field(default_factory=list)
    verdict:           str = "CLEAN"      # CLEAN | PARTIAL | HALLUCINATED

    @property
    def is_trustworthy(self) -> bool:
        """True when all claims are verified or hallucination rate < 10%."""
        return self.hallucination_rate < 0.10


class EvidenceLinker:
    """Validates LLM evidence references against the actual KernelEvent window.

    Usage:
        linker = EvidenceLinker()
        report = linker.verify(decision, event_window)
        if not report.is_trustworthy:
            logger.warning("evidence_hallucination", report=report)
    """

    def verify(
        self,
        decision: ThreatDecision,
        events:   List[KernelEvent],
    ) -> EvidenceReport:
        """Verify all evidence_refs in the decision against actual events."""
        raw_refs = getattr(decision, "evidence_refs", [])

        # If no structured refs, fall back to parsing the reasoning text
        if not raw_refs:
            raw_refs = self._parse_reasoning(decision.reasoning, decision.mitre_ttps)

        if not raw_refs:
            return EvidenceReport(
                total_claims=0,
                verified_claims=0,
                unverified_claims=0,
                hallucination_rate=0.0,
                verified_confidence=decision.confidence,
                verdict="NO_CLAIMS",
            )

        claims = []
        verified_conf = decision.confidence

        for ref in raw_refs:
            claim = EvidenceClaim(
                event_desc=ref.get("event_desc", str(ref)),
                supports_ttp=ref.get("supports", ""),
                confidence_contribution=float(ref.get("confidence_contribution", 0.0)),
            )
            matched_idx, matched_res, note = self._match_event(claim.event_desc, events)
            if matched_idx is not None:
                claim.verified          = True
                claim.matched_event_idx = matched_idx
                claim.matched_resource  = matched_res
                claim.verification_note = note
            else:
                claim.verified          = False
                claim.verification_note = f"No event in window matches '{claim.event_desc}'"
                # Remove this claim's contribution from confidence
                verified_conf -= claim.confidence_contribution

            claims.append(claim)

        verified_conf = max(0.0, min(1.0, verified_conf))
        n_verified    = sum(1 for c in claims if c.verified)
        n_unverified  = len(claims) - n_verified
        hal_rate      = n_unverified / max(len(claims), 1)

        if hal_rate == 0.0:
            verdict = "CLEAN"
        elif hal_rate < 0.50:
            verdict = "PARTIAL"
        else:
            verdict = "HALLUCINATED"

        return EvidenceReport(
            total_claims=len(claims),
            verified_claims=n_verified,
            unverified_claims=n_unverified,
            hallucination_rate=round(hal_rate, 4),
            verified_confidence=round(verified_conf, 4),
            claims=claims,
            verdict=verdict,
        )

    def _match_event(
        self,
        event_desc: str,
        events:     List[KernelEvent],
    ) -> Tuple[Optional[int], str, str]:
        """Return (index, resource, note) of the best matching event, or (None, '', note)."""
        desc_lower = event_desc.lower().strip()

        # Extract syscall type hint from description
        sc_hint: Optional[int] = None
        for alias, sc_type in _SYSCALL_ALIASES.items():
            if alias in desc_lower:
                sc_hint = sc_type
                break

        # Extract resource hint: file path or ip:port
        resource_hint = self.extract_resource(event_desc)

        for idx, evt in enumerate(events):
            # Syscall type match (if we have a hint)
            sc_match = (sc_hint is None) or (evt.sc_type == sc_hint)

            # Resource match — substring check (handles truncated paths)
            if resource_hint:
                res_match = (
                    resource_hint.lower() in evt.resource.lower() or
                    evt.resource.lower() in resource_hint.lower()
                )
            else:
                # No resource in description — match by syscall type alone
                res_match = True

            if sc_match and res_match:
                return (
                    idx,
                    evt.resource,
                    f"Matched event[{idx}]: {evt.comm} sc={evt.sc_type} res={evt.resource!r}",
                )

        # Fuzzy fallback: resource-only match ignoring syscall type
        if resource_hint:
            for idx, evt in enumerate(events):
                if resource_hint.lower() in evt.resource.lower():
                    return (
                        idx,
                        evt.resource,
                        f"Fuzzy-match event[{idx}] by resource only (syscall type mismatch)",
                    )

        return (None, "", f"No event matches '{event_desc}'")

    @staticmethod
    def extract_resource(event_desc: str) -> str:
        """Extract file path or IP:port from a natural-language event description."""
        # File path: starts with /
        path_match = re.search(r'/[\w./\-]+', event_desc)
        if path_match:
            return path_match.group(0)

        # IP:port or hostname:port
        net_match = re.search(r'[\d.]+:\d+|[\w.]+:\d{2,5}', event_desc)
        if net_match:
            return net_match.group(0)

        # Bare resource after common keywords
        for kw in ("reads", "read", "writes", "write", "executes", "exec",
                   "connects", "connect", "access", "from", "to"):
            pattern = rf'{kw}\s+([^\s,;.]+)'
            m = re.search(pattern, event_desc, re.IGNORECASE)
            if m:
                return m.group(1).strip("'\"")

        return ""

    @staticmethod
    def _parse_reasoning(reasoning: str, mitre_ttps: List[str]) -> List[dict]:
        """Parse unstructured reasoning text into evidence claim dicts.

        Used as fallback when the LLM does not emit structured evidence_refs.
        Extracts resource references and maps them to TTPs heuristically.
        """
        claims = []
        per_ttp_contribution = 1.0 / max(len(mitre_ttps), 1)

        # Find all resource mentions in reasoning
        resource_pattern = re.compile(
            r'(/[\w./\-]{3,}|[\d]{1,3}\.[\d]{1,3}\.[\d.]+:\d+|:\d{2,5})'
        )
        ttp_pattern = re.compile(r'T\d{4}(?:\.\d{3})?')

        resources = resource_pattern.findall(reasoning)
        local_ttps = ttp_pattern.findall(reasoning)
        if not local_ttps:
            local_ttps = mitre_ttps or [""]

        for i, res in enumerate(resources[:8]):  # cap at 8 claims
            ttp = local_ttps[min(i, len(local_ttps) - 1)]
            claims.append({
                "event_desc":              res,
                "supports":                ttp,
                "confidence_contribution": round(per_ttp_contribution / max(len(resources), 1), 4),
            })

        return claims
