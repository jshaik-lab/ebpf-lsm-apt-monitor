"""AuditorAgent — Stage 3 of the agentic pipeline.

Responsibility: verification, enforcement, archival.

Processing steps:
  1. CoVeLoop: full 4-step Draft→Verify→Ground→Synthesize with eBPF event IDs
  2. LTL SymbolicGuardian: post-hoc Büchi analysis of the event window
  3. Adjust confidence using verified_confidence from CoVeReport
  4. If hallucination_rate > threshold → downgrade to LOG_ONLY regardless of raw conf
  5. Route to CWAEEngine with verified_confidence (Algorithm 3)
  6. Notify DetectorAgent to flag the PID on MALICIOUS verdict
  7. Write structured audit log entry with CoVe evidence_ids + LTL violations

This is the enforcement gate: nothing reaches the kernel enforcement
mechanism without first passing CoVe grounding.

Paper claim: "SENTINEL produces zero enforcement actions driven by
hallucinated evidence across N evaluation traces."
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Callable, Optional

import structlog

from sentinel.agents.analyzer import AnalysisResult
from sentinel.cove import CoVeLoop, CoVeReport
from sentinel.egte import EGTEEngine, EGTEResult
from sentinel.enforcement import CWAEEngine
from sentinel.ltl import SymbolicGuardian, LTLViolation
from sentinel.models import EnforcementTier, ThreatDecision, TIER_LABELS

logger = structlog.get_logger(__name__)

# Hallucination rate above which we refuse to enforce at tier > LOG_ONLY
_MAX_HALLUCINATION_RATE = 0.50


class AuditorAgent:
    """Stage 3: CoVe grounding + LTL verification + enforcement + archival.

    Pulls AnalysisResults, runs full 4-step CoVe loop, checks LTL axioms,
    calls CWAE, and writes the audit log with eBPF event_id evidence chains.
    """

    def __init__(
        self,
        in_queue:        asyncio.Queue,
        cwae:            CWAEEngine,
        audit_log_path:  str,
        incident_path:   str,
        flag_pid_cb:     Optional[Callable[[int], None]] = None,
        max_hallucination: float = _MAX_HALLUCINATION_RATE,
        egte:            Optional[EGTEEngine] = None,
    ):
        self._in            = in_queue
        self._cwae          = cwae
        self._audit_path    = Path(audit_log_path)
        self._incident_path = Path(incident_path)
        self._flag_cb       = flag_pid_cb
        self._max_hal       = max_hallucination
        self._cove          = CoVeLoop(max_grounding_iterations=1,
                                       hallucination_threshold=max_hallucination)
        self._guardian      = SymbolicGuardian()
        self._egte          = egte   # None = EGTE disabled (default behavior preserved)
        self._stats = {
            "audited": 0,
            "enforced": 0,
            "hallucination_downgrades": 0,
            "clean_evidence": 0,
            "ltl_violations": 0,
            "cove_retractions": 0,
            "egte_caps": 0,   # count of decisions where EGTE lowered the tier
        }

    async def run(self) -> None:
        """Consume AnalysisResults forever — run as asyncio.Task."""
        while True:
            result: AnalysisResult = await self._in.get()
            await self._audit(result)

    async def _audit(self, result: AnalysisResult) -> None:
        t0       = time.perf_counter()
        decision = result.decision
        events   = result.signal.window
        pid      = result.signal.pid
        comm     = result.signal.comm

        # ── Step 1: CoVe 4-step grounding loop ────────────────────────────────
        cove_report: CoVeReport = await asyncio.to_thread(
            self._cove.run, decision, events, pid, comm
        )
        self._stats["cove_retractions"] += len(cove_report.retracted_claims)

        # ── Step 2: LTL Symbolic Guardian (Büchi post-hoc analysis) ──────────
        ltl_violations: list[LTLViolation] = await asyncio.to_thread(
            self._guardian.analyze_window, events
        )
        if ltl_violations:
            self._stats["ltl_violations"] += len(ltl_violations)
            logger.warning(
                "ltl_violation",
                pid=pid, count=len(ltl_violations),
                axioms=[v.axiom_id for v in ltl_violations],
            )

        # ── Step 3: apply hallucination guard using CoVe result ───────────────
        effective_conf = cove_report.final_confidence
        downgraded     = cove_report.final_confidence < decision.confidence

        if (decision.label == "MALICIOUS" and
                cove_report.hallucination_rate > self._max_hal):
            logger.warning(
                "hallucination_guard_triggered",
                pid=pid,
                hal_rate=cove_report.hallucination_rate,
                raw_conf=decision.confidence,
                effective_conf=effective_conf,
                retracted=cove_report.retracted_claims,
            )
            downgraded = True
            self._stats["hallucination_downgrades"] += 1
        else:
            self._stats["clean_evidence"] += 1

        # Rebuild decision with CoVe-adjusted confidence
        if downgraded:
            decision = ThreatDecision(
                label=decision.label,
                confidence=effective_conf,
                reasoning=decision.reasoning + " [CoVe-downgraded]",
                mitre_ttps=decision.mitre_ttps,
                chain_of_thought=decision.chain_of_thought,
                model_used=decision.model_used,
                latency_ms=decision.latency_ms,
                evidence_refs=decision.evidence_refs,
            )

        # LTL violations boost confidence for MALICIOUS decisions
        if ltl_violations and decision.label == "MALICIOUS":
            ltl_boost = min(0.10 * len(ltl_violations), 0.20)
            decision = ThreatDecision(
                label=decision.label,
                confidence=min(decision.confidence + ltl_boost, 1.0),
                reasoning=decision.reasoning +
                          f" [LTL:{','.join(v.axiom_id for v in ltl_violations)}]",
                mitre_ttps=decision.mitre_ttps,
                chain_of_thought=decision.chain_of_thought,
                model_used=decision.model_used,
                latency_ms=decision.latency_ms,
                evidence_refs=decision.evidence_refs,
            )

        # ── Step 3.5: EGTE — evidence-gated tier calibration (if enabled) ─────
        egte_result: Optional[EGTEResult] = None
        egte_max_tier: Optional[EnforcementTier] = None

        if self._egte is not None:
            cwae_tier_preview = self._cwae.compute_tier(decision)
            egte_result = self._egte.enforce_tier(
                decision       = decision,
                cwae_tier      = cwae_tier_preview,
                cove           = cove_report,
                ltl_violations = ltl_violations,
                ipg_nodes      = result.ipg_nodes,
                ipg_edges      = result.ipg_edges,
                entropy        = result.signal.entropy,
            )
            egte_max_tier = egte_result.tier_after
            if egte_result.tier_after < cwae_tier_preview:
                self._stats["egte_caps"] += 1
                logger.info(
                    "egte_tier_cap",
                    pid=pid,
                    tier_before=egte_result.tier_before.name,
                    tier_after=egte_result.tier_after.name,
                    capped_by=egte_result.capped_by,
                    score=round(egte_result.score, 4),
                )

        # ── Step 4: CWAE enforcement with PCABP consensus ────────────────────
        # Pass the PCABP score so CWAEEngine can use
        #   effective_conf = max(llm_conf, 0.4·static + 0.6·AI)
        # This ensures heap-injected shellcode that fools the LLM is still
        # caught and escalated to the correct enforcement tier.
        pcabp_score = getattr(result, "pcabp_score", 0.0)
        if decision.label == "MALICIOUS" or pcabp_score >= 0.40:
            rec = await self._cwae.enforce(pid, comm, decision,
                                           max_tier=egte_max_tier,
                                           pcabp_score=pcabp_score)
            self._stats["enforced"] += 1
            if self._flag_cb:
                self._flag_cb(pid)
        else:
            rec = None

        self._stats["audited"] += 1
        audit_ms = round((time.perf_counter() - t0) * 1000, 2)

        # ── Step 5: write structured audit log ────────────────────────────────
        entry = {
            "ts":            time.time(),
            "pid":           pid,
            "comm":          comm,
            "label":         decision.label,
            "confidence":    round(decision.confidence, 4),
            "verified_conf": round(effective_conf, 4),
            "tier":          TIER_LABELS.get(rec.tier, "LOG_ONLY") if rec else "LOG_ONLY",
            "trigger":       result.signal.trigger,
            "entropy":       round(result.signal.entropy, 3),
            "ipg_nodes":     result.ipg_nodes,
            "ipg_edges":     result.ipg_edges,
            "mitre_ttps":    decision.mitre_ttps,
            "reasoning":     decision.reasoning,
            "cove": {
                "draft_label":          cove_report.draft_label,
                "draft_confidence":     round(cove_report.draft_confidence, 4),
                "hallucination_rate":   round(cove_report.hallucination_rate, 4),
                "explainability_score": round(cove_report.explainability_score, 4),
                "grounding_iterations": cove_report.grounding_iterations,
                "verified_evidence_ids": cove_report.evidence_ids(),
                "retracted_claims":     cove_report.retracted_claims,
                "cove_latency_ms":      cove_report.cove_latency_ms,
                "downgraded":           downgraded,
            },
            "ltl": {
                "violations": len(ltl_violations),
                "axioms":     [v.axiom_id for v in ltl_violations],
                "severities": [v.severity for v in ltl_violations],
            },
            "egte": egte_result.to_audit_dict() if egte_result is not None else {
                "score": None, "quantile": None,
                "tier_before": None, "tier_after": None,
                "capped_by": None, "p_value": None,
                "enabled": False,
            },
            "latency": {
                "detector_ms": result.signal.detector_ms,
                "analyzer_ms": result.analyzer_ms,
                "llm_ms":      result.llm_ms,
                "auditor_ms":  audit_ms,
                "total_ms":    round(
                    result.signal.detector_ms + result.analyzer_ms + audit_ms, 2
                ),
            },
        }

        await asyncio.to_thread(self._write_audit, entry, decision.label)
        logger.info(
            "audit_complete",
            pid=pid, label=decision.label,
            confidence=round(decision.confidence, 3),
            exp_score=round(cove_report.explainability_score, 3),
            ltl_violations=len(ltl_violations),
            tier=entry["tier"],
        )

    def _write_audit(self, entry: dict, label: str) -> None:
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._audit_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        if label == "MALICIOUS" and entry["tier"] in ("QUARANTINE", "ISOLATE"):
            self._incident_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._incident_path, "a") as f:
                f.write(json.dumps(entry) + "\n")

    @property
    def stats(self) -> dict:
        return dict(**self._stats)
