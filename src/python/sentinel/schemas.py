"""Pydantic schemas for structured trace data — formal interchange format.

These schemas sit alongside the dataclass models in models.py.  The Pydantic
models are used at system boundaries (API responses, JSON serialization,
inter-service communication) while the dataclasses are used on the hot path.

Key schemas:
  TracedEvent   — immutable Pydantic view of a KernelEvent with event_id
  TraceWindow   — a 50-event window ready for CoVe analysis
  CoVeReportSchema — structured CoVe output for API/audit log
  LTLViolationSchema — structured LTL violation for reporting
"""
from __future__ import annotations

from typing import List
from pydantic import BaseModel, Field


class TracedEvent(BaseModel):
    """Pydantic representation of a KernelEvent.

    event_id is the stable UUID that links this event to LLM evidence_refs.
    Used by CoVe's Grounding step: "eBPF event EVT-<event_id>" is the proof.
    """
    event_id:  str = Field(..., description="Stable UUID — cite this in evidence_refs")
    ts_ns:     int
    pid:       int
    ppid:      int
    uid:       int
    comm:      str
    sc_type:   int
    resource:  str
    flags:     int = 0
    net_port:  int = 0
    net_ip4:   int = 0

    model_config = {"frozen": True}  # immutable — kernel events never change

    @classmethod
    def from_kernel_event(cls, evt) -> "TracedEvent":
        return cls(
            event_id=evt.event_id,
            ts_ns=evt.ts_ns,
            pid=evt.pid,
            ppid=evt.ppid,
            uid=evt.uid,
            comm=evt.comm,
            sc_type=evt.sc_type,
            resource=evt.resource,
            flags=getattr(evt, "flags", 0),
            net_port=getattr(evt, "net_port", 0),
            net_ip4=getattr(evt, "net_ip4", 0),
        )


class TraceWindow(BaseModel):
    """A bounded window of kernel events ready for analysis.

    window_id links back to the original detection signal.
    Corresponds to the 50-event window described in the CoVe paper section.
    """
    window_id:  str = Field(..., description="UUID identifying this window")
    pid:        int
    comm:       str
    entropy:    float
    trigger:    str   # "hard_trigger" | "flagged_parent" | "entropy" | "novel_edge"
    events:     List[TracedEvent]
    ts_ns:      int   # timestamp of window creation


class VerifiedClaimSchema(BaseModel):
    event_desc:              str
    supports_ttp:            str
    confidence_contribution: float
    event_id:                str   # UUID from KernelEvent.event_id
    matched_resource:        str
    verification_note:       str


class CoVeReportSchema(BaseModel):
    """Structured CoVe output — the forensically defensible audit record.

    Contains only verified claims with eBPF event_id references.
    An external auditor can replay the verdict by querying the ring buffer
    for each cited event_id.
    """
    pid:                  int
    comm:                 str
    draft_label:          str
    draft_confidence:     float
    final_label:          str
    final_confidence:     float
    hallucination_rate:   float
    explainability_score: float  # ES ∈ [0,1]; baselines always 0
    grounding_iterations: int
    cove_latency_ms:      float
    verified_evidence_ids: List[str]  # the proof — cite these in paper
    verified_claims:      List[VerifiedClaimSchema]
    retracted_claims:     List[str]   # hallucinated claims removed from report
    mitre_ttps:           List[str]
    reasoning:            str

    @classmethod
    def from_cove_report(cls, r) -> "CoVeReportSchema":
        return cls(
            pid=r.pid,
            comm=r.comm,
            draft_label=r.draft_label,
            draft_confidence=r.draft_confidence,
            final_label=r.final_label,
            final_confidence=r.final_confidence,
            hallucination_rate=r.hallucination_rate,
            explainability_score=r.explainability_score,
            grounding_iterations=r.grounding_iterations,
            cove_latency_ms=r.cove_latency_ms,
            verified_evidence_ids=r.evidence_ids(),
            verified_claims=[
                VerifiedClaimSchema(
                    event_desc=c.event_desc,
                    supports_ttp=c.supports_ttp,
                    confidence_contribution=c.confidence_contribution,
                    event_id=c.event_id,
                    matched_resource=c.matched_resource,
                    verification_note=c.verification_note,
                )
                for c in r.verified_claims
            ],
            retracted_claims=r.retracted_claims,
            mitre_ttps=r.mitre_ttps,
            reasoning=r.reasoning,
        )


class LTLViolationSchema(BaseModel):
    """Structured LTL violation for API response and audit log."""
    axiom_id:           str
    axiom_formula:      str
    severity:           str
    triggering_event_id: str
    triggering_comm:    str
    triggering_resource: str
    description:        str

    @classmethod
    def from_violation(cls, v) -> "LTLViolationSchema":
        return cls(
            axiom_id=v.axiom_id,
            axiom_formula=v.axiom_formula,
            severity=v.severity,
            triggering_event_id=v.triggering_event.event_id,
            triggering_comm=v.triggering_event.comm,
            triggering_resource=v.triggering_event.resource,
            description=v.description,
        )


class SentinelAlertSchema(BaseModel):
    """Top-level alert combining CoVe report + LTL violations.

    This is the object written to incidents.jsonl and returned by GET /decisions.
    """
    alert_id:     str   # UUID for this alert
    ts:           float # Unix timestamp
    pid:          int
    comm:         str
    cove_report:  CoVeReportSchema
    ltl_violations: List[LTLViolationSchema]
    enforcement_tier: str
    is_hallucination_free: bool
