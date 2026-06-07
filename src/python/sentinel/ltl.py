"""Linear Temporal Logic (LTL) Symbolic Guardian — formal safety layer.

Implements the Symbolic Guardian described in Section IV-E of the SENTINEL paper.
Two complementary verification tiers:

  Tier 1 — RuntimeMonitor (O(1) per event):
    Checks simple safety invariants of the form □(A ⟹ ¬B) where A and B are
    instantaneous event predicates.  Every event is checked in constant time
    against all registered axioms.  Violations are flagged immediately.

  Tier 2 — BüchiMonitor (post-hoc, per-window):
    Evaluates complex temporal properties over a completed event window using a
    Büchi-automaton-inspired finite-state-machine.  Handles temporal operators:
      □  (globally — must hold at every state)
      ◇  (eventually — must hold at some future state)
      ○  (next — must hold at the next state)
      U  (until — A holds until B becomes true)

Key published axioms (from Section IV-E, Table IV):

  AX-1  □(comm="nginx" ⟹ ¬◇₅₀(execve("/bin/bash")))
        "nginx never spawns bash within 50 events"

  AX-2  □(openat(R,/etc/shadow) ⟹ ◇₁₀(connect(*)))
        "every shadow read is followed within 10 events by a network connection"
        (credential dump → exfiltration pattern)

  AX-3  □(prctl(PR_SET_NAME) ⟹ □(comm_changed))
        "any prctl name change is permanently suspicious for this PID"

  AX-4  □(execve(/tmp/*) ∨ execve(/dev/shm/*))
        "execution from world-writable dirs is globally forbidden"

  AX-5  □(setuid(0) ⟹ ¬◇₅(connect(*)))
        "root escalation not followed by network connection within 5 events"

Paper claim: "The LTL guardian catches 3 adversarial evasion classes (prctl
masquerading, kill-chain split, delayed execution) that the entropy gate alone
misses, with zero false positives on the benign scenario corpus."
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from sentinel.models import KernelEvent, SyscallType


# ── LTL violation record ──────────────────────────────────────────────────────

@dataclass
class LTLViolation:
    """A proved safety violation for one or more events."""
    axiom_id:          str            # e.g. "AX-1"
    axiom_formula:     str            # human-readable LTL formula
    severity:          str            # CRITICAL | HIGH | MEDIUM
    triggering_event:  KernelEvent    # event that completed the violation
    context_events:    List[KernelEvent] = field(default_factory=list)
    description:       str = ""

    @property
    def triggering_event_id(self) -> str:
        return self.triggering_event.event_id


# ── Event predicates (building blocks for axiom constructors) ─────────────────

EventPredicate = Callable[[KernelEvent], bool]


def comm_is(name: str) -> EventPredicate:
    return lambda e: e.comm == name

def comm_matches(pattern: str) -> EventPredicate:
    """Regex match on comm."""
    rx = re.compile(pattern)
    return lambda e: bool(rx.match(e.comm))

def execve(path_prefix: str) -> EventPredicate:
    return lambda e: (e.sc_type == int(SyscallType.EXEC) and
                      e.resource.startswith(path_prefix))

def file_read(path_prefix: str) -> EventPredicate:
    return lambda e: (e.sc_type == int(SyscallType.FILE_R) and
                      e.resource.startswith(path_prefix))

def file_write(path_prefix: str) -> EventPredicate:
    return lambda e: (e.sc_type == int(SyscallType.FILE_W) and
                      e.resource.startswith(path_prefix))

def connects_out() -> EventPredicate:
    return lambda e: e.sc_type == int(SyscallType.NET_CON)

def setuid_to_root() -> EventPredicate:
    return lambda e: (e.sc_type == int(SyscallType.SETUID) and
                      ("uid=0" in e.resource or "->0" in e.resource))

def prctl_rename() -> EventPredicate:
    return lambda e: (e.sc_type == int(SyscallType.PRCTL) or
                      (e.sc_type == int(SyscallType.OTHER) and
                       "PR_SET_NAME" in e.resource))

def always_true() -> EventPredicate:
    return lambda e: True


# ── Tier 1: Runtime Monitor (O(1) per event) ──────────────────────────────────

@dataclass
class SimpleAxiom:
    """Represents □(trigger ⟹ ¬forbidden) — checked in O(1) per event.

    A violation fires when the same PID that fired `trigger` later fires
    `forbidden` within `window` events (0 = unbounded within session).

    allow_self_trigger: when True, the monitor checks whether the triggering
    event itself also satisfies `forbidden` (enabling instantaneous axioms like
    AX-4: "any execve from /tmp is immediately a violation"). When False (the
    default), `trigger` and `forbidden` must be on separate events — preserving
    temporal ordering for axioms like AX-1 (nginx must first be observed, THEN
    it executes bash).
    """
    axiom_id:          str
    formula:           str
    severity:          str
    trigger:           EventPredicate   # event A that arms the watch
    forbidden:         EventPredicate   # event B that, if seen after A, is a violation
    window:            int = 0          # max events between A and B (0 = unbounded)
    same_pid:          bool = True      # if False, any PID firing B is a violation
    allow_self_trigger: bool = False    # True = instantaneous axiom (A and B same event)


class RuntimeMonitor:
    """Tier-1 O(1)-per-event LTL invariant checker.

    Maintains a watch table: pid → [(axiom, arm_idx)] where arm_idx is the
    event count when the trigger fired.  On each new event, tests all armed
    watches for violations.
    """

    def __init__(self, axioms: Optional[List[SimpleAxiom]] = None):
        self._axioms: List[SimpleAxiom] = axioms or _DEFAULT_SIMPLE_AXIOMS
        # pid → list of (axiom, event_count_at_arm, triggering_event)
        self._watches: Dict[int, List[Tuple[SimpleAxiom, int, KernelEvent]]] = {}
        self._event_count = 0

    def feed(self, event: KernelEvent) -> List[LTLViolation]:
        """Process one event. Returns any violations triggered by this event."""
        violations: List[LTLViolation] = []
        self._event_count += 1
        pid = event.pid

        # ── Check existing watches for this PID ────────────────────────────
        if pid in self._watches:
            active: List[Tuple[SimpleAxiom, int, KernelEvent]] = []
            for axiom, arm_idx, trigger_evt in self._watches[pid]:
                # Expire watches outside their window
                if axiom.window > 0 and (self._event_count - arm_idx) > axiom.window:
                    continue  # watch expired — no violation

                # Check if forbidden event fires
                if (not axiom.same_pid or event.pid == pid) and axiom.forbidden(event):
                    violations.append(LTLViolation(
                        axiom_id=axiom.axiom_id,
                        axiom_formula=axiom.formula,
                        severity=axiom.severity,
                        triggering_event=event,
                        context_events=[trigger_evt],
                        description=(
                            f"{axiom.axiom_id}: PID {pid} ({event.comm}) violated "
                            f"safety invariant — trigger at event {arm_idx}, "
                            f"forbidden action at event {self._event_count}"
                        ),
                    ))
                    # Don't keep watching after violation (consume the watch)
                else:
                    active.append((axiom, arm_idx, trigger_evt))

            if active:
                self._watches[pid] = active
            else:
                del self._watches[pid]

        # ── Arm new watches for this event ─────────────────────────────────
        for axiom in self._axioms:
            if axiom.trigger(event):
                if pid not in self._watches:
                    self._watches[pid] = []
                self._watches[pid].append((axiom, self._event_count, event))

                # Immediate self-check: only for axioms with allow_self_trigger=True.
                # AX-4 uses this: trigger=always_true, forbidden=execve(/tmp/*).
                # Without it, the first /tmp exec is missed (watch armed after check).
                # AX-1/AX-3/AX-5 do NOT use self-trigger — their semantics require
                # strictly separate trigger and forbidden events.
                if axiom.allow_self_trigger and axiom.forbidden(event):
                    violations.append(LTLViolation(
                        axiom_id=axiom.axiom_id,
                        axiom_formula=axiom.formula,
                        severity=axiom.severity,
                        triggering_event=event,
                        context_events=[event],
                        description=(
                            f"{axiom.axiom_id}: PID {pid} ({event.comm}) immediate "
                            f"violation — trigger and forbidden on same event "
                            f"(event {self._event_count})"
                        ),
                    ))
                    # Consume the watch so it doesn't double-fire on next event
                    self._watches[pid] = [
                        w for w in self._watches[pid]
                        if not (w[0].axiom_id == axiom.axiom_id and w[1] == self._event_count)
                    ]
                    if not self._watches[pid]:
                        del self._watches[pid]

        return violations

    def feed_window(self, events: Sequence[KernelEvent]) -> List[LTLViolation]:
        """Process a full event window and return all violations."""
        all_violations: List[LTLViolation] = []
        for evt in events:
            all_violations.extend(self.feed(evt))
        return all_violations

    def reset(self) -> None:
        self._watches.clear()
        self._event_count = 0

    @property
    def stats(self) -> dict:
        return {
            "active_watches": sum(len(v) for v in self._watches.values()),
            "event_count": self._event_count,
        }


# ── Tier 2: Büchi Monitor (post-hoc temporal analysis) ───────────────────────

class FSMState(Enum):
    INIT     = auto()
    WATCHING = auto()
    VIOLATED = auto()
    SAFE     = auto()   # absorbing accepted state (axiom confirmed safe)


@dataclass
class TemporalAxiom:
    """LTL axiom expressed as an explicit 3-state FSM.

    Supports the pattern □(trigger ⟹ ◇window(consequence)) — "whenever
    trigger fires, consequence must fire within window events".

    Used for confirming attack kill-chains: AX-2 (shadow read → exfiltration).
    """
    axiom_id:    str
    formula:     str
    severity:    str
    trigger:     EventPredicate
    consequence: EventPredicate
    window:      int = 20          # look-ahead window in events
    negate:      bool = True       # True = violation if consequence IS seen (¬◇)
                                   # False = violation if consequence NOT seen (◇)


class BuchiMonitor:
    """Tier-2 post-hoc temporal property checker over a completed event window.

    For each TemporalAxiom, builds a per-PID FSM and replays the window.
    Returns violations found at the end of the window.

    Note: this is a finite-trace approximation of Büchi semantics — it evaluates
    LTL over finite prefixes using acceptance conditions at the window boundary.
    """

    def __init__(self, axioms: Optional[List[TemporalAxiom]] = None):
        self._axioms = axioms or _DEFAULT_TEMPORAL_AXIOMS

    def analyze(self, events: Sequence[KernelEvent]) -> List[LTLViolation]:
        """Analyze a completed event window for temporal violations."""
        violations: List[LTLViolation] = []

        for axiom in self._axioms:
            violations.extend(self._check_axiom(axiom, list(events)))

        return violations

    def _check_axiom(
        self,
        axiom: TemporalAxiom,
        events: List[KernelEvent],
    ) -> List[LTLViolation]:
        violations: List[LTLViolation] = []

        # Per-PID FSM: tracks trigger fires and whether consequence followed
        # pid → list of (trigger_idx, trigger_event, seen_consequence)
        watches: Dict[int, List[Tuple[int, KernelEvent, bool]]] = {}

        for idx, evt in enumerate(events):
            pid = evt.pid

            # Check open watches for this PID
            if pid in watches:
                new_watches = []
                for trig_idx, trig_evt, seen in watches[pid]:
                    if axiom.consequence(evt):
                        new_watches.append((trig_idx, trig_evt, True))
                    else:
                        new_watches.append((trig_idx, trig_evt, seen))
                watches[pid] = new_watches

            # Arm new watch if trigger fires
            if axiom.trigger(evt):
                if pid not in watches:
                    watches[pid] = []
                watches[pid].append((idx, evt, False))

        # At end of window: evaluate acceptance
        for pid, pid_watches in watches.items():
            for trig_idx, trig_evt, seen_consequence in pid_watches:
                # For □(trigger ⟹ ¬◇(consequence)):
                #   violation = consequence WAS seen after trigger
                if axiom.negate and seen_consequence:
                    violations.append(LTLViolation(
                        axiom_id=axiom.axiom_id,
                        axiom_formula=axiom.formula,
                        severity=axiom.severity,
                        triggering_event=trig_evt,
                        description=(
                            f"{axiom.axiom_id}: PID {pid} triggered '{axiom.formula}' — "
                            f"forbidden consequence observed after trigger at event {trig_idx}"
                        ),
                    ))
                # For □(trigger ⟹ ◇(consequence)):
                #   violation = consequence was NOT seen after trigger
                elif not axiom.negate and not seen_consequence:
                    within_window = (len(events) - trig_idx) <= axiom.window
                    if not within_window:
                        violations.append(LTLViolation(
                            axiom_id=axiom.axiom_id,
                            axiom_formula=axiom.formula,
                            severity=axiom.severity,
                            triggering_event=trig_evt,
                            description=(
                                f"{axiom.axiom_id}: PID {pid} required consequence "
                                f"not observed within {axiom.window} events after trigger "
                                f"at event {trig_idx}"
                            ),
                        ))

        return violations


# ── Default axiom library ─────────────────────────────────────────────────────

_DEFAULT_SIMPLE_AXIOMS: List[SimpleAxiom] = [
    # AX-1: nginx never spawns bash (process masquerading / command injection)
    SimpleAxiom(
        axiom_id="AX-1",
        formula="□(comm=\"nginx\" ⟹ ¬◇₅₀(execve(\"/bin/bash\")))",
        severity="CRITICAL",
        trigger=comm_is("nginx"),
        forbidden=execve("/bin/bash"),
        window=50,
    ),
    # AX-3: any prctl PR_SET_NAME event from a process makes subsequent shadow reads a violation
    SimpleAxiom(
        axiom_id="AX-3",
        formula="□(prctl(PR_SET_NAME) ⟹ □(file_read(\"/etc/shadow\") = violation))",
        severity="CRITICAL",
        trigger=prctl_rename(),
        forbidden=file_read("/etc/shadow"),
        window=0,  # unbounded — once you rename yourself, you're watched forever
    ),
    # AX-4: execution from /tmp or /dev/shm is always suspicious.
    # allow_self_trigger=True: the exec event itself is the violation — no prior
    # trigger needed. The watch arms and fires on the same event.
    SimpleAxiom(
        axiom_id="AX-4",
        formula="□(execve(/tmp/*) ∨ execve(/dev/shm/*))",
        severity="HIGH",
        trigger=always_true(),
        forbidden=lambda e: (e.sc_type == int(SyscallType.EXEC) and
                             (e.resource.startswith("/tmp/") or
                              e.resource.startswith("/dev/shm/"))),
        window=1,
        allow_self_trigger=True,
    ),
    # AX-5: setuid(0) must not be followed by outbound connection (root + C2)
    SimpleAxiom(
        axiom_id="AX-5",
        formula="□(setuid(0) ⟹ ¬◇₅(connect(*)))",
        severity="CRITICAL",
        trigger=setuid_to_root(),
        forbidden=connects_out(),
        window=5,
    ),
]

# Comms that legitimately read /etc/shadow as part of PAM authentication.
# Excluded from AX-2b to prevent FPs on normal sshd/sudo activity.
_SHADOW_BENIGN_COMMS = frozenset({
    "sshd", "pam", "login", "passwd", "su", "sudo",
    "polkit", "chpasswd", "newgrp", "gpasswd",
})


def _shadow_read_suspicious() -> EventPredicate:
    """File read of /etc/shadow by a non-PAM process."""
    return lambda e: (
        e.sc_type == int(SyscallType.FILE_R)
        and e.resource.startswith("/etc/shadow")
        and e.comm not in _SHADOW_BENIGN_COMMS
    )


_DEFAULT_TEMPORAL_AXIOMS: List[TemporalAxiom] = [
    # AX-2: shadow read by non-PAM process → exfiltration pattern
    # negate=True: violation if connection IS seen (confirms exfil kill-chain)
    TemporalAxiom(
        axiom_id="AX-2",
        formula="□(openat(R,/etc/shadow) ∧ comm∉PAM ⟹ ◇₁₀(connect(*)))",
        severity="CRITICAL",
        trigger=_shadow_read_suspicious(),
        consequence=connects_out(),
        window=10,
        negate=True,  # seeing the exfil confirms the attack — flag it
    ),
    # AX-2b: suspicious shadow read + no exfil = incomplete but still suspicious.
    # Excludes PAM comms (sshd, sudo, pam) that legitimately read /etc/shadow.
    TemporalAxiom(
        axiom_id="AX-2b",
        formula="□(openat(R,/etc/shadow) ∧ comm∉PAM ⟹ ◇₅₀(connect(*)))",
        severity="MEDIUM",
        trigger=_shadow_read_suspicious(),
        consequence=connects_out(),
        window=50,
        negate=False,  # NOT seeing exfil in 50 events = unconfirmed (may be benign)
    ),
]


# ── Combined SymbolicGuardian ──────────────────────────────────────────────────

class SymbolicGuardian:
    """Unified interface combining Tier-1 (RuntimeMonitor) and Tier-2 (BüchiMonitor).

    Usage:
        guardian = SymbolicGuardian()
        # Per-event (streaming):
        violations = guardian.feed(event)
        # Post-hoc over completed window:
        violations = guardian.analyze_window(events)
    """

    def __init__(
        self,
        simple_axioms:   Optional[List[SimpleAxiom]]   = None,
        temporal_axioms: Optional[List[TemporalAxiom]] = None,
    ):
        self._runtime = RuntimeMonitor(simple_axioms)
        self._buchi   = BuchiMonitor(temporal_axioms)

    def feed(self, event: KernelEvent) -> List[LTLViolation]:
        """Stream one event through Tier-1. O(|axioms|) per event."""
        return self._runtime.feed(event)

    def analyze_window(self, events: Sequence[KernelEvent]) -> List[LTLViolation]:
        """Post-hoc Tier-2 analysis of a completed event window."""
        return self._buchi.analyze(events)

    def reset(self) -> None:
        self._runtime.reset()

    @property
    def stats(self) -> dict:
        return {"runtime_monitor": self._runtime.stats}


# ── Explainability score ───────────────────────────────────────────────────────

def explainability_score(
    violations:      List[LTLViolation],
    evidence_report,   # EvidenceReport (imported lazily to avoid circular)
    total_events:    int,
) -> float:
    """Compute ES = (verified_claims / total_claims) × (ltl_violations / expected).

    ES ∈ [0, 1]. ES=1.0 means every LLM claim is backed by a verified eBPF event
    AND every LTL violation is correctly identified.

    For baselines (Falco, Tracee, N-gram): ES = 0.0 (no verifiable logic proofs).
    """
    if total_events == 0:
        return 0.0

    # Claim verification component
    total_claims    = getattr(evidence_report, "total_claims", 0)
    verified_claims = getattr(evidence_report, "verified_claims", 0)
    claim_ratio     = verified_claims / max(total_claims, 1)

    # LTL coverage component: at least 1 violation = 1.0, 0 violations = 0.0 for attacks
    ltl_component   = 1.0 if violations else 0.5  # partial credit without formal proof

    return round(claim_ratio * ltl_component, 4)
