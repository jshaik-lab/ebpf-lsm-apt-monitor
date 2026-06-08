# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> [!IMPORTANT]
   > **DO NOT RUN ANY WORKLOADS, COMMANDS, OR TESTS ON THE IONOS VPS (`74.208.76.97`) unless the user explicitly requests it.**
   > All execution, benchmarks, and evaluations must run ONLY on Google Cloud Platform (GCP) or local environments. This rule is absolute and applies across all subagents and tasks.

## What This Is

SENTINEL is an IEEE research paper + production Python implementation targeting **IEEE Transactions on Information Forensics and Security (TIFS)**. It integrates eBPF kernel tracing with local LLMs to enforce zero-trust policies based on process behavioral intent.

Seven novel contributions define the paper's claims — do not change these mechanisms without understanding the paper sections they reference:

1. **Intent Provenance Graph (IPG)** — `sentinel/ipg.py`, Algorithm 1, Section IV-B.
   Converts a sliding window of `KernelEvent`s into a compact YAML-serialized directed multigraph. Parallel edges with the same syscall label are merged into a bounded summary `(count, min_dt_ms, max_dt_ms, first_idx)` — NOT min-Δt-only (audit fix #5: min-only let a fast benign instance mask a slow malicious one of the same src→dst→syscall). `n:`/`dt_max_ms:` emitted only for merged edges. Semantic hints attached to sensitive resources.
   **Measured (GCP, 105 strace traces, tiktoken cl100k_base)**: 74.0% token reduction at window=20 (avg 1122→292 tokens); 92.7% at full trace (avg 12185→885 tokens). See `results/evaluations_gcp/ipg_token_reduction_gcp.json`.

2. **Dual-Tier Inference Pipeline** — `sentinel/llm/base.py`, Algorithm 2, Section IV-C.
   Draft (llama3.2:1b) → if BENIGN at conf ≥ 0.90, skip full model. MALICIOUS from draft always escalates to llama3.1:8b.
   **Measured** (real Ollama, M5): 35.7% invocation reduction (5/14 draft hits). Prior paper claim of 94.7% is wrong — **must update Section V-B**. BENIGN-only fast-path causes 2 false negatives: draft misclassifies Lateral Movement (T1210, conf=0.99) and Valid Accounts (T1078, conf=0.98).
   8B-only accuracy: 14/14; dual-tier accuracy: 12/14 (GCP Ollama). See `results/evaluations_gcp/dual_tier_reduction_gcp.json`.

3. **Confidence-Weighted Adaptive Enforcement (CWAE)** — `sentinel/enforcement.py`, Algorithm 3, Section IV-D.
   **Measured (GCP)**: CWAE enforce p50=0.888ms, p99=0.932ms; IPG p50=0.184ms. Detector throughput: 25,665 events/s. See `results/evaluations_gcp/overhead_gcp.json`.
   Now accepts `pcabp_score` param: `effective_conf = max(llm_conf, pcabp_score)`. This ensures heap-injected shellcode that fools the LLM is still escalated to correct tier.

4. **LTL Symbolic Guardian** — `sentinel/ltl.py`, Section IV-E.
   Five formal safety axioms (AX-1 through AX-5). Tier-1: O(1) RuntimeMonitor (AX-1, AX-3, AX-4, AX-5); Tier-2: BüchiMonitor (AX-2 shadow→exfil kill-chain).
   **Measured (GCP)**: 0 false positives on 387 benign sliding windows (55 traces). See `results/evaluations_gcp/ltl_fpr_real_gcp.json`.

5. **Chain of Verification (CoVe)** — `sentinel/cove.py`, Section IV-F.
   4-step Draft→Verify→Ground→Synthesize. Each LLM claim linked to a real eBPF `event_id` UUID. `hallucination_eval.py` tests blocking, but "zero hallucinations" claim requires Ollama measurement — MockClassifier always returns `evidence_refs=[]`.

6. **Evidence-Gated Tier-Calibrated Enforcement (EGTE)** — `sentinel/egte.py`, Section IV-G.
   Split conformal calibration. Finite-sample guarantee: P(benign over-escalation) ≤ α + 1/(n+1). Disabled by default (`egte.enabled: false`). Calibration dataset is synthetic — requires real benign traces for publication-quality coverage guarantee.

7. **Program-Counter-Aware Behavioral Provenance (PCABP)** — `sentinel/pcabp/`, Section IV-H (new).
   Detects process-injection attacks by checking WHERE in the address space a syscall was invoked (user-space instruction pointer from eBPF `bpf_get_stack`), not just WHAT syscall was called. Solves the nginx-mimicry problem: heap-injected shellcode that calls connect() looks identical to nginx at the syscall level, but its call-site IP is outside nginx's .text section.
   - **Static layer** (`call_site_map.py`): Bloom filter of valid return addresses built from ELF .plt entries + .text BL/CALL instruction scan (pyelftools + capstone). O(1) lookup. ARM64 support added (capstone `CS_ARCH_ARM64, CS_MODE_ARM`; mnemonic `bl`, target parsed as `int(op_str.lstrip("#"), 16)`).
   - **AI layer** (`behavioral_encoder.py`): PyTorch contrastive encoder (~35K params). Input per event: (syscall_id/16, log(offset_delta+1)/30, resource_type/8) → Linear(3→64) → LayerNorm → GELU → Linear(64→32) → L2-norm → mean-pool over window → 32-dim embedding. Trained with TripletMarginLoss: anchor/positive=in-binary (delta=0), negative=heap-injected (large delta). Centroid separation=1.717.
   - **Consensus**: `pcabp_score = 0.4 * static_violation + 0.6 * ai_divergence`. Weights from Table V.
   - **Integration**: Layer 0 in DetectorAgent (pre-entropy triage) + AnalyzerAgent (_compute_pcabp) + AuditorAgent (passes to CWAE) + CWAEEngine (effective_conf override).
   - **Measured** (500-trial synthetic eval, real nginx 1.18.0 linux/arm64 binary, 311 call sites): TPR=1.0, FPR=0.0, F1=1.0 at threshold=0.40. Legit-window scores: mean=0.115 (range 0.115–0.115, fixed sc_type/resource test design). Injected-window scores: mean=0.892 (range 0.888–0.894). Bloom FPR theoretical ≈ 7.8e-28. Note: 100% separation is due to pure synthetic classes (all legit IPs from bloom filter, all injected IPs from heap). Real-world mixed windows will show variance. See `results/evaluations/pcabp_results.json`.

---

## Measured Results (GCP authoritative — `results/evaluations_gcp/`)

**Source of truth:** `results/evaluations_gcp/*_gcp.json` + `MANIFEST.json` (2026-06-08 run on `sentinel-gpu-vm`). Platform: g2-standard-4, NVIDIA L4, kernel 6.17.0-1018-gcp. All LLM evals: `ollama_fallback_to_mock_count: 0`.

**Overhead** (`overhead_gcp.json`): IPG p50=0.184ms, p99=0.306ms; CWAE p50=0.888ms; detector 25,665 events/s.

**Real-data** (105 native strace traces, llama3.1:8b, `real_data_results_gcp.json`):
TPR=0.714, FPR=0.291, accuracy=0.712 [95% CI: 0.625–0.798], n=104 evaluated.

**DARPA TC E3 CADETS (100 windows, 50 attack / 50 benign)**:

| Mode | F1 | TPR | FPR | Precision | Accuracy | File |
|---|---|---|---|---|---|---|
| Hybrid behavioral (v5) | **0.603** | 0.44 | 0.02 | 0.957 | 0.71 | `darpa_tc_behavioral_v5_gcp.json` |
| LLM-only behavioral (v4) | **0.597** | 0.46 | 0.08 | 0.852 | 0.69 | `darpa_tc_behavioral_v4_gcp.json` |
| TI-aided (v8) | **0.915** | 0.86 | 0.02 | 0.977 | 0.92 | `darpa_tc_v8_ti_aided_gcp.json` |

**Ablation** (`darpa_ablation_gcp.json`): graph-only F1=0.611 (0 LLM calls); hybrid F1=0.603 (1/100 LLM calls); hybrid+LTL F1=0.611 (0 FPR).

Competitors (behavioral-only, no TI oracle): WATSON F1=0.82, UNICORN F1=0.88, ProvDetector F1=0.87, DEPIMPACT F1=0.91. SENTINEL behavioral F1 remains below all competitors.

**CRITICAL METHODOLOGICAL NOTE — TI-aided result is NOT comparable to competitors:**
TI-aided F1=0.915 uses `[C2]`/`[MALWARE]` from the same `KNOWN_C2_IPS` list as ground truth. Always report as "TI-aided" with circularity caveat. 24/25 nginx_backdoor windows are syscall-indistinguishable from benign nginx workers.

Dataset: `data/darpa/ta1-cadets-e3-official.json.2` on GCP VM (also on Mac external SSD).

---

## Developer Workflow

```bash
pip install -r requirements-dev.txt  # one-time setup

make test        # 218 unit tests — no Docker/root/LLM needed, runs in <2s
make lint        # ruff check
make type-check  # mypy

make run         # simulation mode + mock LLM
make eval-ltl    # LTL axiom validation on all 9 evasion scenarios

# Train PCABP encoder (one-time, no GPU needed, ~30s on M5):
cd src/python && python -m sentinel.pcabp.behavioral_encoder --train
# Outputs: sentinel/pcabp/pcabp_weights.pt  sentinel/pcabp/pcabp_centroids.pkl
# Centroid separation target: >1.0 (achieved: 1.717)

# Evaluations (require Ollama running with llama3.1:8b):
make eval-scenarios   # 14 MITRE ATT&CK scenarios → results/evaluations/scenario_results.json
make eval-real        # 15 real strace traces → results/evaluations/real_data_results.json
make eval-darpa-tc    # DARPA TC E3 CADETS, 100 windows (run on GCP for paper numbers)
                      # Paper results: results/evaluations_gcp/darpa_tc_*_gcp.json
                      # GCP chain: bash scripts/run_gcp_eval_chain.sh (see docs/RUNME.md)
make eval-darpa-tc-full  # 400 windows (full paper submission run)
make eval-all         # all evaluations except eval-real and eval-darpa-tc

# Honest behavioral-only DARPA TC evaluation (COMPLETED — F1=0.500, TPR=0.360):
# cd src/python && PYTHONPATH=. python3 evaluate_darpa_tc.py \
#   --dataset cadets --max-windows 100 \
#   --strip-annotations --hard-fraction 0.5 \
#   --out ../../results/evaluations/darpa_tc_behavioral.json
# Result: F1=0.500, TPR=0.360, FPR=0.080, Precision=0.818, Accuracy=0.640
# Comparable to WATSON (F1=0.82) — SENTINEL behavioral-only is below all competitors.

# Run a single test file:
PYTHONPATH=src/python pytest src/python/tests/test_ltl.py -v
```

---

## Docker Quick Start (Mac M5)

```bash
make up-mock     # instant start, mock LLM, no downloads
make up          # full Ollama stack (~5-9 GB model downloads on first run)
make up-ebpf     # live eBPF inside Docker VM (privileged)
make down && make logs
```

Ports: `8080` (FastAPI), `9090` (Prometheus metrics), `9091` (Prometheus UI), `3000` (Grafana admin/sentinel).

---

## Compile the Paper

```bash
cd paper/
pdflatex main && bibtex main && pdflatex main && pdflatex main
open main.pdf
```

Run `chktex main.tex` before submission. Page limit: 14 pages. Author/affiliation at lines 68–76 of `paper/main.tex`.

---

## Production Architecture

Three-stage agentic pipeline inside `SentinelAgent.run()`:

```
sentinel.c  (eBPF: tracepoints + LSM hooks + prctl PR_SET_NAME)
    └── ring buffer (struct event_t, 224 bytes total, event_id UUID + user_ip)
sentinel/bpf.py — BPFLoader  (or SimulationSource: 21 scenarios)
    ↓
Stage 1 — DetectorAgent (sentinel/agent.py)
    ├── Layer 0: PCABP static violation — check event.ip vs ValidCallSiteMap bloom filter
    │           (if ip ≠ 0 and ip ∉ call-site map → immediate LLM bypass, trigger=pcabp_static_violation)
    ├── Layer 1: Hard-trigger bypass: /.ssh/, /etc/shadow, /proc/self/mem → immediate LLM
    ├── Layer 2: Flagged-PID bypass: child of MALICIOUS process → immediate LLM
    ├── EntropyTracker: Shannon entropy per PID over 64-event window
    └── IPGBuilder.fingerprint() → SHA-256 bloom dedup

Stage 2 — AnalyzerAgent (sentinel/agents/analyzer.py)
    ├── IPGBuilder.build() + serialize()  [Algorithm 1, ~441 tokens]
    ├── DualTierClassifier                [Algorithm 2]
    │   ├── OllamaClassifier (llama3.2:1b draft) or MockClassifier
    │   └── OllamaClassifier (llama3.1:8b full)
    │   → ThreatDecision {label, confidence, mitre_ttps, evidence_refs, event_id UUIDs}
    └── _compute_pcabp(window) — runs in asyncio.to_thread:
        ├── ValidCallSiteMap.check(ip) → static_violation (1.0 if any IP outside bloom filter)
        ├── BehavioralEncoder.score(window, offset_deltas) → ai_divergence ∈ [0,1]
        └── pcabp_score = 0.4*static_violation + 0.6*ai_divergence
        → AnalysisResult.pcabp_static / .pcabp_ai / .pcabp_score

Stage 3 — AuditorAgent (sentinel/agents/auditor.py)
    ├── CoVeLoop: Draft→Verify→Ground→Synthesize  [Section IV-F]
    │   └── EvidenceLinker: validates evidence_refs against KernelEvent window by UUID
    ├── SymbolicGuardian: RuntimeMonitor (O(1)) + BüchiMonitor  [Section IV-E]
    └── CWAEEngine.enforce(pcabp_score=...) with consensus override  [Algorithm 3]
        ├── effective_conf = max(llm_conf, pcabp_score)
        ├── if BENIGN and pcabp_score ≥ 0.40 → enforce at pcabp tier anyway
        └── LOG_ONLY / PAUSE / KILL / QUARANTINE / ISOLATE
```

`sentinel/egte.py` — optional EGTE layer (disabled): EscalationScorer (5 weighted features) + TierCalibrator (split conformal) + apply_gates() (CoVe cap + LTL floor).

### LTL Axioms (Section IV-E, Table IV)

| ID | Formula | Tier | Severity |
|---|---|---|---|
| AX-1 | □(comm="nginx" ⟹ ¬◇₅₀(execve("/bin/bash"))) | Runtime | CRITICAL |
| AX-2 | □(shadow_read ⟹ ◇₁₀(connect(*))) | Büchi | CRITICAL |
| AX-3 | □(prctl(PR_SET_NAME) ⟹ ¬◇₅₀(shadow_read)) | Runtime | CRITICAL |
| AX-4 | □(¬execve(/tmp/* ∨ /dev/shm/*)) | Runtime | HIGH |
| AX-5 | □(setuid(0) ⟹ ¬◇₅(connect(*))) | Runtime | CRITICAL |

### KernelEvent Forensic Linking

Every `KernelEvent` has a stable `event_id: str = uuid4()`. CoVe cites these UUIDs in `verified_evidence_ids` in the audit log. Never remove `event_id` from `KernelEvent`.

`KernelEvent` also has `ip: int = 0` — the user-space instruction pointer from eBPF `bpf_get_stack(BPF_F_USER_STACK)`. `ip=0` means not captured (simulation mode / CDM18 data). Non-zero means PCABP-eligible.

### Enforcement Tiers (Algorithm 3)

| Confidence | Tier | Action |
|---|---|---|
| < 0.30 | LOG_ONLY | log only |
| < 0.50 | PAUSE | SIGSTOP + alert |
| < 0.70 | KILL | SIGKILL + memory dump |
| < 0.85 | QUARANTINE | SIGKILL + XDP network block |
| ≥ 0.85 | ISOLATE | SIGKILL + XDP + cgroup freeze + incident report |

PCABP consensus override: if `pcabp_score ≥ 0.40` and LLM says BENIGN, enforce at `pcabp_score` level anyway (LLM fooled by injection mimicry). Example: LLM BENIGN@0.05 + PCABP 0.515 → KILL tier.

---

## PCABP Module — Deep Dive

### Files

```
src/python/sentinel/pcabp/
├── __init__.py             exports ValidCallSiteMap, BehavioralEncoder, PCAPBScore
├── call_site_map.py        ELF-based bloom filter for valid call sites
├── behavioral_encoder.py   PyTorch contrastive encoder + offline trainer
├── pcabp_weights.pt        trained model weights (centroid_sep=1.717, ~35K params)
└── pcabp_centroids.pkl     in-binary + injected centroid vectors
```

### ValidCallSiteMap (`call_site_map.py`)

Built offline from the target binary (e.g., `/usr/sbin/nginx`):
```python
csm = ValidCallSiteMap.build("/usr/sbin/nginx")
csm.save("nginx_callsites.pkl")
# Later:
csm = ValidCallSiteMap.load("nginx_callsites.pkl")
is_valid, delta = csm.check(ip)   # O(1), delta = distance to nearest valid call site
region = csm.region(ip)           # "TEXT" | "HEAP_MMAP" | "UNKNOWN"
```

Bloom filter is SHA-256-based, configurable capacity/FPR. Falls back to E8 byte scan if capstone not available. Currently trained on synthetic data only — needs real nginx binary for production.

### BehavioralEncoder (`behavioral_encoder.py`)

```python
# Train (run once offline, ~30s on M5 CPU, no GPU needed):
python -m sentinel.pcabp.behavioral_encoder --train
# Saves: pcabp_weights.pt, pcabp_centroids.pkl

# Inference:
enc = BehavioralEncoder()  # loads weights automatically
score = enc.score(window, offset_deltas)  # → float ∈ [0,1]
# 0.0 = in-binary centroid (benign); 1.0 = injected centroid (malicious)
```

Feature vector per event: `[sc_type/16, log(offset_delta+1)/30, resource_type/8]`
Formula: `divergence = d_in / (d_in + d_out)` where d_in = distance from in-binary centroid.
**WARNING**: The formula is NOT `d_out / (d_in + d_out)` — that's inverted and was a past bug. Small d_in → small divergence → benign.

### Integration Points

PCABP is wired into the existing 3-stage pipeline in 4 places:

1. **DetectorAgent** (`sentinel/agents/detector.py`): Layer 0 — per-event static violation check before entropy triage. Triggers immediate LLM on first out-of-call-site IP detected.
2. **AnalyzerAgent** (`sentinel/agents/analyzer.py`): `_compute_pcabp(window)` called after LLM inference. Scores full window statically + AI. Results stored in `AnalysisResult.pcabp_*`.
3. **AuditorAgent** (`sentinel/agents/auditor.py`): Passes `pcabp_score` to `cwae.enforce()`. Also gates enforcement: if `pcabp_score ≥ 0.40` even on BENIGN, still enforce.
4. **CWAEEngine** (`sentinel/enforcement.py`): `effective_conf = max(llm_conf, pcabp_score)`. Logs `pcabp_confidence_override` when PCABP overrides LLM.

---

## eBPF Event Struct Layout

The `EventStruct` in `sentinel/bpf.py` must exactly match `struct event_t` in `sentinel.c`. Current layout (224 bytes total, packed):

| Field | Type | Offset | Notes |
|---|---|---|---|
| `ts_ns` | u64 | 0 | timestamp nanoseconds |
| `pid` | u32 | 8 | |
| `ppid` | u32 | 12 | |
| `uid` | u32 | 16 | |
| `gid` | u32 | 20 | |
| `sc_type` | u8 | 24 | SyscallType enum |
| `flags` | u8 | 25 | |
| `net_port` | u16 | 26 | |
| `net_ip4` | u32 | 28 | |
| `arm64_regs` | u64[3] | 32 | arm64 only (24 bytes) |
| `comm` | char[16] | 56 | process name |
| `resource` | char[128] | 72 | file path / socket addr |
| `original_comm` | char[16] | 200 | pre-prctl rename name |
| `user_ip` | u64 | 216 | PCABP: user-space call-site IP from bpf_get_stack |

**Historical note**: `arm64_regs[3]` and `original_comm` were missing from `bpf.py` until this was fixed. The struct was silently 56 bytes short, causing field misalignment in live eBPF mode. This is now corrected.

The `user_ip` is captured in `sentinel.c` via:
```c
static __always_inline __u64 _capture_user_ip(void *ctx) {
    __u64 user_stack[1] = {};
    long ret = bpf_get_stack(ctx, user_stack, sizeof(user_stack), BPF_F_USER_STACK);
    if (ret == sizeof(__u64)) return user_stack[0];
    return 0ULL;
}
```
Called in `trace_connect` and `trace_write`. `user_stack[0]` = return address of the call site that invoked connect/write in user space.

---

## File Layout (non-obvious parts)

```
src/python/
├── sentinel/           production package
│   ├── agents/
│   │   ├── auditor.py  Stage 3: CoVe + LTL + CWAE + PCABP consensus
│   │   └── analyzer.py Stage 2: IPG + LLM + PCABP scoring
│   ├── llm/
│   │   ├── base.py     DualTierClassifier (Algorithm 2)
│   │   ├── mock.py     heuristic fallback (no model needed)
│   │   └── ollama.py   Ollama HTTP async client
│   ├── pcabp/
│   │   ├── __init__.py
│   │   ├── call_site_map.py    ValidCallSiteMap (ELF bloom filter)
│   │   ├── behavioral_encoder.py  BehavioralEncoder (PyTorch contrastive)
│   │   ├── pcabp_weights.pt    trained weights (centroid_sep=1.717)
│   │   └── pcabp_centroids.pkl centroid vectors
│   ├── cove.py         CoVeLoop + EvidenceLinker
│   ├── egte.py         EscalationScorer + TierCalibrator + EGTEEngine
│   ├── ltl.py          RuntimeMonitor + BüchiMonitor + SymbolicGuardian
│   ├── schemas.py      Pydantic: TracedEvent, TraceWindow, SentinelAlertSchema
│   └── simulation.py   21 scenarios: 9 attack + 3 benign + 9 evasion
├── evaluate_darpa_tc.py  DARPA TC E3 CADETS evaluation script (see --help)
├── evaluation/
│   ├── cadets_ingestor.py     CDM18 JSONL streaming parser (DARPA TC)
│   ├── ipg_compression_eval.py  token reduction measurement (tiktoken)
│   ├── hallucination_eval.py    CoVe hallucination blocking test
│   ├── benchmark.py             DARPA TC + MITRE F1/TPR/FPR evaluation
│   ├── baseline_runner.py       Falco/OSSEC/DeepLog comparison
│   └── adversarial_tester.py    red-team evasion scenarios
└── tests/              201 pytest tests
    ├── test_ltl.py     37 tests
    ├── test_cove.py    28 tests
    └── test_egte.py    52 tests
```

---

## evaluate_darpa_tc.py — Key CLI Flags

```
python evaluate_darpa_tc.py --dataset cadets --max-windows 100 [OPTIONS]

--strip-annotations     Remove [C2]/[MALWARE]/[PARENT_CHAIN] from IPG YAML before LLM
                        inference. Without this flag, annotations appear in both ground
                        truth AND LLM input → circular evaluation (TI-AIDED mode).
                        Use this flag for honest behavioral comparison to WATSON/UNICORN.

--hard-fraction FLOAT   Fraction of attack windows that are "hard" nginx_ts windows
                        (no direct C2 signal). 0.0 = all easy/c2-detected (v8 default).
                        0.5 = balanced. 1.0 = all hard. Use 0.5 for honest comparison.

--out PATH              Output JSON path for results.

Example — honest behavioral evaluation (COMPLETED — F1=0.500):
  PYTHONPATH=. python3 evaluate_darpa_tc.py \
    --dataset cadets --max-windows 100 \
    --strip-annotations --hard-fraction 0.5 \
    --out ../../results/evaluations/darpa_tc_behavioral.json
  # Result: F1=0.500, TPR=0.360, FPR=0.080, Precision=0.818, Accuracy=0.640
```

---

## Configuration

Override any field via env vars: `SENTINEL__LLM__BACKEND=ollama`, `SENTINEL__MODE=simulation`, `SENTINEL__ENFORCEMENT__DRY_RUN=false`.

Constants that must stay in sync between `sentinel.c` and Python:
- `ENTROPY_WINDOW = 64` — in `agent.py` and `sentinel.c`
- `SC_TYPES = 16` — in `agent.py` and `sentinel.c`
- `EventStruct` layout in `bpf.py` must exactly match `struct event_t` in `sentinel.c` (224 bytes; see layout table above)

---

## Key Open Gaps Before IEEE TIFS Submission

**COMPLETED (GCP 2026-06-08, `results/evaluations_gcp/`):**
- ✅ Full eval chain + MANIFEST.json; 0 mock fallbacks on LLM evals
- ✅ DARPA hybrid v5 F1=0.603; LLM-only v4 F1=0.597; TI-aided v8 F1=0.915
- ✅ Ablation: graph-only F1=0.611; hybrid 1/100 LLM invocations
- ✅ Real strace n=104: TPR=0.714, FPR=0.291; LTL 0/387 FP
- ✅ IPG 74.0% @ n=20; dual-tier 35.7%; PCABP real nginx F1=1.0 (663 x86 sites)
- ✅ `paper/main.tex` synced to GCP JSONs; docs updated (RUNME, REPRO, diagrams)

**STILL OPEN (before IEEE TIFS submission):**

1. **Author metadata + PDF build** — affiliation, funding, `pdflatex`, page count ≤14
2. **CoVe Ollama measurement** — hallucination rate with structured `evidence_refs`
3. **High real-data FPR** (0.291) — analyze benign FP patterns; document in paper
4. **EGTE** — demoted from paper; code retained as future work
5. **Baseline honesty** — Falco/N-gram LR contamination fixes
6. **Live eBPF PCABP** — optional demo with non-zero `user_ip`

---

## Paper Submission Checklist

Before submitting to IEEE Manuscript Central (https://mc.manuscriptcentral.com/tifs-ieee):
- Fill author/affiliation in `paper/main.tex` lines 68–76
- Add funding acknowledgement in `\thanks{}` (line 77)
- Verify TikZ architecture diagram (Figure 1) renders (add PCABP as 7th contribution box)
- Check page count ≤ 14 pages
- Run `chktex main.tex`
- **[DONE]** GCP DARPA: v5 hybrid F1=0.603, v4 LLM-only F1=0.597, TI-aided F1=0.915 (`results/evaluations_gcp/`)
- **[DONE]** Section V-B dual-tier 35.7%; Section V-D DARPA + ablation tables synced
- **[DONE]** PCABP real nginx x86 (663 sites) in `pcabp_real_nginx_gcp.json`
- [ ] Author/affiliation, funding, final PDF build
