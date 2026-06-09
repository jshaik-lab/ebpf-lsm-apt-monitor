# Option A Implementation Prompt (copy-paste for AI agent)

Use this prompt in Cursor Agent, Claude Code on GCP, or any coding agent.
Repository: `ebpf-lsm-apt-monitor` (SENTINEL → IEEE TIFS).

---

## PROMPT START — copy everything below this line

You are implementing **SENTINEL Option A** for an IEEE TIFS submission.

### Thesis (do not deviate)

SENTINEL is **not** an "LLM beats provenance detectors" paper. It is an **IPG-centric forensic architecture**:

1. **Intent Provenance Graph (IPG)** = unified intermediate representation (IR) consumed by:
   - Graph-ML / deterministic scorer (**primary detector**)
   - LLM (**MITRE attribution + natural-language explanation only**, not sole classifier)
   - LTL symbolic guardian (hard safety floors)
   - CoVe (evidence grounding to `event_id` UUIDs)
   - CWAE enforcement (graduated response from **fused** scores, not raw LLM confidence)

2. **Honest evaluation**: DARPA TC behavioral F1 with LLM-only is ~0.47 (GCP). That is expected and must be reported. Graph-first fusion is the fix, not better prompts alone.

3. **Authoritative results**: `results/evaluations_gcp/*_gcp.json` on GCP `sentinel-gpu-vm` (g2-standard-4, NVIDIA L4). Do **not** cite IONOS or Mac `results/evaluations/` files.

---

### Phase 1 — Code: IPG analysis + graph-first detector

#### 1.1 Refactor `src/python/sentinel/ipg.py`

Add a dataclass and method:

```python
@dataclass
class IPGMeta:
    n_nodes: int
    n_edges: int
    outbound_ext: int
    exec_after_net: bool
    unusual_comm: bool
    sensitive_reads: int
    tmp_exec: bool
    external_connect: bool

class IPGBuilder:
    def analyze(self, G: nx.MultiDiGraph) -> IPGMeta: ...
    def serialize(self, G, meta: IPGMeta | None = None) -> str: ...
```

- Move meta pre-scan logic from `serialize()` into `analyze()`.
- `serialize()` calls `analyze()` if meta not passed.
- Add helpers: `_has_tmp_exec(G)`, `_count_sensitive_reads(G)`.

Add unit tests in `src/python/tests/test_ipg.py` for `analyze()`.

#### 1.2 New module `src/python/sentinel/provenance_ml/`

```
provenance_ml/
├── __init__.py
├── features.py      # IPGMeta + nx graph → float feature vector
├── scorer.py        # Deterministic ProvenanceScorer (weighted meta + paths)
├── detector.py      # Optional LightGBM wrapper (train/predict_proba)
└── fusion.py        # Algorithm 4: fuse graph + LTL + PCABP + LLM
```

**`features.py`** — extract ≥20 features from IPG graph:
- `n_nodes`, `n_edges`, structural entropy, `outbound_ext`, `exec_after_net`, `unusual_comm`
- counts of connect/execve/openat to `/tmp`, `/var/log`, `/etc/shadow`
- comm entropy, max parallel edge count, `ext_outbound` edge count

**`scorer.py`** — deterministic score ∈ [0, 1]:
```python
def provenance_score(meta: IPGMeta, G: nx.MultiDiGraph) -> float:
    # Start with hand-tuned weights; fit weights on benign CADETS windows optional
```

**`fusion.py`** — core fusion (Algorithm 4):
```python
def fuse_scores(
    graph_score: float,
    llm_label: str,
    llm_conf: float,
    ltl_severity: float,      # 0–1 from SymbolicGuardian
    pcabp_score: float = 0.0,
    cove_cap: float | None = None,
) -> tuple[str, float]:
    effective = max(graph_score, pcabp_score)
    if ltl_severity >= 0.7:
        effective = max(effective, ltl_severity)
    if llm_label == "MALICIOUS":
        effective = max(effective, llm_conf)
    if cove_cap is not None:
        effective = min(effective, cove_cap)
    label = "MALICIOUS" if effective >= 0.50 else "BENIGN"
    return label, effective
```

#### 1.3 Wire into `src/python/evaluate_darpa_tc.py`

In `evaluate()`:

1. **Parent injection** (missing today — exists in `agent.py`):
   - Maintain `pid_buffers: dict[int, list[KernelEvent]]` while iterating windows.
   - Before `build()`, call `ipg_builder.inject_parent_events(w.events, parent_buffers[ppid], max_parent=5)` when ppid known.

2. **Graph-first classification**:
   ```python
   G = ipg_builder.build(enriched_events)
   meta = ipg_builder.analyze(G)
   graph_score = provenance_score(meta, G)
   
   # Gray zone → LLM for attribution; high/low → skip LLM for label
   if graph_score >= 0.55:
       pred_label, pred_conf = "MALICIOUS", graph_score
       llm_decision = await classifier.classify(ipg_text)  # TTPs only
   elif graph_score <= 0.15:
       pred_label, pred_conf = "BENIGN", 1.0 - graph_score
       llm_decision = None
   else:
       llm_decision = await classifier.classify(ipg_text)
       pred_label = llm_decision.label
       pred_conf = llm_decision.confidence
   
   # Optional: LTL floor via SymbolicGuardian on enriched_events
   final_label, final_conf = fuse_scores(graph_score, pred_label, pred_conf, ltl_sev, ...)
   ```

3. **CLI flags**:
   - `--detector-mode {llm_only,graph_only,hybrid}` (default: `hybrid` for paper)
   - `--graph-threshold-high 0.55 --graph-threshold-low 0.15`
   - Remove default `cove_ablation=True` on behavioral runs

4. **Output JSON** per window: add fields `graph_score`, `detector_mode`, `llm_invoked: bool`.

5. **Write results** to `results/evaluations_gcp/darpa_tc_behavioral_v5_gcp.json`.

#### 1.4 Wire into production pipeline

Update `src/python/sentinel/agents/analyzer.py` and `auditor.py`:
- Analyzer computes `graph_score` alongside LLM.
- Auditor `fuse_scores()` before CWAE (replace `max(llm_conf, pcabp)` only path).

Keep backward compat: `SENTINEL__DETECTOR_MODE=llm_only` for tests.

#### 1.5 Ablation eval script

New: `src/python/evaluate_darpa_ablation.py`

Runs 5 modes on same 100 windows (can subsample for dev):
| Mode | graph | LLM label | LTL | PCABP |
|------|-------|-----------|-----|-------|
| llm_only | ✗ | ✓ | ✗ | ✗ |
| graph_only | ✓ | ✗ | ✗ | ✗ |
| hybrid | ✓ | gray | ✗ | ✗ |
| hybrid_ltl | ✓ | gray | ✓ | ✗ |
| full | ✓ | gray | ✓ | ✓ |

Output: `results/evaluations_gcp/darpa_ablation_gcp.json` with F1 per row.

#### 1.6 Tests

- `tests/test_provenance_ml.py` — scorer monotonicity, fusion logic
- `tests/test_ipg.py` — analyze() parity with serialize meta
- Existing 201+ tests must pass: `make test`

---

### Phase 2 — Optional graph ML (if time)

`src/python/sentinel/provenance_ml/detector.py`:
- Train `sklearn.ensemble.GradientBoostingClassifier` or LightGBM on feature vectors.
- Train on benign-only windows (UNICORN-style) OR supervised with held-out nginx_backdoor epoch.
- Save model to `sentinel/provenance_ml/cadets_gbdt.pkl`.
- Integrate as `graph_score = max(provenance_score, gbdt.predict_proba)`.

Do **not** block Phase 1 on this.

---

### Phase 3 — Paper rewrite (`paper/main.tex`) for Option A

#### Abstract (replace detection claims)

- Lead: IPG as unified forensic IR.
- Numbers from GCP (measured 2026-06-08): 74.0% token reduction, DARPA hybrid F1=0.603, TI-aided F1=0.915 with caveat.
- State: "graph-first detection with LLM attribution and evidence-gated enforcement."
- Remove: "LLM achieves SOTA", "100% scenario accuracy" as headline.

#### Contributions (reduce to 4–5)

1. IPG unified IR (ML + LLM + LTL + CoVe consumers)
2. Hybrid fusion (Algorithm 4) with ablation
3. CWAE from fused scores (motivated by ECE 0.19 on raw LLM)
4. LTL symbolic guardian (0 FPR on 387 benign windows, GCP)
5. PCABP orthogonal injection axis (caveat controlled eval)

**Demote** to future work unless measured: TLS uprobe, EGTE, fleet K8s.

#### Section V tables (sync to GCP)

| File | Use |
|------|-----|
| `scenario_results_gcp.json` | 14/14 simulation (mechanism demo) |
| `dual_tier_reduction_gcp.json` | 35.7% reduction, 12/14 dual vs 14/14 8B |
| `ipg_token_reduction_gcp.json` | 74.0% @ n=20; 92.7% full trace |
| `real_data_results_gcp.json` | TPR=0.714, FPR=0.291, Acc=0.712 |
| `darpa_tc_behavioral_v5_gcp.json` | F1=0.603 hybrid behavioral |
| `darpa_tc_behavioral_v4_gcp.json` | F1=0.597 LLM-only |
| `darpa_tc_v8_ti_aided_gcp.json` | F1=0.915 + circularity paragraph |
| `darpa_ablation_gcp.json` | Ablation table (graph F1=0.611) |
| `ltl_fpr_real_gcp.json` | 0/387 FPR |
| `pcabp_real_nginx_gcp.json` | F1 1.0 + caveat |
| `overhead_gcp.json` | Non-LLM latency |
| `calibration_results_gcp.json` | ECE 0.192 |

Replace all `*_ionos.json`, `IONOS VPS`, `<IONOS-VPS-IP>` with GCP platform string from meta.

#### New ablation table (Section V)

```latex
% Rows: LLM-only | Graph-only | Hybrid | Hybrid+LTL | Full
% Cols: F1, TPR, FPR, LLM invocations, mean latency
```

#### Limitations (keep prominent)

- nginx_backdoor mimicry ceiling
- TI-aided circularity
- PCABP controlled classes
- LLM calibration insufficient for raw-confidence enforcement

---

### Phase 4 — GCP re-run

On `sentinel-gpu-vm` after code deploy:

```bash
export SENTINEL__LLM__BACKEND=ollama
export SENTINEL__LLM__TIMEOUT_SECONDS=300
export SENTINEL_EVAL_PLATFORM="GCP g2-standard-4 Ubuntu 24.04; NVIDIA L4; Ollama llama3.1:8b"
export SENTINEL_GIT_SHA=$(git rev-parse HEAD)
export PYTHONPATH=src/python

# Unit tests
make test

# Ablation + behavioral v5
python3 src/python/evaluate_darpa_ablation.py \
  --dataset cadets --max-windows 100 \
  --strip-annotations --hard-fraction 0.5 \
  --darpa-path data/darpa/ta1-cadets-e3-official.json.2 \
  --out results/evaluations_gcp/darpa_ablation_gcp.json

python3 src/python/evaluate_darpa_tc.py \
  --dataset cadets --max-windows 100 \
  --strip-annotations --hard-fraction 0.5 \
  --detector-mode hybrid \
  --out results/evaluations_gcp/darpa_tc_behavioral_v5_gcp.json

python3 scripts/generate_manifest.py results/evaluations_gcp/
```

Sync `results/evaluations_gcp/` back to Mac. Rebuild paper PDF.

---

### Constraints (must follow)

- **Never** cite MockClassifier results in paper tables.
- **Never** claim TI-aided F1 is competitor-comparable without caveat.
- **Never** lead abstract with LLM-only DARPA F1.
- Minimize diff scope — reuse `IPGBuilder`, `SymbolicGuardian`, `CWAEEngine`, `provenance.py`.
- `make test` and `make lint` must pass before commit.
- Do not change the seven/eight mechanism algorithms in ways that break unit tests without updating tests.
- Paper ≤ 14 pages.

---

### Definition of done

- [ ] `IPGBuilder.analyze()` + tests
- [ ] `sentinel/provenance_ml/` with scorer + fusion
- [ ] `evaluate_darpa_tc.py` hybrid mode + parent injection
- [ ] `evaluate_darpa_ablation.py` + `darpa_ablation_gcp.json`
- [x] `darpa_tc_behavioral_v5_gcp.json` F1=0.603 > v4 F1=0.597 (precision/FPR improved)
- [x] Analyzer/Auditor use fusion in production path (`AgentPipeline`)
- [x] `paper/main.tex` Option A abstract + contributions + ablation table
- [x] All cited numbers from `results/evaluations_gcp/`
- [x] `MANIFEST.json` regenerated
- [x] `docs/RUNME.md` updated for GCP-only

Report completion with:
1. Ablation F1 table (all 5 modes)
2. v4 vs v5 behavioral F1 delta
3. List of paper sections changed
4. Remaining blockers for IEEE submission

## PROMPT END

---

## How to use

**Cursor:**
```
@docs/OPTION_A_IMPLEMENTATION_PROMPT.md

Implement Phase 1 and Phase 3. Run tests locally. Do not re-run GCP evals unless I start the VM.
```

**GCP agent (VM running):**
```
Read docs/OPTION_A_IMPLEMENTATION_PROMPT.md and implement Phases 1–4 completely.
Deploy from Mac via rsync or git pull first.
```

**Phased:**
- Session 1: Phase 1 code only
- Session 2: GCP re-run (Phase 4)
- Session 3: Phase 3 paper sync
