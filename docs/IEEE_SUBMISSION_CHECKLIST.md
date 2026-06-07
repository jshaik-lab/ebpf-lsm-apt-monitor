# IEEE TIFS Submission Checklist — SENTINEL (Paper 1)

**Target venue:** IEEE Transactions on Information Forensics and Security (TIFS)  
**Page limit:** ≤14 pages (IEEEtran journal)  
**Source of truth for numbers:** `results/evaluations/*.json`  
**Last updated:** 2026-06-07

---

## Definition of “submission-ready”

All items in **Section A (Blockers)** must be checked before upload to IEEE Manuscript Central.  
Sections B–F strengthen acceptability; G is optional polish.

---

## A. Blockers (must complete)

### A1. Evaluation platform

- [ ] Primary experiments run on **native Linux** (IONOS VPS XL or equivalent), not Mac-only Docker Desktop
- [ ] Platform table in Section V: Ubuntu version, `uname -r`, CPU, RAM, Ollama model tags
- [ ] Remove abstract/conclusion language: *“Live eBPF … deferred to follow-on work”* (once measured or scoped down)

### A2. Real syscall corpus (replace n=15)

- [ ] Expand `capture_real_traces.sh` → **≥50 benign + ≥50 attack** traces (minimum **≥30/30** if time-bound)
- [ ] Benign diversity: nginx, sshd, postgres, apt, cron, systemd, shells (not only `cat`/`which`)
- [ ] Re-run: `make capture-traces` → `make eval-real` → `make eval-calibration`
- [ ] Report TPR, FPR, precision, F1, **bootstrap 95% CIs**
- [ ] Document/fix known FPs: `benign_python_json`, `benign_which_bash` (ablation before/after)
- [ ] **Never cite MockClassifier results** in the paper

**Current baseline:** n=15, FPR=0.286, CI [66.7%, 100%] — `real_data_results.json`

### A3. DARPA TC E3 CADETS (measured, not yet in paper)

- [ ] Upload dataset to VPS: `ta1-cadets-e3-official.json.2`
- [ ] Run `make eval-darpa-tc` (100 windows) and `make eval-darpa-tc-full` (400 windows)
- [ ] Write **Section V-D** with dual-mode table:

  | Mode | F1 | TPR | FPR | Files |
  |------|-----|-----|-----|-------|
  | Behavioral (`--strip-annotations`) | 0.568 | 0.42 | 0.06 | `darpa_tc_behavioral_v4.json` |
  | TI-aided (v8) | 0.931 | 0.94 | 0.08 | `darpa_tc_v8_ti_aided.json` |

- [ ] **Honesty paragraph:** TI-aided uses `[C2]`/`[MALWARE]` from same list as ground truth — not comparable to WATSON/UNICORN behavioral F1
- [ ] Error analysis: 7 remaining v8 errors (3 FN, 4 FP)
- [ ] Replace all TeX “DARPA planned follow-on” (~8 occurrences) with results or explicit out-of-scope

### A4. Paper ↔ JSON sync

- [ ] Dual-tier: **35.7%** invocation reduction (not 94.7%) — `dual_tier_reduction.json`
- [ ] IPG: **59.8%** token reduction at n=20 — `ipg_token_reduction.json`
- [ ] Memory: **~60.6 MB** Python RSS (not <15 MB) — `claims_validation_summary.json`
- [ ] Abstract contribution count matches intro + Section IV (currently inconsistent: “nine” vs body)
- [ ] Remove/replace every grep hit: `planned`, `deferred`, `follow-on work` in `paper/main.tex`

### A5. Scientific narrative

- [ ] One clear thesis: framework + honest DARPA dual-mode + evidence-grounded enforcement
- [ ] Do **not** claim behavioral SOTA on DARPA vs WATSON/UNICORN without TI caveat
- [ ] Prominent **Limitations** subsection: mimicry ceiling (24/25 nginx_backdoor windows), calibration, PCABP synthetic eval

### A6. IEEE submission metadata

- [ ] Author/affiliation filled (`paper/main.tex` ~lines 68–76)
- [ ] `\thanks{}` funding acknowledgement
- [ ] Manuscript date placeholders replaced
- [ ] `cd paper && pdflatex && bibtex && pdflatex ×2` — clean build
- [ ] `chktex main.tex` — address critical warnings
- [ ] Page count ≤14

---

## B. Strongly recommended (major revision risk if skipped)

### B1. Dual-tier + scenarios on Linux

- [ ] Re-run `make eval-scenarios` with Ollama on Linux VPS
- [ ] Report draft vs full **latency p50/p99** on Linux
- [ ] Document 2 draft FNs (T1210, T1078) and 1× 8B FN (T1041) in Section V-B

### B2. CoVe / hallucination (real LLM)

- [ ] `OllamaClassifier` populates structured `evidence_refs` / event linkage
- [ ] Fix or replace stale `src/python/evaluation/hallucination_eval.py` (wrong imports)
- [ ] Measure: hallucination_rate, downgrade count, enforcements with verified `event_id`s
- [ ] Replace “zero hallucinations” with measured N/M bound

### B3. LTL on real benign workloads

- [ ] Run SymbolicGuardian on **≥50 benign real windows**
- [ ] Report LTL FPR (current: 0 FP on **3 synthetic** scenarios only)
- [ ] Keep red-team / evasion scenarios in §Security Analysis

### B4. Confidence calibration

- [ ] n≥200 predictions for ECE (current: n=15, ECE=0.174)
- [ ] Temperature scaling ablation (`sentinel/llm/temperature.py`)
- [ ] Reliability diagram figure in paper

### B5. Baselines (honesty)

- [ ] Falco: run real Falco OR relabel as “rule-inspired Python baseline”
- [ ] N-gram LR: fix train/test split contamination in `evaluate_baselines.py`
- [ ] Tracee: `make eval-tracee` on Linux if cited

### B6. Overhead on Linux

- [ ] `make benchmark-overhead` on VPS
- [ ] `make benchmark-sysbench` (optional, supports <3% CPU claim for non-LLM path)
- [ ] Ollama E2E latency table (Linux)

---

## C. Per-contribution completion

| # | Contribution | Code | Paper | Eval action |
|---|--------------|------|-------|-------------|
| 1 | LSM-eBPF TOCTOU | `src/bpf/sentinel.c` | ✓ | Live attach smoke test on Linux |
| 2 | IPG | `sentinel/ipg.py` | ✓ | Re-run token eval; n≥6 traces |
| 3 | Dual-tier LLM | `sentinel/llm/base.py` | ✓ | Linux Ollama re-measure |
| 4 | SSL/TLS uprobe | partial | ✓ | `make eval-tls` — cite or demote |
| 5 | CWAE | `sentinel/enforcement.py` | ✓ | Overhead on Linux |
| 6 | CoVe | `sentinel/cove.py` | ✓ | Ollama measurement (B2) |
| 7 | LTL guardian | `sentinel/ltl.py` | ✓ | Real benign FPR (B3) |
| 8 | PCABP | `sentinel/pcabp/` | ✓ | Synthetic caveat + x86 nginx map on VPS; live `user_ip` ideal |
| 9 | EGTE | `sentinel/egte.py` | **✗ not in main.tex** | **Either:** Section IV-G + calibration eval **or** remove from claims |

---

## D. Live eBPF (kernel credibility)

Pick one path:

**Path 1 — Full (preferred):**
- [ ] `make up-ebpf` on Linux VPS (privileged)
- [ ] Events → IPG → Ollama → audit log with non-zero `user_ip` (PCABP)
- [ ] Document `CONFIG_BPF_LSM`, hook attach success

**Path 2 — Narrow claims:**
- [ ] Paper states: userspace pipeline validated on strace-equivalent events; BPF in appendix as prototype
- [ ] No live enforcement claims in abstract

---

## E. Reproducibility & engineering

- [ ] `REPRO.md`: VPS setup, Ollama install, eval command sequence, expected runtime
- [ ] `make test` passes (`requirements-dev.txt`)
- [ ] `make lint` / `make type-check` clean (or document known exceptions)
- [ ] Tag Git release matching submission date
- [ ] Update stale `docs/ACTION_PLAN.md`
- [ ] DARPA dataset availability statement (public TC E3 link)

---

## F. Related work & differentiation

- [ ] CP-in-security / selective prediction (brief — differentiate EGTE if kept)
- [ ] Provenance APT: WATSON, UNICORN, ProvDetector, DEPIMPACT — behavioral compare via DARPA only
- [ ] Falco/Tetragon tracepoint vs LSM — your TOCTOU argument
- [ ] CoVe — cite prior NLP work; your contribution = eBPF `event_id` grounding

---

## G. Optional (acceptability boost)

- [ ] EGTE: benign calibration JSONL ≥100 windows; empirical over-escalation rate vs α
- [ ] TOCTOU micro-benchmark: symlink race, LSM vs tracepoint (small n)
- [ ] Zenodo artifact / supplementary JSON bundle
- [ ] Second reviewer pass: external colleague read

---

## Quick reference — key result files

| File | Use in paper |
|------|----------------|
| `real_data_results.json` | Table: real strace eval |
| `dual_tier_reduction.json` | Section V-B |
| `ipg_token_reduction.json` | Compression table |
| `darpa_tc_behavioral_v4.json` | DARPA behavioral |
| `darpa_tc_v8_ti_aided.json` | DARPA TI-aided (caveat) |
| `pcabp_results.json` | PCABP (synthetic caveat) |
| `calibration_results.json` | ECE / reliability |
| `claims_validation_summary.json` | Overhead audit |
| `baseline_comparison.json` | Fix before citing |
| `red_team_results.json` | §Security Analysis |

---

## Progress tracker

| Section | Status | Notes |
|---------|--------|-------|
| A Blockers | 🟡 In progress | SSH key generated; authorize on VPS (docs/IONOS_SSH_SETUP.md) |
| B Recommended | ⬜ | Pending VPS eval runs |
| C Contributions | 🟡 | DARPA in paper; EGTE noted as optional/disabled |
| D eBPF | ⬜ | After SSH + bootstrap |
| E Repro | ✅ | docs/REPRO.md, scripts/bootstrap_ionos.sh |
| F Related work | 🟡 | DARPA competitor table in paper |
| G Optional | ⬜ | |

**GitHub:** https://github.com/jshaik-lab/Paper1_ZeroTrustAgent  
**Submission target date:** _______________
