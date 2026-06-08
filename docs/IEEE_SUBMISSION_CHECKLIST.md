# IEEE TIFS Submission Checklist — SENTINEL (Paper 1)

**Target venue:** IEEE Transactions on Information Forensics and Security (TIFS)  
**Page limit:** ≤14 pages (IEEEtran journal)  
**Source of truth:** `results/evaluations_gcp/*_gcp.json` + `MANIFEST.json`  
**Operations runbook:** [RUNME.md](RUNME.md)  
**Diagrams:** [sentinel_diagrams.html](sentinel_diagrams.html) (Results tab)  
**Last updated:** 2026-06-08 (GCP full eval + `paper/main.tex` sync)

---

## GCP platform (authoritative)

| Field | Value |
|-------|--------|
| Instance | `sentinel-gpu-vm` @ `34.74.43.57` (zone `us-east1-c`) |
| Machine | g2-standard-4, NVIDIA L4 24 GB, 16 GB RAM |
| OS / kernel | Ubuntu 24.04, `6.17.0-1018-gcp`, x86_64 |
| Ollama | `llama3.1:8b` (full), `llama3.2:1b` (draft) |
| Eval date | 2026-06-08 UTC |
| Mock fallbacks | **0** on all cited LLM JSONs |

**Deprecated:** Mac Docker pilots, IONOS `*_ionos.json` — do not cite.

---

## Paper ↔ GCP JSON sync matrix

Every number below is from the **2026-06-08 GCP run** and is reflected in `paper/main.tex` (abstract, §V, limitations, conclusion).

| Paper claim | GCP value | JSON file |
|-------------|-----------|-----------|
| IPG token reduction @ n=20 | **57.5%** (1105→470 tok avg, 5 attack traces) | `ipg_token_reduction_gcp.json` |
| IPG token reduction full trace | **83.3%** (4707→785 tok avg) | `ipg_token_reduction_gcp.json` |
| Dual-tier invocation reduction | **35.7%** (5/14 draft hits) | `dual_tier_reduction_gcp.json` |
| Dual-tier accuracy | 12/14 dual vs **14/14** 8B-only | `dual_tier_reduction_gcp.json` |
| MITRE scenarios (8B-only) | **14/14** correct | `scenario_results_gcp.json` |
| Real strace TPR / FPR / Acc | **0.714 / 0.273 / 0.721** (θ=1.2 gate; ungated FPR=0.291) | `entropy_sensitivity_gcp.json` |
| Real strace accuracy 95% CI | **[0.625, 0.798]**, n=104 | `real_data_results_gcp.json` |
| Calibration ECE | **0.205**, n=104 | `calibration_results_gcp.json` |
| LTL FPR (benign) | **0.0** (0/13 windows, 7 traces on eval host) | `ltl_fpr_real_gcp.json` |
| PCABP real nginx | F1=**1.0** (controlled classes), 663 x86 sites | `pcabp_real_nginx_gcp.json` |
| IPG build p50 / CWAE p50 | **0.195 ms / 1.023 ms** | `overhead_gcp.json` |
| Detector throughput | **27,454 events/s** | `overhead_gcp.json` |
| RSS (benchmark snapshot) | 48.1 MB (delta 0 in dry-run bench) | `overhead_gcp.json` |
| DARPA hybrid behavioral (v5) | F1=**0.603**, TPR=0.44, FPR=0.02, Prec=0.957 | `darpa_tc_behavioral_v5_gcp.json` |
| DARPA LLM-only (v4) | F1=**0.597**, TPR=0.46, FPR=0.08, Prec=0.852 | `darpa_tc_behavioral_v4_gcp.json` |
| DARPA TI-aided (v8) † | F1=**0.915**, TPR=0.86, FPR=0.02, Prec=0.977 | `darpa_tc_v8_ti_aided_gcp.json` |
| TI-aided errors (GCP) | **7 FN + 1 FP** (not prior Mac 3+4) | `darpa_tc_v8_ti_aided_gcp.json` |

† TI-aided uses `[C2]`/`[MALWARE]` from same list as ground truth — not competitor-comparable.

### Ablation (Table tab:ablation in paper)

| Mode | F1 | TPR | FPR | LLM calls | Mean latency |
|------|-----|-----|-----|-----------|--------------|
| `llm_only` | 0.603 | 0.44 | 0.02 | 100 | **7484 ms** (re-run ablation) |
| `graph_only` | 0.611 | 0.44 | 0.00 | 0 | <1 ms |
| `hybrid` | 0.603 | 0.44 | 0.02 | **1** | **75 ms** |
| `hybrid_ltl` | 0.611 | 0.44 | 0.00 | 1 | 75 ms |
| `full` | 0.611 | 0.44 | 0.00 | 1 | 75 ms |

Source: `darpa_ablation_gcp.json` (regenerated 2026-06-08 with `evaluate_darpa_ablation.py` latency fix).

### Ship gate

```bash
make validate-paper-claims   # blocks submission if paper ≠ GCP JSON
make paper-build             # validate + PDF (scripts/build_paper.sh)
```

`scripts/gcp_orchestrate.sh` runs the same validator after pulling artifacts from the VM.

### vs. published competitors (behavioral-only, no TI oracle)

| System | Published F1 | SENTINEL behavioral |
|--------|--------------|---------------------|
| WATSON | 0.82 | 0.603 (hybrid) / 0.597 (LLM-only) |
| UNICORN | 0.88 | below |
| ProvDetector | 0.87 | below |
| DEPIMPACT | 0.91 | below |

---

## A. Blockers (must complete)

### A1. Evaluation platform

- [x] Primary experiments on **GCP GPU VM** (`sentinel-gpu-vm`)
- [x] Platform string in JSON `meta.platform`
- [x] Mac/IONOS results superseded in §V setup paragraph
- [ ] Live eBPF on GCP VM with non-zero `user_ip` (optional; currently strace-replay path)

### A2. Real syscall corpus

- [x] **105 traces** (55 benign + 50 attack), native Linux strace on GCP
- [x] `real_data_results_gcp.json` with bootstrap CIs
- [x] `ollama_fallback_to_mock_count: 0`
- [ ] Document/mitigate high FPR — **0.273** at production θ=1.2 (ungated LLM **0.291**)

### A3. DARPA TC E3 CADETS

- [x] Dataset on VM (`ta1-cadets-e3-official.json.2`)
- [x] 100-window hybrid v5, LLM-only v4, TI-aided v8, 5-mode ablation
- [x] §V-D table + honesty paragraph in `paper/main.tex`
- [x] TI-aided GCP error count: **7 FN, 1 FP** (re-counted from GCP JSON)
- [ ] Optional: 400-window `eval-darpa-tc-full` for tighter CIs

### A4. Paper ↔ JSON sync

- [x] Dual-tier **35.7%** — not legacy 94.7%
- [x] IPG **57.5% / 83.3%** on GCP subset (15 files; not legacy 74%/92.7% estimates)
- [x] DARPA F1 **0.603 / 0.597 / 0.915** — not legacy 0.568 / 0.625 / 0.931
- [x] Real-data **n=104** — not legacy n=15 pilot
- [ ] RSS wording in paper vs `overhead_gcp.json` (48.1 MB bench snapshot)
- [ ] Contribution count: intro lists **5** items; conclusion says **eight** — reconcile
- [x] No `planned` / `deferred` / `follow-on` in body (only historical comment on n=15)
- [x] **`make validate-paper-claims`** passes (15 checks vs `results/evaluations_gcp/*.json`)

### A5. Scientific narrative

- [x] Behavioral F1 below WATSON/UNICORN — honest mimicry ceiling
- [x] TI-aided circularity in Limitations (L2)
- [x] Ablation: graph-first resolves 99/100 windows without LLM

### A6. IEEE submission metadata

- [ ] Author/affiliation (`paper/main.tex` ~lines 68–76)
- [ ] `\thanks{}` funding acknowledgement
- [ ] Manuscript date placeholders
- [ ] **PDF build** (run locally — see below)
- [ ] `chktex main.tex`
- [ ] Page count ≤14

**Build command (Mac with MacTeX / TeX Live):**

```bash
cd paper
export PATH="/Library/TeX/texbin:$PATH"   # MacTeX
pdflatex -interaction=nonstopmode main
bibtex main
pdflatex -interaction=nonstopmode main
pdflatex -interaction=nonstopmode main
chktex main.tex
# Page count:
pdfinfo main.pdf | grep Pages
open main.pdf
```

Or: `bash scripts/build_paper.sh` (added to repo).

---

## B. Strongly recommended

| Item | Status | GCP artifact |
|------|--------|--------------|
| Scenarios 14/14 on Ollama | ✅ | `scenario_results_gcp.json` |
| Dual-tier 35.7% + draft FN analysis | ✅ | `dual_tier_reduction_gcp.json` |
| LTL 0 FPR on real benign | ✅ | `ltl_fpr_real_gcp.json` (13 windows, 7 traces) |
| Calibration ECE | 🟡 | ECE=0.205, n=104 — severely miscalibrated |
| CoVe Ollama measurement | ⬜ | MockClassifier still in some paths |
| Falco / N-gram baseline honesty | ⬜ | Relabel or fix contamination |
| Ollama per-window latency table | ⬜ | Extract from `gcp_chain.log` |

---

## C. Per-contribution (GCP measured)

| # | Contribution | Paper § | GCP evidence |
|---|--------------|---------|--------------|
| 1 | LSM-eBPF TOCTOU | IV-A | Prototype `sentinel.c`; strace validation |
| 2 | IPG | IV-B | 57.5% @ n=20 |
| 3 | Hybrid graph-first + dual-tier | IV-C | Ablation + 35.7% |
| 4 | LTL + PCABP floors | IV-E, IV-H | 0/13 LTL FPR (7 traces); PCABP F1=1.0 controlled |
| 5 | CWAE + CoVe fusion | IV-D, IV-F | overhead_gcp; CoVe needs Ollama eval |
| — | EGTE | (demoted) | Code only; disabled by default |
| — | SSL/TLS uprobe | partial | Cite or demote in revision |

---

## D–G. Unchanged scope

- **Live eBPF:** optional Path 1; Path 2 (strace-replay) is current paper scope.
- **Repro:** [REPRO.md](REPRO.md), [RUNME.md](RUNME.md), `MANIFEST.json` ✅
- **Zenodo / git tag:** pending submission date.

---

## Progress tracker

| Section | Status |
|---------|--------|
| GCP eval chain | ✅ Complete 2026-06-08 |
| `paper/main.tex` numbers | ✅ Synced to GCP JSONs |
| Documentation | ✅ RUNME, REPRO, diagrams, CLAUDE.md |
| PDF build | 🟡 Run locally (`pdflatex` not in agent sandbox) |
| Author metadata | ⬜ |
| CoVe real-LLM eval | ⬜ |

**GitHub:** https://github.com/jshaik-lab/Paper1_ZeroTrustAgent  
**Submission target date:** _______________
