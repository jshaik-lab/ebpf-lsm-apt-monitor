# SENTINEL — Run Me (GCP Operations Guide)

**Purpose:** Reproduce paper-grade evaluations on the GCP GPU VM and sync results for IEEE TIFS submission.

| Document | Purpose |
|----------|---------|
| [GCP_SETUP_GUIDE.md](GCP_SETUP_GUIDE.md) | VM specs, SSH, start/stop, cost |
| [OPTION_A_IMPLEMENTATION_PROMPT.md](OPTION_A_IMPLEMENTATION_PROMPT.md) | Option A architecture spec |
| [IEEE_SUBMISSION_CHECKLIST.md](IEEE_SUBMISSION_CHECKLIST.md) | Submission blockers tracker |
| [sentinel_diagrams.html](sentinel_diagrams.html) | Architecture + data-flow diagrams |

**GitHub:** https://github.com/jshaik-lab/Paper1_ZeroTrustAgent

---

## Platform policy

| Platform | Role |
|----------|------|
| **GCP GPU VM** (`sentinel-gpu-vm`) | **Authoritative** for all paper-reported numbers |
| **Mac** | Dev only: `make test`, lint, edit, rsync to GCP |
| **IONOS VPS** | **Deprecated** — do not cite `_ionos.json` results |

**Source of truth:** `results/evaluations_gcp/*_gcp.json` + `MANIFEST.json`

---

## GCP VM quick reference

| Item | Value |
|------|--------|
| Instance | `sentinel-gpu-vm` |
| Zone | `us-east1-c` |
| IP | `34.74.43.57` |
| SSH user | `sentinel` |
| SSH key | `~/.ssh/id_ed25519_sentinel` |
| Machine | g2-standard-4 + NVIDIA L4 24 GB |
| Ollama models | `llama3.1:8b` (full), `llama3.2:1b` (draft) |
| DARPA dataset (on VM) | `data/darpa/ta1-cadets-e3-official.json.2` |

```bash
# Start VM (GCP Console or gcloud after auth login)
gcloud compute instances start sentinel-gpu-vm --zone=us-east1-c

# SSH
ssh -i ~/.ssh/id_ed25519_sentinel sentinel@34.74.43.57

# Stop VM (save compute cost — disk billing continues ~$10/mo)
gcloud compute instances stop sentinel-gpu-vm --zone=us-east1-c
```

---

## Architecture (code path)

`main.py` → `SentinelAgent` → **`AgentPipeline`** (Option A):

1. **DetectorAgent** — PCABP static, hard-triggers, entropy/Markov gate
2. **AnalyzerAgent** — IPG → `provenance_score()` → gray-zone dual-tier LLM → PCABP
3. **AuditorAgent** — CoVe → LTL → `fuse_scores()` → CWAE

DARPA evaluation uses the same hybrid logic via `evaluate_darpa_tc.py --detector-mode hybrid`.

---

## Mac setup (dev only)

```bash
cd Paper1_ZeroTrustAgent
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
make dirs
make test    # 218 unit tests, no Ollama
make lint
```

Deploy code to GCP:

```bash
rsync -avz --exclude .venv --exclude results --exclude .git \
  ./ sentinel@34.74.43.57:~/Paper1_ZeroTrustAgent/
```

---

## GCP fresh-run procedure

### 1. Start VM and SSH in

```bash
gcloud compute instances start sentinel-gpu-vm --zone=us-east1-c
ssh -i ~/.ssh/id_ed25519_sentinel sentinel@34.74.43.57
```

### 2. Bootstrap (first time or after OS update)

```bash
cd ~/Paper1_ZeroTrustAgent
git pull   # or rsync from Mac
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
sudo systemctl start ollama
ollama pull llama3.1:8b
ollama pull llama3.2:1b
```

### 3. Wipe stale results (required after prior runs)

```bash
bash scripts/cleanup_stale_results.sh
```

### 4. Upload DARPA dataset (once, ~35 GB)

From Mac:

```bash
rsync -avP "/Volumes/Extreme SSD/DARPA_TC/cadets/ta1-cadets-e3-official.json.2" \
  sentinel@34.74.43.57:~/Paper1_ZeroTrustAgent/data/darpa/
```

### 5. Run full eval chain (~6–10 hours with DARPA)

```bash
cd ~/Paper1_ZeroTrustAgent
source .venv/bin/activate
bash scripts/run_gcp_eval_chain.sh 2>&1 | tee results/evaluations_gcp/gcp_chain.log
```

Or via Makefile: `make eval-gcp-chain`

### 6. Sync results back to Mac

```bash
# From Mac
rsync -avz sentinel@34.74.43.57:~/Paper1_ZeroTrustAgent/results/evaluations_gcp/ \
  ./results/evaluations_gcp/
```

### 7. Stop VM

```bash
sudo shutdown -h now   # on VM
# or: gcloud compute instances stop sentinel-gpu-vm --zone=us-east1-c
```

---

## Expected GCP output files

| File | Paper section | Notes |
|------|---------------|-------|
| `overhead_gcp.json` | V overhead | IPG/CWAE latency |
| `ipg_token_reduction_gcp.json` | V-A | **74.0%** @ window=20; **92.7%** full trace |
| `ltl_fpr_real_gcp.json` | V-E | 0 FPR on benign traces |
| `pcabp_real_nginx_gcp.json` | IV-H | Controlled-class caveat |
| `scenario_results_gcp.json` | V scenarios | 14/14 mechanism demo |
| `dual_tier_reduction_gcp.json` | V-B | **35.7%** reduction; dual 12/14 vs 8B 14/14 |
| `real_data_results_gcp.json` | V real traces | TPR=0.714, FPR=0.291, Acc=0.712, CI [0.625, 0.798] |
| `calibration_results_gcp.json` | V calibration | ECE |
| `darpa_tc_behavioral_v5_gcp.json` | V-D | **Primary** hybrid: F1=**0.603**, TPR=0.44, FPR=0.02 |
| `darpa_tc_behavioral_v4_gcp.json` | V-D | LLM-only baseline: F1=**0.597**, TPR=0.46, FPR=0.08 |
| `darpa_tc_v8_ti_aided_gcp.json` | V-D | TI-aided F1=**0.915** (+ circularity caveat) |
| `darpa_ablation_gcp.json` | V-D ablation | 5-mode table |
| `MANIFEST.json` | Reproducibility | SHA-256 + headline metrics |

After sync, update `paper/main.tex` numbers from these JSONs and rebuild PDF.

---

## Individual eval commands (partial runs)

```bash
export PYTHONPATH=src/python
export SENTINEL__LLM__BACKEND=ollama

make benchmark-overhead          # → results/evaluations/overhead.json
make eval-ipg-tokens
make eval-scenarios
make eval-dual-tier
make eval-real                   # needs traces from capture_real_traces.sh
make eval-calibration
make eval-darpa-tc               # 100 windows, hybrid default
make eval-darpa-ablation
python3 scripts/generate_manifest.py
```

Tag outputs for paper with provenance:

```bash
python3 scripts/add_meta_to_json.py \
  results/evaluations/scenario_results.json \
  results/evaluations_gcp/scenario_results_gcp.json
```

---

## Paper sync checklist (after GCP run)

- [x] All cited numbers trace to `results/evaluations_gcp/*_gcp.json` (2026-06-08 run)
- [x] `MANIFEST.json` regenerated; `meta.ollama_fallback_to_mock_count == 0`
- [x] DARPA behavioral F1=0.603 (v5 hybrid) / 0.597 (v4 LLM-only) in `paper/main.tex`
- [x] Ablation table from `darpa_ablation_gcp.json` (graph-only F1=0.611, hybrid 1/100 LLM calls)
- [x] TI-aided F1=0.915 with circularity paragraph
- [ ] Rebuild PDF: `bash scripts/build_paper.sh` (or `cd paper && pdflatex …`); verify ≤14 pages
- [ ] Run `@ieee-publication-validator` skill before submission

### Measured headline metrics (GCP, 2026-06-08)

| Metric | Value | Source |
|--------|-------|--------|
| IPG token reduction @ n=20 | 74.0% | `ipg_token_reduction_gcp.json` |
| IPG token reduction full trace | 92.7% | `ipg_token_reduction_gcp.json` |
| Dual-tier invocation reduction | 35.7% (5/14 draft hits) | `dual_tier_reduction_gcp.json` |
| LTL FPR (benign real traces) | 0.0 (0/387 windows) | `ltl_fpr_real_gcp.json` |
| PCABP real nginx | F1=1.0 (controlled classes) | `pcabp_real_nginx_gcp.json` |
| Real strace eval | TPR=0.714, FPR=0.291 | `real_data_results_gcp.json` |
| DARPA behavioral hybrid (v5) | F1=0.603, TPR=0.44, FPR=0.02 | `darpa_tc_behavioral_v5_gcp.json` |
| DARPA TI-aided (v8) | F1=0.915, TPR=0.86, FPR=0.02 | `darpa_tc_v8_ti_aided_gcp.json` |
| Non-LLM IPG p50 / CWAE p50 | 0.184 ms / 0.888 ms | `overhead_gcp.json` |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Ollama timeout | `export SENTINEL__LLM__TIMEOUT_SECONDS=300` |
| MockClassifier fallback | Check `ollama serve`; verify models pulled |
| DARPA path missing | Set `DARPA_PATH=data/darpa/ta1-cadets-e3-official.json.2` |
| PCABP bloom missing | Run `python3 scripts/rebuild_pcabp_x86.py` on GCP |
| Stale results | `bash scripts/cleanup_stale_results.sh` |
