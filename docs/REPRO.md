# SENTINEL Reproducibility Guide

> **Start here:** [RUNME.md](RUNME.md) — master runbook (GCP-only operations).

**Authoritative evaluation platform:** GCP GPU VM `sentinel-gpu-vm` (g2-standard-4, NVIDIA L4, Ubuntu 24.04, kernel 6.17.0-1018-gcp).

| Field | Value |
|-------|--------|
| Provider | Google Cloud Platform |
| Instance | `sentinel-gpu-vm` (zone `us-east1-c`) |
| IP | `34.74.43.57` |
| SSH user | `sentinel` |
| SSH key | `~/.ssh/id_ed25519_sentinel` |
| GitHub | https://github.com/jshaik-lab/Paper1_ZeroTrustAgent |
| Ollama models | `llama3.1:8b`, `llama3.2:1b` |
| Result bundle | `results/evaluations_gcp/*_gcp.json` + `MANIFEST.json` |

**Deprecated:** IONOS VPS (`74.208.76.97`) — do not cite `*_ionos.json` results. See [IONOS_SSH_SETUP.md](IONOS_SSH_SETUP.md) (archived).

---

## 1. SSH access

```bash
gcloud compute instances start sentinel-gpu-vm --zone=us-east1-c
ssh -i ~/.ssh/id_ed25519_sentinel sentinel@34.74.43.57
```

See [GCP_SETUP_GUIDE.md](GCP_SETUP_GUIDE.md) for VM specs, cost, and key management.

---

## 2. Bootstrap (first time)

```bash
cd ~/Paper1_ZeroTrustAgent
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pip install tiktoken pyelftools capstone
sudo systemctl start ollama
ollama pull llama3.1:8b
ollama pull llama3.2:1b
python3 scripts/rebuild_pcabp_x86.py   # nginx bloom filter (663 call sites)
```

Expected duration: **20–40 minutes** (Ollama model downloads dominate).

---

## 3. Full evaluation chain

```bash
cd ~/Paper1_ZeroTrustAgent
source .venv/bin/activate
export PYTHONPATH=src/python
export SENTINEL__LLM__BACKEND=ollama
export SENTINEL__LLM__TIMEOUT_SECONDS=300
export SENTINEL_EVAL_PLATFORM="GCP g2-standard-4 NVIDIA L4 Ubuntu $(uname -r)"

bash scripts/cleanup_stale_results.sh          # wipe stale JSON (keeps PCABP bloom)
bash scripts/run_gcp_eval_chain.sh 2>&1 | tee results/evaluations_gcp/gcp_chain.log
# Or resume partial progress:
bash scripts/run_gcp_eval_resume.sh
```

**Runtime:** ~2 h without DARPA re-ingest; ~6–10 h including full DARPA TC pass (3.2 GB JSONL).

---

## 4. DARPA TC E3 CADETS (individual runs)

Dataset on VM: `data/darpa/ta1-cadets-e3-official.json.2`

```bash
# Hybrid behavioral (primary paper result)
python3 src/python/evaluate_darpa_tc.py \
  --dataset cadets --max-windows 100 \
  --strip-annotations --hard-fraction 0.5 \
  --detector-mode hybrid \
  --darpa-path data/darpa/ta1-cadets-e3-official.json.2 \
  --out results/evaluations_gcp/darpa_tc_behavioral_v5_gcp.json

# LLM-only baseline
python3 src/python/evaluate_darpa_tc.py \
  --dataset cadets --max-windows 100 \
  --strip-annotations --hard-fraction 0.5 \
  --detector-mode llm_only \
  --out results/evaluations_gcp/darpa_tc_behavioral_v4_gcp.json

# TI-aided (disclose circularity in paper)
python3 src/python/evaluate_darpa_tc.py \
  --dataset cadets --max-windows 100 \
  --hard-fraction 0.0 \
  --out results/evaluations_gcp/darpa_tc_v8_ti_aided_gcp.json

# 5-mode ablation
python3 src/python/evaluate_darpa_ablation.py \
  --dataset cadets --max-windows 100 \
  --strip-annotations --hard-fraction 0.5 \
  --out results/evaluations_gcp/darpa_ablation_gcp.json
```

---

## 5. Sync results to Mac

```bash
rsync -avz -e "ssh -i ~/.ssh/id_ed25519_sentinel" \
  sentinel@34.74.43.57:~/Paper1_ZeroTrustAgent/results/evaluations_gcp/ \
  ./results/evaluations_gcp/
```

Verify integrity:

```bash
python3 scripts/generate_manifest.py
# Check meta.ollama_fallback_to_mock_count == 0 in MANIFEST.json
```

---

## 6. Measured results (2026-06-08 GCP run)

| Artifact | Headline |
|----------|----------|
| `darpa_tc_behavioral_v5_gcp.json` | F1=0.603, TPR=0.44, FPR=0.02 (hybrid) |
| `darpa_tc_behavioral_v4_gcp.json` | F1=0.597, TPR=0.46, FPR=0.08 (LLM-only) |
| `darpa_tc_v8_ti_aided_gcp.json` | F1=0.915, TPR=0.86, FPR=0.02 (TI-aided) |
| `darpa_ablation_gcp.json` | Graph-only F1=0.611; hybrid 1/100 LLM calls |
| `dual_tier_reduction_gcp.json` | 35.7% invocation reduction |
| `ipg_token_reduction_gcp.json` | 74.0% @ n=20; 92.7% full trace |
| `real_data_results_gcp.json` | TPR=0.714, FPR=0.291, n=104 |
| `ltl_fpr_real_gcp.json` | 0 FPR on 387 benign windows |
| `overhead_gcp.json` | IPG p50=0.184 ms; CWAE p50=0.888 ms |

Paper numbers in `paper/main.tex` are synced to these files.

---

## 7. Paper build

```bash
cd paper
pdflatex main && bibtex main && pdflatex main && pdflatex main
chktex main.tex
```

---

## 8. Security notes

- Do **not** expose Ollama port 11434 on the public internet.
- Eval-only VM; no production credentials.
- Stop VM when idle: `gcloud compute instances stop sentinel-gpu-vm --zone=us-east1-c`

---

## 9. Checklist cross-reference

Track submission readiness in [IEEE_SUBMISSION_CHECKLIST.md](IEEE_SUBMISSION_CHECKLIST.md).
